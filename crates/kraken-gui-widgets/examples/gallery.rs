//! Widget gallery: `cargo run -p kraken-gui-widgets --example gallery [-- --light --tab graph --stress --screenshot out.png]`.

use std::path::PathBuf;
use std::time::Instant;

use eframe::Renderer;
use egui::{Id, RichText, Ui, ViewportCommand, WidgetText};
use egui_dock::{DockArea, DockState, NodeIndex, Style, TabViewer};
use kraken_gui_widgets::listing::{ListingRow, ListingSource, OperandToken};
use kraken_gui_widgets::{
    BlockModel, CfgModel, EdgeKind, GraphView, HexView, KrakenTheme, ListingView, TokenText,
    VirtualList,
};
use kraken_proto::{Completeness, DecompileResult, Locator, Token, TokenKind};

const SAMPLE_C: &str = r#"// recovered from sub_00401a30, 2 callers
int process_packet(Session *sess, uint8_t *buf, size_t len)
{
  PacketHeader *hdr;
  uint32_t checksum;
  size_t payload_len;
  int status;
  size_t i;

  if (buf == NULL || len < 12) {
    log_error(sess, "short packet", len);
    return -1;
  }
  hdr = (PacketHeader *)buf;
  if (hdr->magic != 0x4b524b4e) {
    log_error(sess, "bad magic", hdr->magic);
    return -2;
  }
  payload_len = hdr->length;
  if (payload_len > len - 12) {
    /* attacker controlled length: clamp to the buffer */
    payload_len = len - 12;
  }
  checksum = 0;
  for (i = 0; i < payload_len; i++) {
    checksum = (checksum << 5) + checksum + buf[12 + i];
  }
  if (checksum != hdr->checksum) {
    status = session_reset(sess, 3);
    if (status != 0) {
      return status;
    }
    return -3;
  }
  switch (hdr->type) {
  case 1:
    status = handle_hello(sess, buf + 12, payload_len);
    break;
  case 2:
    status = handle_data(sess, buf + 12, payload_len);
    break;
  case 0x7f:
    status = session_close(sess);
    break;
  default:
    log_error(sess, "unknown type", hdr->type);
    status = -4;
    break;
  }
  sess->bytes_in += payload_len;
  sess->last_status = status;
  if (status == 0) {
    sess->packets++;
  }
  return status;
}
"#;

/// A tiny C lexer producing the same kind of token map a decompiler would.
fn sample_result() -> DecompileResult {
    const KEYWORDS: &[&str] = &[
        "if", "else", "for", "while", "return", "switch", "case", "default", "break", "NULL",
    ];
    const TYPES: &[&str] = &[
        "int",
        "size_t",
        "uint8_t",
        "uint32_t",
        "Session",
        "PacketHeader",
        "void",
    ];
    const LOCALS: &[(&str, &str)] = &[
        ("sess", "stack:0x8:8"),
        ("buf", "stack:0x10:8"),
        ("len", "stack:0x18:8"),
        ("hdr", "stack:-0x20:8"),
        ("checksum", "stack:-0x14:4"),
        ("payload_len", "stack:-0x30:8"),
        ("status", "stack:-0x34:4"),
        ("i", "stack:-0x40:8"),
    ];
    let text = SAMPLE_C;
    let b = text.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    let mut prev_member = false;
    let mk = |start: usize, end: usize, kind: TokenKind| Token {
        start: start as u32,
        end: end as u32,
        kind,
        target: None,
        symbol: None,
        varnode: None,
    };
    while i < b.len() {
        let c = b[i] as char;
        let start = i;
        if c.is_whitespace() {
            i += 1;
        } else if text[i..].starts_with("//") {
            i += text[i..].find('\n').unwrap_or(text.len() - i);
            tokens.push(mk(start, i, TokenKind::Comment));
        } else if text[i..].starts_with("/*") {
            i += text[i..].find("*/").map_or(text.len() - i, |p| p + 2);
            tokens.push(mk(start, i, TokenKind::Comment));
        } else if c == '"' {
            i += 1;
            while b[i] != b'"' {
                i += 1;
            }
            i += 1;
            tokens.push(mk(start, i, TokenKind::Constant));
        } else if c.is_ascii_digit() {
            while i < b.len() && (b[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            tokens.push(mk(start, i, TokenKind::Constant));
        } else if c.is_ascii_alphabetic() || c == '_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let word = &text[start..i];
            let mut t = if prev_member {
                let mut t = mk(start, i, TokenKind::Field);
                t.symbol = Some(word.to_string());
                t
            } else if KEYWORDS.contains(&word) {
                let kind = if word == "NULL" {
                    TokenKind::Constant
                } else {
                    TokenKind::Keyword
                };
                mk(start, i, kind)
            } else if TYPES.contains(&word) {
                let mut t = mk(start, i, TokenKind::Type);
                t.symbol = Some(word.to_string());
                t
            } else if let Some((_, vn)) = LOCALS.iter().find(|(n, _)| *n == word) {
                let mut t = mk(start, i, TokenKind::Variable);
                t.symbol = Some(word.to_string());
                t.varnode = Some((*vn).to_string());
                t
            } else if b.get(i) == Some(&b'(') {
                let mut t = mk(start, i, TokenKind::Function);
                let addr = 0x401000 + (word.bytes().map(u64::from).sum::<u64>() * 0x37 % 0x4000);
                t.target = (word != "process_packet").then(|| Locator::ram(addr));
                t.symbol = Some(word.to_string());
                t
            } else {
                mk(start, i, TokenKind::Other)
            };
            if t.kind == TokenKind::Other {
                t.kind = TokenKind::Variable;
            }
            tokens.push(t);
            prev_member = false;
            continue;
        } else {
            // Operators / punctuation, with `->` and `.` marking a following field.
            let two = text.get(i..i + 2).unwrap_or("");
            let len = if ["->", "==", "!=", "<=", ">=", "&&", "||", "<<", "++", "+="].contains(&two)
            {
                2
            } else {
                1
            };
            i += len;
            prev_member = &text[start..i] == "->" || &text[start..i] == ".";
            tokens.push(mk(start, i, TokenKind::Op));
            continue;
        }
        prev_member = false;
    }
    let r = DecompileResult {
        function: Locator::ram(0x401a30),
        language: "c".into(),
        text: text.to_string(),
        tokens,
        warnings: vec![],
        completeness: Completeness::Complete,
    };
    debug_assert!(r.validate_tokens().is_ok());
    r
}

struct FakeListing;

impl ListingSource for FakeListing {
    fn len(&self) -> usize {
        50_000
    }
    fn row(&self, index: usize) -> ListingRow {
        let regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9"];
        let r = |k: usize| regs[(index * 7 + k) % regs.len()];
        let address = 0x401000 + index as u64 * 4;
        let sep = || OperandToken::new(", ", TokenKind::Op);
        let reg = |s: &str| OperandToken::new(s, TokenKind::Variable);
        let (mnemonic, kind, operands, comment, bytes): (&str, _, Vec<OperandToken>, _, Vec<u8>) =
            match index % 9 {
                0 => (
                    "push",
                    TokenKind::Keyword,
                    vec![reg("rbp")],
                    None,
                    vec![0x55],
                ),
                1 => (
                    "mov",
                    TokenKind::Keyword,
                    vec![reg("rbp"), sep(), reg("rsp")],
                    None,
                    vec![0x48, 0x89, 0xe5],
                ),
                2 => (
                    "sub",
                    TokenKind::Keyword,
                    vec![
                        reg("rsp"),
                        sep(),
                        OperandToken::new("0x40", TokenKind::Constant),
                    ],
                    None,
                    vec![0x48, 0x83, 0xec, 0x40],
                ),
                3 => (
                    "mov",
                    TokenKind::Keyword,
                    vec![
                        OperandToken::new("qword ptr ", TokenKind::Type),
                        OperandToken::new("[", TokenKind::Op),
                        reg("rbp"),
                        OperandToken::new("-0x8", TokenKind::Constant),
                        OperandToken::new("]", TokenKind::Op),
                        sep(),
                        reg(r(1)),
                    ],
                    Some("sess".to_string()),
                    vec![0x48, 0x89, 0x7d, 0xf8],
                ),
                4 => (
                    "call",
                    TokenKind::Function,
                    vec![OperandToken::new("log_error", TokenKind::Function)],
                    Some("logs and returns".to_string()),
                    vec![0xe8, 0x1c, 0x03, 0x00, 0x00],
                ),
                5 => (
                    "cmp",
                    TokenKind::Keyword,
                    vec![
                        reg(r(2)),
                        sep(),
                        OperandToken::new("0xc", TokenKind::Constant),
                    ],
                    None,
                    vec![0x48, 0x83, 0xf8, 0x0c],
                ),
                6 => (
                    "jbe",
                    TokenKind::Keyword,
                    vec![OperandToken::new(
                        format!("0x{:x}", address + 0x24),
                        TokenKind::Constant,
                    )],
                    None,
                    vec![0x76, 0x1e],
                ),
                7 => (
                    "xor",
                    TokenKind::Keyword,
                    vec![reg("eax"), sep(), reg("eax")],
                    None,
                    vec![0x31, 0xc0],
                ),
                _ => ("ret", TokenKind::Keyword, vec![], None, vec![0xc3]),
            };
        ListingRow {
            mark: Default::default(),
            address,
            bytes,
            mnemonic: mnemonic.into(),
            mnemonic_kind: kind,
            operands,
            comment,
        }
    }
}

/// Splits one assembly line into syntax-coloured pieces.
fn asm_line(line: &str) -> Vec<(String, TokenKind)> {
    let (mnemonic, rest) = line.split_once(' ').unwrap_or((line, ""));
    let m_kind = if mnemonic.starts_with('j') || mnemonic == "call" {
        TokenKind::Function
    } else {
        TokenKind::Keyword
    };
    let mut out = vec![(mnemonic.to_string(), m_kind)];
    if rest.is_empty() {
        return out;
    }
    out.push((" ".into(), TokenKind::Other));
    let call = mnemonic == "call";
    let flush = |word: &mut String, out: &mut Vec<(String, TokenKind)>| {
        if word.is_empty() {
            return;
        }
        let kind = if call {
            TokenKind::Function
        } else if word.starts_with("0x") || word.starts_with('-') || word.parse::<i64>().is_ok() {
            TokenKind::Constant
        } else if matches!(word.as_str(), "qword" | "dword" | "byte" | "ptr" | "rip") {
            TokenKind::Type
        } else {
            TokenKind::Variable
        };
        out.push((std::mem::take(word), kind));
    };
    let mut word = String::new();
    for c in rest.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || (c == '-' && word.is_empty()) {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            let kind = if c == ' ' {
                TokenKind::Other
            } else {
                TokenKind::Op
            };
            out.push((c.to_string(), kind));
        }
    }
    flush(&mut word, &mut out);
    out
}

/// A realistic 26-block function: guards, a checksum loop, if/else and a switch.
fn sample_cfg() -> CfgModel {
    use EdgeKind::{Back, ConditionalFalse as F, ConditionalTrue as T, Fallthrough as Ft, Jump};
    #[rustfmt::skip]
    let blocks: [&[&str]; 26] = [
        &["push rbp", "mov rbp, rsp", "sub rsp, 0x40", "mov qword ptr [rbp-0x8], rdi",
          "mov qword ptr [rbp-0x10], rsi", "mov qword ptr [rbp-0x18], rdx", "test rsi, rsi", "je 0x401a8e"],
        &["lea rsi, [rip+0x2a1f]", "call log_error", "mov eax, -1", "jmp 0x401c70"],
        &["cmp rdx, 0xc", "jb 0x401aa2"],
        &["lea rsi, [rip+0x2a0b]", "call log_error", "mov eax, -1", "jmp 0x401c70"],
        &["mov rax, qword ptr [rbp-0x10]", "mov eax, dword ptr [rax]", "cmp eax, 0x4b524b4e", "jne 0x401ac6"],
        &["mov esi, eax", "call log_error", "mov eax, -2", "jmp 0x401c70"],
        &["mov rax, qword ptr [rbp-0x10]", "mov eax, dword ptr [rax+0x4]", "mov qword ptr [rbp-0x20], rax",
          "mov rcx, qword ptr [rbp-0x18]", "sub rcx, 0xc", "cmp rax, rcx", "jbe 0x401af0"],
        &["mov qword ptr [rbp-0x20], rcx"],
        &["mov dword ptr [rbp-0x24], 0", "mov qword ptr [rbp-0x28], 0"],
        &["mov rax, qword ptr [rbp-0x28]", "cmp rax, qword ptr [rbp-0x20]", "jae 0x401b3c"],
        &["mov rdx, qword ptr [rbp-0x10]", "movzx eax, byte ptr [rdx+rax+0xc]", "mov ecx, dword ptr [rbp-0x24]",
          "shl ecx, 5", "add ecx, dword ptr [rbp-0x24]", "add ecx, eax", "mov dword ptr [rbp-0x24], ecx"],
        &["add qword ptr [rbp-0x28], 1", "jmp 0x401b10"],
        &["mov rax, qword ptr [rbp-0x10]", "mov eax, dword ptr [rax+0x8]", "cmp dword ptr [rbp-0x24], eax", "je 0x401b6a"],
        &["mov rdi, qword ptr [rbp-0x8]", "mov esi, 3", "call session_reset", "mov dword ptr [rbp-0x34], eax",
          "cmp dword ptr [rbp-0x34], 0", "jne 0x401b5c"],
        &["mov eax, dword ptr [rbp-0x34]", "jmp 0x401c70"],
        &["mov rax, qword ptr [rbp-0x10]", "mov eax, dword ptr [rax+0xc]", "cmp eax, 2", "ja 0x401b90"],
        &["cmp eax, 0x7f", "je 0x401c20"],
        &["lea rdx, [rip+0x2f4a]", "mov rax, qword ptr [rdx+rax*8]", "jmp rax"],
        &["mov rdi, qword ptr [rbp-0x8]", "call handle_hello", "mov dword ptr [rbp-0x34], eax", "jmp 0x401c34"],
        &["mov rdi, qword ptr [rbp-0x8]", "call handle_data", "mov dword ptr [rbp-0x34], eax", "jmp 0x401c34"],
        &["mov rax, qword ptr [rbp-0x8]", "mov rdi, rax", "call session_close", "mov dword ptr [rbp-0x34], eax", "jmp 0x401c34"],
        &["lea rsi, [rip+0x29d3]", "call log_error", "mov dword ptr [rbp-0x34], -4"],
        &["mov rax, qword ptr [rbp-0x8]", "mov rdx, qword ptr [rbp-0x20]", "add qword ptr [rax+0x10], rdx",
          "cmp dword ptr [rbp-0x34], 0", "jne 0x401c6c"],
        &["mov eax, -3", "jmp 0x401c70"],
        &["leave", "ret"],
        &["add qword ptr [rax+0x18], 1"],
    ];
    // Block 24 is the shared epilogue, 23 the checksum-failure return, 25 the packet counter.
    #[rustfmt::skip]
    let edges = [
        (0, 1, T), (0, 2, F), (1, 24, Jump),
        (2, 3, T), (2, 4, F), (3, 24, Jump),
        (4, 5, T), (4, 6, F), (5, 24, Jump),
        (6, 8, T), (6, 7, F), (7, 8, Ft),
        (8, 9, Ft), (9, 12, T), (9, 10, F),
        (10, 11, Ft), (11, 9, Back),
        (12, 15, T), (12, 13, F),
        (13, 14, T), (13, 23, F), (14, 24, Jump),
        (15, 16, T), (15, 17, F),
        (16, 21, T), (16, 22, F),
        (17, 18, Jump), (17, 19, Jump), (17, 22, Jump),
        (18, 20, Jump), (19, 20, Jump), (21, 20, Jump), (22, 20, Ft),
        (20, 24, T), (20, 25, F), (25, 24, Ft),
        (23, 24, Jump),
    ];
    let blocks = blocks
        .iter()
        .enumerate()
        .map(|(i, lines)| BlockModel {
            id: i as u64,
            title: format!("0x{:x}", 0x401a30 + i * 0x2c),
            lines: lines.iter().map(|l| asm_line(l)).collect(),
        })
        .collect();
    CfgModel {
        blocks,
        edges: edges.to_vec(),
        entry: Some(0),
    }
}

/// Deterministic pseudo-random CFG of `n` blocks: forward branches, loops and long jumps.
fn stress_cfg(n: usize) -> CfgModel {
    const BODY: [&str; 8] = [
        "mov rax, qword ptr [rbp-0x8]",
        "add eax, 1",
        "cmp eax, 0x10",
        "lea rdx, [rax+rax*4]",
        "call sub_401230",
        "xor ecx, ecx",
        "mov dword ptr [rbp-0x14], eax",
        "test rax, rax",
    ];
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut rnd = move |m: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % m
    };
    let mut blocks = Vec::with_capacity(n);
    let mut edges = Vec::new();
    for i in 0..n {
        let count = 2 + rnd(5) as usize;
        let mut lines: Vec<Vec<(String, TokenKind)>> = (0..count)
            .map(|_| asm_line(BODY[rnd(8) as usize]))
            .collect();
        let id = i as u64;
        if i + 1 < n {
            match rnd(10) {
                0..=4 => {
                    lines.push(asm_line("jmp 0x401000"));
                    edges.push((id, id + 1, EdgeKind::Fallthrough));
                }
                5..=8 => {
                    lines.push(asm_line("jne 0x401000"));
                    let far = (i + 2 + rnd(6) as usize).min(n - 1) as u64;
                    edges.push((id, id + 1, EdgeKind::ConditionalFalse));
                    edges.push((id, far, EdgeKind::ConditionalTrue));
                }
                _ => {
                    lines.push(asm_line("jb 0x401000"));
                    let back = id.saturating_sub(1 + rnd(8));
                    edges.push((id, id + 1, EdgeKind::ConditionalFalse));
                    edges.push((id, back, EdgeKind::ConditionalTrue));
                }
            }
        } else {
            lines.push(asm_line("ret"));
        }
        blocks.push(BlockModel {
            id,
            title: format!("0x{:x}", 0x401000 + i * 0x20),
            lines,
        });
    }
    CfgModel {
        blocks,
        edges,
        entry: Some(0),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
enum Tab {
    Functions,
    Decompiler,
    Hex,
    Listing,
    Graph,
}

struct Viewer {
    decompiled: DecompileResult,
    hex: Vec<u8>,
    selected_fn: Option<usize>,
    selected_row: Option<usize>,
    status: String,
    screenshot_mode: bool,
    cfg: CfgModel,
    stress: CfgModel,
    use_stress: bool,
    graph_sel: Option<u64>,
    graph_busy: bool,
    graph_ms: f32,
}

fn fake_name(i: usize) -> String {
    const NOUNS: [&str; 8] = [
        "packet", "session", "buffer", "table", "stream", "header", "cache", "timer",
    ];
    const VERBS: [&str; 8] = [
        "parse", "init", "flush", "handle", "decode", "reset", "alloc", "verify",
    ];
    if i.is_multiple_of(3) {
        format!("sub_{:06x}", 0x401000 + i * 0x20)
    } else {
        format!("{}_{}_{}", VERBS[i % 8], NOUNS[(i / 8) % 8], i)
    }
}

impl TabViewer for Viewer {
    type Tab = Tab;

    fn id(&mut self, tab: &mut Tab) -> Id {
        Id::new(*tab)
    }

    fn title(&mut self, tab: &mut Tab) -> WidgetText {
        format!("{tab:?}").into()
    }

    fn is_closeable(&self, _tab: &Tab) -> bool {
        false
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Tab) {
        let pal = KrakenTheme::from_ctx(ui.ctx()).palette();
        match tab {
            Tab::Functions => {
                ui.label(
                    RichText::new("100,000 functions")
                        .small()
                        .color(pal.text_dim),
                );
                let resp = VirtualList::new("functions", 100_000, 22.0).show(
                    ui,
                    &mut self.selected_fn,
                    |ui, i, selected| {
                        ui.label(
                            RichText::new(format!("{:08x}", 0x401000 + i * 0x20))
                                .monospace()
                                .color(pal.address),
                        );
                        let color = if selected { pal.text_strong } else { pal.text };
                        ui.label(RichText::new(fake_name(i)).monospace().color(color));
                    },
                );
                if resp.changed
                    && let Some(i) = self.selected_fn
                {
                    self.status = format!("selected {}", fake_name(i));
                }
            }
            Tab::Decompiler => {
                let mut t = TokenText::new(&self.decompiled).id_salt("decomp");
                if self.screenshot_mode {
                    t = t.initial_highlight("payload_len");
                }
                let out = t.show(ui);
                if let Some(c) = out.clicked {
                    self.status = format!(
                        "clicked token {} ({:?}) target {:?}",
                        c.index, c.symbol, c.target
                    );
                }
            }
            Tab::Hex => {
                let hl = [
                    (0x40u64..0x58, pal.highlight),
                    (0x200..0x214, pal.selection),
                ];
                let out = HexView::new(&self.hex, 0x0040_0000)
                    .id_salt("hex")
                    .highlights(&hl)
                    .show(ui);
                if let Some(sel) = out.selection {
                    self.status = format!(
                        "selection {:#x}..{:#x} ({} bytes)  hover {:?}",
                        sel.start,
                        sel.end,
                        sel.end - sel.start,
                        out.hovered
                    );
                }
            }
            Tab::Graph => {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.use_stress, "stress: 3,000 blocks");
                    ui.label(
                        RichText::new(format!("graph ui {:.2} ms/frame", self.graph_ms))
                            .small()
                            .color(pal.text_dim),
                    );
                });
                let (model, id) = if self.use_stress {
                    (&self.stress, 2)
                } else {
                    (&self.cfg, 1)
                };
                let t0 = Instant::now();
                let out = GraphView::new(model)
                    .id_salt(("graph", id))
                    .cache_id(id)
                    .show(ui, &mut self.graph_sel);
                let ms = t0.elapsed().as_secs_f32() * 1000.0;
                self.graph_ms = self.graph_ms * 0.9 + ms * 0.1;
                self.graph_busy = out.laying_out;
                if let Some(t) = out.token {
                    self.status = format!("token {:?} ({:?}) in block {}", t.text, t.kind, t.block);
                } else if out.changed {
                    self.status = format!("selected block {:?}", self.graph_sel);
                }
            }
            Tab::Listing => {
                ListingView::new(&FakeListing)
                    .id_salt("listing")
                    .address_digits(8)
                    .show(ui, &mut self.selected_row);
            }
        }
    }
}

struct App {
    dock: DockState<Tab>,
    viewer: Viewer,
    theme: KrakenTheme,
    applied: Option<KrakenTheme>,
    screenshot: Option<PathBuf>,
    frames: u32,
    shot_requested: bool,
    shot_frame: u32,
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if self.applied != Some(self.theme) {
            self.theme.apply(&ctx);
            self.applied = Some(self.theme);
        }
        let pal = self.theme.palette();
        egui::Panel::top("top")
            .frame(
                egui::Frame::new()
                    .fill(pal.bg)
                    .inner_margin(egui::Margin::symmetric(14, 8)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("KRAKEN")
                            .strong()
                            .size(16.0)
                            .color(pal.accent),
                    );
                    ui.label(RichText::new("widget gallery").color(pal.text_dim));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let label = if self.theme.dark { "Light" } else { "Dark" };
                        if ui.button(label).clicked() {
                            self.theme.dark = !self.theme.dark;
                        }
                    });
                });
            });
        egui::Panel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(pal.bg)
                    .inner_margin(egui::Margin::symmetric(14, 5)),
            )
            .show(ui, |ui| {
                ui.label(
                    RichText::new(&self.viewer.status)
                        .monospace()
                        .small()
                        .color(pal.text_dim),
                );
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(pal.bg).inner_margin(6))
            .show(ui, |ui| {
                let style = Style::from_egui(ui.style().as_ref());
                DockArea::new(&mut self.dock)
                    .style(style)
                    .show_inside(ui, &mut self.viewer);
            });

        self.frames += 1;
        if let Some(path) = self.screenshot.clone() {
            if self.frames >= 12 && !self.viewer.graph_busy && !self.shot_requested {
                self.shot_requested = true;
                self.shot_frame = self.frames;
            }
            if self.shot_requested && self.frames == self.shot_frame + 3 {
                ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::default()));
            }
            let shot = ctx.input(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(img) = shot {
                let rgba: Vec<u8> = img.pixels.iter().flat_map(|c| c.to_array()).collect();
                let [w, h] = img.size;
                match image::save_buffer(&path, &rgba, w as u32, h as u32, image::ColorType::Rgba8)
                {
                    Ok(()) => println!("screenshot saved: {} ({w}x{h})", path.display()),
                    Err(e) => eprintln!("screenshot failed: {e}"),
                }
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
            ctx.request_repaint();
        }
    }
}

fn pseudo_random_bytes(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut v: Vec<u8> = (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // sprinkle zero runs and text so the dump has structure
            if x.is_multiple_of(11) {
                0
            } else {
                (x >> 24) as u8
            }
        })
        .collect();
    let text = b"KRAKEN gallery: /usr/lib/libc.so.6 GLIBC_2.34 __libc_start_main";
    v[0x40..0x40 + text.len()].copy_from_slice(text);
    v[..4].copy_from_slice(b"\x7fELF");
    v
}

fn main() -> anyhow::Result<()> {
    let mut screenshot = None;
    let mut theme = KrakenTheme::DARK;
    let mut renderer = Renderer::default();
    let mut focus_tab = None;
    let mut stress = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--screenshot" => screenshot = args.next().map(PathBuf::from),
            "--light" => theme = KrakenTheme::LIGHT,
            "--stress" => stress = true,
            "--tab" => {
                focus_tab = Some(match args.next().as_deref() {
                    Some("decompiler") => Tab::Decompiler,
                    Some("functions") => Tab::Functions,
                    Some("hex") => Tab::Hex,
                    Some("listing") => Tab::Listing,
                    Some("graph") => Tab::Graph,
                    other => anyhow::bail!("unknown tab {other:?}"),
                })
            }
            "--renderer" => {
                renderer = match args.next().as_deref() {
                    Some("glow") => Renderer::Glow,
                    Some("wgpu") => Renderer::Wgpu,
                    other => anyhow::bail!("unknown renderer {other:?}"),
                }
            }
            other => anyhow::bail!("unknown argument {other}"),
        }
    }

    let mut dock = DockState::new(vec![Tab::Decompiler, Tab::Graph]);
    let surface = dock.main_surface_mut();
    let (left, right_frac) = if focus_tab == Some(Tab::Graph) {
        (0.1, 0.78)
    } else {
        (0.2, 0.42)
    };
    let [main, _functions] = surface.split_left(NodeIndex::root(), left, vec![Tab::Functions]);
    let [_decomp, right] = surface.split_right(main, right_frac, vec![Tab::Hex]);
    surface.split_below(right, 0.5, vec![Tab::Listing]);
    if let Some(tab) = focus_tab
        && let Some(found) = dock.find_tab(&tab)
    {
        let _ = dock.set_active_tab(found);
    }

    let viewer = Viewer {
        decompiled: sample_result(),
        hex: pseudo_random_bytes(1 << 20),
        selected_fn: Some(2),
        selected_row: Some(3),
        status: "ready".into(),
        screenshot_mode: screenshot.is_some(),
        cfg: sample_cfg(),
        stress: stress_cfg(3000),
        use_stress: stress,
        graph_sel: Some(9),
        graph_busy: false,
        graph_ms: 0.0,
    };
    let options = eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(if focus_tab == Some(Tab::Graph) {
                [1500.0, 1150.0]
            } else {
                [1400.0, 820.0]
            })
            .with_title("KRAKEN widget gallery"),
        ..Default::default()
    };
    eframe::run_native(
        "KRAKEN widget gallery",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(App {
                dock,
                viewer,
                theme,
                applied: None,
                screenshot,
                frames: 0,
                shot_requested: false,
                shot_frame: 0,
            }))
        }),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}
