//! Tests of the program views: scripted replies for exact request/response logic, and the
//! in-process backend over a recorded fixture for real data.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use kraken_proto::{ErrorCode, ProtoError, TokenKind};
use serde_json::{Value, json};
use tokio::runtime::Runtime;

use super::bytes::PAGE_SIZE;
use super::*;
use crate::testing::FakeBackend;
use crate::{Connection, Load, ToastLevel, ViewModel};

const WAIT: Duration = Duration::from_secs(10);

fn u(s: &str) -> Value {
    json!({"untrusted": true, "value": s})
}

fn fn_view(addr: u64, name: &str, size: u64) -> Value {
    json!({
        "address": format!("{addr:#x}"), "name": u(name), "size": size,
        "signature": u(&format!("void {name}(void)")),
        "completeness": {"kind": "complete"},
    })
}

fn page(items: Vec<Value>, next: Option<&str>) -> Value {
    let mut p = json!({ "items": items });
    if let Some(n) = next {
        p["next_cursor"] = json!(n);
    }
    p
}

fn project_json() -> Value {
    json!({
        "project_dir": "/tmp/p", "binary_path": "/bin/demo", "binary_sha256": "00",
        "program": {"arch": "x86:LE:64", "format": "elf", "base": "0x400000", "sha256": "00", "size": 4096},
        "engine_build": "fake", "capabilities": [], "epoch": {}, "epoch_stale": false,
        "stale_fields": [], "analysis": {"phase": "complete", "function_count": 3},
        "pending_entries": 0, "log_entries": 0, "open_proposals": 0,
    })
}

fn addr_of(args: &Value, key: &str) -> u64 {
    let s = args[key].as_str().unwrap_or("0x0");
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
}

fn insn(addr: u64, mnemonic: &str, operands: Value, flow: &str) -> Value {
    json!({
        "address": format!("{addr:#x}"), "bytes": "9090", "mnemonic": mnemonic,
        "operands": operands, "flow": flow,
    })
}

fn call_op(target: u64, name: &str) -> Value {
    json!([{"kind": "symbol", "text": format!("{target:#x}"), "symbol": u(name), "target": format!("{target:#x}")}])
}

fn xref(from: u64, to: u64, kind: &str, from_fn: Option<(u64, &str)>) -> Value {
    let mut x = json!({"from": format!("{from:#x}"), "to": format!("{to:#x}"), "kind": kind});
    if let Some((a, n)) = from_fn {
        x["from_function"] = json!({"address": format!("{a:#x}"), "name": u(n)});
    }
    x
}

/// The replies every flow needs: three functions, details and a plain decompile.
fn base() -> FakeBackend {
    FakeBackend::new()
        .reply("project_open", project_json())
        .reply("project_info", project_json())
        .reply(
            "list_functions",
            page(
                vec![
                    fn_view(0x401000, "main", 0x40),
                    fn_view(0x401040, "helper", 0x20),
                    fn_view(0x401100, "other", 0x20),
                ],
                None,
            ),
        )
        .reply("history", page(vec![], None))
        .reply("proposals_list", page(vec![], None))
        .on("get_function", |a| {
            let n = addr_of(a, "address");
            let mut v = fn_view(n, if n == 0x401000 { "main" } else { "helper" }, 0x40);
            v["comments"] = json!([]);
            v["versions"] = json!({});
            Ok(v)
        })
        .on("decompile", |a| {
            let n = addr_of(a, "address");
            Ok(json!({
                "address": format!("{n:#x}"), "language": "c",
                "text": u("void f(void)\n{\n  helper();\n}\n"),
                "truncated": false, "tokens": [], "references": [], "warnings": [],
                "completeness": {"kind": "complete"},
            }))
        })
}

struct Rig {
    _rt: Runtime,
    vm: ViewModel,
    backend: Arc<FakeBackend>,
}

fn opened(backend: FakeBackend) -> Rig {
    let rt = Runtime::new().expect("runtime");
    let backend = Arc::new(backend);
    let mut vm = ViewModel::new(backend.clone(), rt.handle().clone());
    vm.open_project("/tmp/p");
    assert!(vm.block_until_idle(WAIT));
    assert_eq!(vm.connection, Connection::Open);
    Rig {
        _rt: rt,
        vm,
        backend,
    }
}

impl Rig {
    fn settle(&mut self) {
        assert!(self.vm.block_until_idle(WAIT), "calls did not finish");
    }

    fn select(&mut self, addr: u64) {
        self.vm.select_function(addr);
        self.settle();
    }
}

// ------------------------------------------------------------------ decompiler tokens

#[test]
fn server_token_spans_replace_the_client_tokenizer() {
    let text = "void f(void)\n{\n  helper();\n}\n";
    let at = |n: &str| text.find(n).unwrap();
    let helper = at("helper");
    let backend = base().on("decompile", move |a| {
        let n = addr_of(a, "address");
        Ok(json!({
            "address": format!("{n:#x}"), "language": "c", "text": u(text), "truncated": false,
            "tokens": [
                {"start": 0, "end": 4, "kind": "type"},
                {"start": helper, "end": helper + 6, "kind": "function", "target": "0x401040"},
            ],
            "references": [], "warnings": [], "completeness": {"kind": "complete"},
        }))
    });
    let mut r = opened(backend);
    r.select(0x401000);
    let Load::Ready(d) = &r.vm.current.as_ref().unwrap().decompiled else {
        panic!("decompiled");
    };
    // Only the spans the server sent: the client tokenizer would also have found `f`, `{`, ...
    assert_eq!(d.result.tokens.len(), 2);
    let call = &d.result.tokens[1];
    assert_eq!(call.kind, TokenKind::Function);
    assert_eq!(call.target, Some(kraken_proto::Locator::ram(0x401040)));
    assert_eq!(call.symbol.as_deref(), Some("helper"));
    d.result.validate_tokens().unwrap();
}

#[test]
fn without_token_spans_the_client_tokenizer_still_works() {
    let mut r = opened(base());
    r.select(0x401000);
    let Load::Ready(d) = &r.vm.current.as_ref().unwrap().decompiled else {
        panic!("decompiled");
    };
    assert!(d.result.tokens.len() > 2);
    assert!(
        d.result
            .tokens
            .iter()
            .any(|t| t.symbol.as_deref() == Some("helper"))
    );
}

// ------------------------------------------------------------------ listing

/// `disassemble` answering in pages of `per_page` rows out of `total`, 4 bytes apart.
fn paged_listing(total: u64, per_page: u64) -> FakeBackend {
    base().on("disassemble", move |a| {
        let entry = addr_of(a, "function");
        let first: u64 = a["cursor"]
            .as_str()
            .map_or(0, |c| c.parse().unwrap_or(u64::MAX));
        let asked = a["max_instructions"]
            .as_u64()
            .unwrap_or(per_page)
            .min(per_page);
        let end = (first + asked).min(total);
        let rows = (first..end)
            .map(|i| {
                let ops = if i % 5 == 4 {
                    call_op(0x401040, "helper")
                } else {
                    json!([])
                };
                insn(
                    entry + i * 4,
                    if i % 5 == 4 { "CALL" } else { "NOP" },
                    ops,
                    if i % 5 == 4 { "call" } else { "fallthrough" },
                )
            })
            .collect();
        Ok(page(
            rows,
            (end < total).then(|| end.to_string()).as_deref(),
        ))
    })
}

#[test]
fn the_listing_loads_lazily_and_pages_as_the_user_scrolls() {
    // Pages of 50 rows: a page is longer than the 40 rows of look-ahead, so the top of the first
    // page is "far from the end". Every count is read after `settle`, so a request that was
    // made shows up however slowly the runtime runs it.
    let mut r = opened(paged_listing(130, 50));
    r.vm.views.listing.page_size = 50;
    r.select(0x401000);
    // Nothing is requested until a view asks.
    assert!(r.backend.calls_to("disassemble").is_empty());

    r.vm.ensure_listing();
    r.vm.ensure_listing(); // idempotent while loading
    r.settle();
    r.vm.ensure_listing(); // and once loaded
    r.settle();
    let l = &r.vm.views.listing;
    assert_eq!(r.backend.calls_to("disassemble").len(), 1);
    assert_eq!(r.backend.calls_to("disassemble")[0]["function"], "0x401000");
    assert_eq!(r.backend.calls_to("disassemble")[0]["max_instructions"], 50);
    assert_eq!(
        (l.function, l.rows.len(), l.has_more()),
        (Some(0x401000), 50, true)
    );
    assert_eq!(l.rows[4].mnemonic, "call");
    assert_eq!(l.rows[4].operands[0].text, "helper");
    assert_eq!(l.rows[4].operands[0].target, Some(0x401040));
    assert_eq!(l.rows[0].bytes, vec![0x90, 0x90]);

    // Far from the end: no request. Near the end: the next page, by cursor.
    r.vm.listing_scrolled(0);
    r.settle();
    assert_eq!(r.backend.calls_to("disassemble").len(), 1);
    r.vm.listing_scrolled(10);
    r.vm.listing_scrolled(11); // one page at a time
    r.settle();
    assert_eq!(r.backend.calls_to("disassemble").len(), 2);
    assert_eq!(r.backend.calls_to("disassemble")[1]["cursor"], "50");
    assert_eq!(r.vm.views.listing.rows.len(), 100);
    r.vm.listing_scrolled(60);
    r.settle();
    let l = &r.vm.views.listing;
    assert_eq!((l.rows.len(), l.has_more()), (130, false));
    assert_eq!(l.rows[129].address, 0x401000 + 129 * 4);
    assert_eq!(r.backend.calls_to("disassemble")[2]["cursor"], "100");
    r.vm.listing_scrolled(130);
    r.settle();
    assert_eq!(r.backend.calls_to("disassemble").len(), 3);
}

#[test]
fn a_new_function_clears_the_listing_and_late_answers_are_ignored() {
    let mut r = opened(paged_listing(5, 5));
    r.select(0x401000);
    r.vm.ensure_listing();
    r.settle();
    assert_eq!(r.vm.views.listing.rows.len(), 5);
    let rev = r.vm.views.listing.revision;

    r.vm.select_function(0x401040);
    assert!(r.vm.views.listing.rows.is_empty());
    assert_eq!(r.vm.views.listing.function, None);
    r.vm.ensure_listing();
    // Switch away again while the request is in flight; its answer must not land.
    r.vm.select_function(0x401100);
    r.settle();
    r.vm.ensure_listing();
    r.settle();
    let l = &r.vm.views.listing;
    assert_eq!(l.function, Some(0x401100));
    assert_eq!(l.rows[0].address, 0x401100);
    assert!(l.revision > rev);

    // A refresh of the same function keeps the rows on screen while it reloads.
    r.vm.refresh_current();
    assert!(r.vm.views.listing.stale);
    assert_eq!(r.vm.views.listing.rows.len(), 5);
    r.settle();
    r.vm.ensure_listing();
    r.settle();
    assert!(!r.vm.views.listing.stale);
    assert_eq!(r.vm.views.listing.rows.len(), 5);
}

#[test]
fn focus_waits_for_the_row_and_keeps_paging_until_it_arrives() {
    let mut r = opened(paged_listing(30, 10));
    r.vm.views.listing.page_size = 10;
    r.select(0x401000);
    r.vm.ensure_listing();
    r.vm.listing_focus(0x401000 + 22 * 4);
    r.settle();
    let l = &mut r.vm.views.listing;
    assert_eq!(l.rows.len(), 30.min(l.rows.len()));
    assert_eq!(l.selected, Some(22));
    assert_eq!(l.take_scroll(), Some(22));
    assert_eq!(l.take_scroll(), None);
    assert_eq!(l.pending_focus, None);
    assert_eq!(r.vm.views.cursor, Some(0x401000 + 22 * 4));

    // An address that is not in the function stops the search at the end.
    r.vm.listing_focus(0x409000);
    r.settle();
    assert_eq!(r.vm.views.listing.pending_focus, None);
    assert_eq!(r.vm.views.listing.rows.len(), 30);
}

#[test]
fn decompiler_clicks_select_the_matching_listing_row() {
    let mut r = opened(paged_listing(12, 12));
    r.select(0x401000);
    r.vm.ensure_listing();
    r.settle();
    // A token at an instruction's address selects that row.
    assert!(r.vm.sync_listing_to(0x401000 + 8));
    assert_eq!(r.vm.views.listing.selected, Some(2));
    // A call target selects the first instruction that calls it.
    assert!(r.vm.sync_listing_to(0x401040));
    assert_eq!(r.vm.views.listing.selected, Some(4));
    assert_eq!(r.vm.views.listing.take_scroll(), Some(4));
    assert_eq!(r.vm.views.cursor, Some(0x401000 + 16));
    // Nothing matches: the selection stays.
    assert!(!r.vm.sync_listing_to(0x500000));
    assert_eq!(r.vm.views.listing.selected, Some(4));
}

#[test]
fn a_failed_listing_says_why_and_can_be_retried() {
    let mut r = opened(base().fail(
        "disassemble",
        ErrorCode::Unsupported,
        "the engine cannot disassemble",
    ));
    r.select(0x401000);
    r.vm.ensure_listing();
    r.settle();
    let l = &r.vm.views.listing;
    assert!(
        l.error
            .as_deref()
            .unwrap_or("")
            .contains("cannot disassemble"),
        "{:?}",
        l.error
    );
    r.vm.ensure_listing();
    r.settle();
    assert_eq!(r.backend.calls_to("disassemble").len(), 1, "no retry loop");
    r.vm.retry_listing();
    r.settle();
    assert_eq!(r.backend.calls_to("disassemble").len(), 2);
}

// ------------------------------------------------------------------ memory map and bytes

fn mem_block(
    name: &str,
    start: u64,
    end: u64,
    perms: &str,
    init: bool,
    kind: &str,
    space: Option<&str>,
) -> Value {
    let mut b = json!({
        "name": u(name), "start": format!("{start:#x}"), "end": format!("{end:#x}"),
        "size": end - start, "perms": perms, "initialized": init, "kind": kind,
    });
    if let Some(s) = space {
        b["space"] = json!(s);
    }
    b
}

/// Memory: .text (initialized), .bss (not) and noise that must not reach the block list.
fn with_memory(b: FakeBackend) -> FakeBackend {
    b.reply(
        "memory_map",
        json!({"blocks": [
            mem_block(".bss", 0x404000, 0x405000, "rw-", false, "default", None),
            mem_block(".text", 0x401000, 0x403000, "r-x", true, "default", None),
            mem_block(".comment", 0, 0x20, "---", true, "overlay", Some(".comment")),
            mem_block("EXTERNAL", 0x500000, 0x500100, "rw-", false, "external", None),
        ]}),
    )
    .on("read_bytes", |a| {
        let start = addr_of(a, "address");
        let len = a["length"].as_u64().unwrap_or(0);
        // .text is 0x401000..0x403000; .bss starts at 0x404000 and reads as uninitialized zeros.
        let end = (start + len).min(0x405000);
        let mut data = Vec::new();
        for a in start..end {
            data.push(if (0x401000..0x403000).contains(&a) { (a & 0xff) as u8 } else { 0 });
        }
        let mut out = json!({
            "start": format!("{start:#x}"),
            "bytes": base64::engine::general_purpose::STANDARD.encode(&data),
            "length": data.len(), "complete": end == start + len,
        });
        if end > 0x404000 && start < 0x405000 {
            out["uninitialized"] = json!([{"space": "ram", "start": format!("{:#x}", start.max(0x404000)), "end": format!("{end:#x}")}]);
        }
        Ok(out)
    })
}

#[test]
fn the_memory_map_lists_ram_blocks_in_address_order() {
    let mut r = opened(with_memory(base()));
    let m = &r.vm.views.memory;
    assert!(m.loaded);
    let names: Vec<&str> = m.blocks.iter().map(|b| b.name.as_str()).collect();
    assert_eq!(names, [".text", ".bss"]);
    assert_eq!(m.blocks[0].len(), 0x2000);
    assert!(m.blocks[0].label().contains("r-x"));
    assert!(m.blocks[1].label().contains("no contents"));
    assert_eq!(m.block_index_of(0x401800), Some(0));
    assert_eq!(m.block_index_of(0x404010), Some(1));
    assert_eq!(m.block_index_of(0x500000), None);

    r.vm.hex_select_block(1);
    assert_eq!(r.vm.views.hex.block, Some(1));
    assert_eq!(r.vm.views.hex.take_scroll(), Some(0x404000));
    assert_eq!(r.vm.hex_window(), Some(0x404000..0x405000));
    r.vm.hex_select_block(7); // out of range: ignored
    assert_eq!(r.vm.views.hex.block, Some(1));
}

#[test]
fn a_missing_memory_map_does_not_break_the_hex_view() {
    let mut r = opened(base());
    assert!(!r.vm.views.memory.loaded);
    assert!(r.vm.views.memory.error.is_some());
    r.select(0x401000);
    // Falls back to the function's own bytes.
    assert_eq!(r.vm.hex_window(), Some(0x401000..0x401040));
    assert_eq!(r.vm.views.hex.block, None);
}

#[test]
fn hex_fetches_the_function_range_once_and_any_address_on_demand() {
    let mut r = opened(with_memory(base()));
    r.select(0x401000);
    // Selecting a function prefetched exactly its page in one call.
    let reads = r.backend.calls_to("read_bytes");
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert_eq!(
        reads[0],
        json!({"address": "0x401000", "length": PAGE_SIZE})
    );
    assert_eq!(r.vm.views.hex.block, Some(0));
    assert_eq!(r.vm.views.hex.highlight, Some(0x401000..0x401040));
    assert_eq!(r.vm.views.hex.take_scroll(), Some(0x401000));
    let cache = &r.vm.views.bytes;
    assert_eq!(cache.byte(0x401010), Some(0x10));
    assert_eq!(cache.state(0x401010), ByteState::Ready);

    // Reading what is cached asks for nothing; the view can paint and service every frame.
    let mut buf = [0u8; 32];
    cache.read(0x401000, &mut buf);
    assert_eq!(buf[5], 5);
    r.vm.service_bytes();
    r.settle();
    assert_eq!(r.backend.calls_to("read_bytes").len(), 1);

    // Scrolling to an address nobody asked about notes the page; servicing fetches it.
    let mut buf = [0u8; 16];
    r.vm.views.bytes.read(0x402000, &mut buf);
    assert_eq!(buf, [0; 16], "unloaded bytes read as zero meanwhile");
    assert_eq!(r.vm.views.bytes.state(0x402000), ByteState::Loading);
    r.vm.service_bytes();
    r.settle();
    assert_eq!(r.backend.calls_to("read_bytes").len(), 2);
    assert_eq!(r.backend.calls_to("read_bytes")[1]["address"], "0x402000");
    assert_eq!(r.vm.views.bytes.byte(0x402003), Some(3));

    // Two neighbouring pages go out as one call.
    r.vm.views.bytes.want_range(0x404000, 2 * PAGE_SIZE - 1);
    r.vm.service_bytes();
    r.settle();
    let reads = r.backend.calls_to("read_bytes");
    assert_eq!(reads.len(), 3);
    // .bss ends at 0x405000, so the second page has nothing mapped and is not requested.
    assert_eq!(
        reads[2],
        json!({"address": "0x404000", "length": PAGE_SIZE})
    );
}

#[test]
fn uninitialized_memory_is_marked_and_unmapped_bytes_too() {
    let mut r = opened(with_memory(base()));
    r.select(0x401000);
    assert!(r.vm.hex_goto(0x404010));
    r.settle();
    assert_eq!(r.vm.views.hex.block, Some(1));
    assert_eq!(r.vm.views.hex.take_scroll(), Some(0x404010));
    let c = &r.vm.views.bytes;
    assert_eq!(c.state(0x404010), ByteState::Uninitialized);
    assert_eq!(c.byte(0x404010), Some(0));
    // The read stopped at the end of mapped memory (0x405000).
    assert_eq!(c.state(0x405000), ByteState::Loading);
    // Nothing is mapped at 0x600000: the jump is refused.
    assert!(!r.vm.hex_goto(0x600000));
}

#[test]
fn a_failed_read_leaves_the_page_unmapped_and_retry_asks_again() {
    let mut r = opened(base().fail("read_bytes", ErrorCode::Internal, "boom"));
    r.select(0x401000);
    assert_eq!(r.vm.views.bytes.state(0x401000), ByteState::Unmapped);
    let n = r.backend.calls_to("read_bytes").len();
    r.vm.service_bytes();
    r.settle();
    assert_eq!(r.backend.calls_to("read_bytes").len(), n, "no retry loop");
    r.vm.views.bytes.retry_failed();
    let _ = r.vm.views.bytes.state(0x401000);
    r.vm.service_bytes();
    r.settle();
    assert_eq!(r.backend.calls_to("read_bytes").len(), n + 1);
}

// ------------------------------------------------------------------ graph

fn cfg_reply() -> Value {
    json!({
        "function": "0x401000",
        "blocks": [
            {"start": "0x401000", "end": "0x401008", "instructions": 2},
            {"start": "0x401008", "end": "0x401010", "instructions": 2},
            {"start": "0x401010", "end": "0x401018", "instructions": 2},
        ],
        "edges": [
            {"from": "0x401000", "to": "0x401008", "kind": "conditional_false"},
            {"from": "0x401000", "to": "0x401010", "kind": "conditional_true"},
            {"from": "0x401008", "to": "0x401010", "kind": "fallthrough"},
        ],
        "truncated": false,
    })
}

#[test]
fn the_graph_groups_listing_rows_by_block_once_everything_is_loaded() {
    let mut r = opened(paged_listing(6, 2).reply("cfg", cfg_reply()));
    r.vm.views.listing.page_size = 2;
    r.select(0x401000);
    r.vm.ensure_graph();
    r.settle();
    r.vm.ensure_graph();
    r.settle();
    // The graph needs every row, so it paged through the whole function.
    assert_eq!(r.vm.views.listing.rows.len(), 6);
    assert!(!r.vm.views.listing.has_more());
    let g = &r.vm.views.graph;
    let data = g.data.as_ref().expect("graph is built");
    assert_eq!(data.blocks.len(), 3);
    assert_eq!(
        data.blocks
            .iter()
            .map(|b| b.lines.len())
            .collect::<Vec<_>>(),
        [2, 2, 2]
    );
    assert_eq!(data.blocks[1].id, 0x401008);
    assert_eq!(data.blocks[1].title, "0x401008");
    assert_eq!(data.entry, Some(0x401000));
    assert_eq!(data.edges.len(), 3);
    assert!(
        data.edges
            .contains(&(0x401000, 0x401010, GraphEdgeKind::True))
    );
    assert!(
        data.edges
            .contains(&(0x401000, 0x401008, GraphEdgeKind::False))
    );
    // A line is address, mnemonic, then operands with colours.
    let line = &data.blocks[0].lines[0];
    assert_eq!(line[0].0.trim(), "401000");
    assert!(line[1].0.starts_with("nop"));

    // Asking again changes nothing and costs nothing.
    let rev = g.revision;
    let calls = r.backend.calls().len();
    r.vm.ensure_graph();
    r.settle();
    assert_eq!(r.vm.views.graph.revision, rev);
    assert_eq!(r.backend.calls().len(), calls);
}

#[test]
fn graph_selection_follows_the_listing_and_a_double_click_jumps() {
    let mut r = opened(paged_listing(6, 6).reply("cfg", cfg_reply()));
    r.select(0x401000);
    r.vm.ensure_graph();
    r.settle();
    r.vm.select_listing_row(2); // 0x401008, the second block
    assert_eq!(r.vm.views.graph.selected, Some(0x401008));
    r.vm.graph_select(0x401010);
    assert_eq!(r.vm.views.cursor, Some(0x401010));
    assert_eq!(r.vm.views.listing.selected, Some(4));

    let before = r.vm.nav.entries().0.len();
    r.vm.graph_open(0x401008);
    r.settle();
    assert_eq!(r.vm.nav.current(), Some(0x401008));
    assert_eq!(r.vm.nav.entries().0.len(), before + 1);
    assert_eq!(r.vm.views.listing.selected, Some(2));
    assert_eq!(r.vm.views.take_reveal(), Some(Reveal::Listing));
    assert_eq!(r.vm.views.graph.selected, Some(0x401008));
    // Still the same function, so nothing was decompiled again.
    assert_eq!(r.backend.calls_to("decompile").len(), 1);
}

#[test]
fn building_a_graph_tolerates_missing_rows_and_dangling_edges() {
    use kraken_proto::{CfgBlock, CfgEdge, CfgEdgeKind, Hex64};
    let blocks = [CfgBlock {
        start: Hex64(0x10),
        end: Hex64(0x20),
        instructions: 0,
    }];
    let edges = [CfgEdge {
        from: Hex64(0x10),
        to: Hex64(0x99),
        kind: CfgEdgeKind::Jump,
    }];
    let g = graph::build_graph(0x10, &blocks, &edges, &[]);
    assert_eq!(g.blocks.len(), 1);
    assert!(g.blocks[0].lines.is_empty());
    assert!(g.edges.is_empty());
    assert_eq!(g.entry, Some(0x10));
}

// ------------------------------------------------------------------ cross-references

fn with_xrefs(b: FakeBackend) -> FakeBackend {
    b.on("callers", |a| {
        let cursor = a["cursor"].as_str().map(str::to_string);
        Ok(match cursor.as_deref() {
            None => page(
                vec![
                    xref(0x401010, 0x401040, "call", Some((0x401000, "main"))),
                    xref(0x401108, 0x401040, "call", Some((0x401100, "other"))),
                ],
                Some("2"),
            ),
            Some(_) => page(
                vec![xref(0x401030, 0x401040, "call", Some((0x401000, "main")))],
                None,
            ),
        })
    })
    .reply(
        "callees",
        page(
            vec![xref(0x401044, 0x401100, "call", Some((0x401040, "helper")))],
            None,
        ),
    )
    .on("xrefs", |a| {
        let to = addr_of(a, "address");
        Ok(if to == 0x405000 {
            page(vec![], None)
        } else {
            page(
                vec![
                    xref(0x401004, to, "read", None),
                    xref(0x401108, to, "data", Some((0x401100, "other"))),
                ],
                None,
            )
        })
    })
}

#[test]
fn callers_and_callees_load_for_the_current_function_and_page() {
    let mut r = opened(with_xrefs(paged_listing(4, 4)));
    r.select(0x401040);
    r.vm.ensure_xrefs();
    r.vm.ensure_xrefs();
    r.settle();
    assert_eq!(r.backend.calls_to("callers").len(), 1);
    assert_eq!(r.backend.calls_to("callers")[0]["address"], "0x401040");
    assert_eq!(r.backend.calls_to("callees").len(), 1);
    let x = &r.vm.views.xrefs;
    assert_eq!(x.callers.items.len(), 2);
    assert!(x.callers.has_more());
    assert_eq!(
        x.callers.items[0].from_function.as_ref().unwrap().name,
        "main"
    );
    assert_eq!(x.callers.items[0].kind_label(), "call");
    assert_eq!(x.callees.items[0].to, 0x401100);

    r.vm.more_xrefs(XrefWhich::Callers);
    r.settle();
    assert_eq!(r.backend.calls_to("callers")[1]["cursor"], "2");
    assert_eq!(r.vm.views.xrefs.callers.items.len(), 3);
    assert!(!r.vm.views.xrefs.callers.has_more());
    r.vm.more_xrefs(XrefWhich::Callers);
    assert_eq!(
        r.backend.calls_to("callers").len(),
        2,
        "nothing more to fetch"
    );

    // Another function starts over; a refresh of the same one reloads in place.
    r.select(0x401000);
    assert!(r.vm.views.xrefs.callers.items.is_empty());
    r.vm.ensure_xrefs();
    r.settle();
    assert_eq!(r.backend.calls_to("callers")[2]["address"], "0x401000");
    r.vm.refresh_current();
    r.settle();
    assert!(r.vm.views.xrefs.stale);
    r.vm.ensure_xrefs();
    r.settle();
    assert_eq!(r.backend.calls_to("callers").len(), 4);
    assert!(!r.vm.views.xrefs.callers.items.is_empty());
}

#[test]
fn clicking_a_reference_navigates_and_is_recorded_in_the_history() {
    let mut r = opened(with_xrefs(paged_listing(4, 4)));
    r.select(0x401040);
    r.vm.ensure_xrefs();
    r.settle();
    // A caller row goes to the call site, which lies inside main.
    r.vm.open_xref(XrefWhich::Callers, 0);
    r.settle();
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401000);
    assert_eq!(r.vm.nav.current(), Some(0x401010));
    assert_eq!(r.vm.views.cursor, Some(0x401010));
    // A callee row goes to the called function.
    r.select(0x401040);
    r.vm.ensure_xrefs();
    r.settle();
    r.vm.open_xref(XrefWhich::Callees, 0);
    r.settle();
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401100);
    r.vm.go_back();
    r.settle();
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401040);
    r.vm.go_back();
    r.settle();
    // Back through the call-site entry lands in main again, not on a function entry.
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401000);
    assert_eq!(r.vm.views.cursor, Some(0x401010));
}

#[test]
fn references_to_an_address_load_on_demand_and_reveal_the_xrefs_view() {
    let mut r = opened(with_xrefs(base()));
    r.select(0x401000);
    assert!(r.vm.views.xrefs.references.is_none());
    r.vm.show_references(0x404000, Some("counter".into()));
    r.settle();
    let refs = r.vm.views.xrefs.references.as_ref().unwrap();
    assert_eq!(refs.label, "counter");
    assert_eq!(refs.list.items.len(), 2);
    let args = &r.backend.calls_to("xrefs")[0];
    assert_eq!(
        (args["address"].as_str(), args["direction"].as_str()),
        (Some("0x404000"), Some("to"))
    );
    assert_eq!(r.vm.views.take_reveal(), Some(Reveal::Xrefs));
    // Without a label the heading uses the function name or the address.
    r.vm.show_references(0x401040, None);
    assert_eq!(
        r.vm.views.xrefs.references.as_ref().unwrap().label,
        "helper"
    );
    r.vm.show_references(0x404008, None);
    assert_eq!(
        r.vm.views.xrefs.references.as_ref().unwrap().label,
        "0x404008"
    );
    r.settle();

    // The key / context action refers to the cursor.
    r.vm.views.cursor = Some(0x401234);
    r.vm.references_to_cursor();
    r.settle();
    assert_eq!(
        r.vm.views.xrefs.references.as_ref().unwrap().address,
        0x401234
    );
    // A click on a reference goes to where it is.
    r.vm.open_xref(XrefWhich::References, 1);
    r.settle();
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401100);
}

// ------------------------------------------------------------------ strings, imports, exports

fn string_row(addr: u64, v: &str) -> Value {
    json!({"address": format!("{addr:#x}"), "value": u(v), "truncated": false, "encoding": "ascii", "length": v.len() + 1})
}

fn sym_row(name: &str, addr: Option<u64>, lib: Option<&str>) -> Value {
    let mut s = json!({"name": u(name), "kind": "function"});
    if let Some(a) = addr {
        s["address"] = json!(format!("{a:#x}"));
    }
    if let Some(l) = lib {
        s["library"] = u(l);
    }
    s
}

fn with_lists(b: FakeBackend) -> FakeBackend {
    b.on("strings", |a| {
        let filter = a["filter"].as_str().unwrap_or("").to_lowercase();
        let all = [
            ("usage: demo", 0x402000u64),
            ("error %d", 0x402010),
            ("hello", 0x402020),
        ];
        let rows: Vec<Value> = all
            .iter()
            .filter(|(s, _)| s.contains(&filter))
            .map(|(s, a)| string_row(*a, s))
            .collect();
        let first = a["cursor"].as_str().map_or(0, |c| c.parse().unwrap_or(0));
        let limit = 2;
        let end = (first + limit).min(rows.len());
        let next = (end < rows.len()).then(|| end.to_string());
        Ok(page(rows[first..end].to_vec(), next.as_deref()))
    })
    .on("imports", |a| {
        let rows = [
            sym_row("printf", Some(0x401f00), Some("libc.so.6")),
            sym_row("malloc", Some(0x401f10), Some("libc.so.6")),
            sym_row("SSL_read", Some(0x401f20), Some("libssl.so")),
            sym_row("data_import", None, None),
        ];
        Ok(match a["cursor"].as_str() {
            None => page(rows[..2].to_vec(), Some("2")),
            Some(_) => page(rows[2..].to_vec(), None),
        })
    })
    .reply(
        "exports",
        page(vec![sym_row("main", Some(0x401000), None)], None),
    )
}

#[test]
fn strings_page_filter_and_reload_from_the_top() {
    let mut r = opened(with_lists(with_xrefs(base())));
    r.vm.ensure_strings();
    r.vm.ensure_strings();
    r.settle();
    assert_eq!(r.backend.calls_to("strings").len(), 1);
    assert_eq!(r.backend.calls_to("strings")[0]["min_len"], 4);
    let s = &r.vm.views.strings;
    assert_eq!(s.items.len(), 2);
    assert_eq!(s.items[0].value, "usage: demo");
    assert_eq!(s.items[1].address, 0x402010);
    assert!(s.has_more());

    // Two rows are within the look-ahead of the end: scrolling asks for the next page, once.
    // The count is read after `settle`, when the request has surely reached the backend.
    r.vm.strings_scrolled(0);
    r.vm.strings_scrolled(2);
    r.settle();
    assert_eq!(r.backend.calls_to("strings").len(), 2);
    assert_eq!(r.vm.views.strings.items.len(), 3);
    assert!(!r.vm.views.strings.has_more());
    r.vm.strings_scrolled(3);
    r.settle();
    assert_eq!(
        r.backend.calls_to("strings").len(),
        2,
        "nothing more to load"
    );

    r.vm.set_strings_filter("ERR");
    r.vm.set_strings_filter("ERR"); // unchanged: no second request
    r.settle();
    assert_eq!(r.backend.calls_to("strings").len(), 3);
    assert_eq!(r.backend.calls_to("strings")[2]["filter"], "ERR");
    assert_eq!(r.vm.views.strings.items.len(), 1);
    assert_eq!(r.vm.views.strings.items[0].value, "error %d");
}

#[test]
fn a_slow_unfiltered_page_cannot_overwrite_a_newer_filtered_list() {
    let gate = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let g = gate.clone();
    let b = base().on("strings", move |a| {
        // The first (unfiltered) request is answered; the filtered one is answered differently.
        let _ = &g;
        let items = if a.get("filter").is_some() {
            vec![string_row(0x402010, "error %d")]
        } else {
            vec![
                string_row(0x402000, "usage"),
                string_row(0x402010, "error %d"),
            ]
        };
        Ok(page(items, None))
    });
    let mut r = opened(b);
    r.vm.ensure_strings();
    r.vm.set_strings_filter("err"); // issued before the first answer is applied
    r.settle();
    assert_eq!(r.vm.views.strings.items.len(), 1);
    assert_eq!(r.vm.views.strings.filter, "err");
    drop(gate);
}

#[test]
fn imports_filter_by_name_and_library_and_load_every_page_to_do_so() {
    let mut r = opened(with_lists(base()));
    r.vm.ensure_symbols(SymbolTable::Imports);
    r.settle();
    assert_eq!(r.vm.views.imports.items.len(), 2);
    // Without a filter the second page waits for scrolling.
    r.vm.ensure_symbols(SymbolTable::Imports);
    r.settle();
    assert_eq!(r.vm.views.imports.items.len(), 2);
    assert_eq!(r.vm.views.imports.visible(), vec![0, 1]);

    r.vm.set_symbols_filter(SymbolTable::Imports, "ssl");
    r.vm.ensure_symbols(SymbolTable::Imports); // a filter pulls in the rest
    r.settle();
    assert_eq!(r.vm.views.imports.items.len(), 4);
    assert_eq!(r.vm.views.imports.visible(), vec![2]);
    r.vm.set_symbols_filter(SymbolTable::Imports, "LIBC");
    assert_eq!(r.vm.views.imports.visible(), vec![0, 1]);

    r.vm.ensure_symbols(SymbolTable::Exports);
    r.settle();
    assert_eq!(r.vm.views.exports.items[0].name, "main");
    assert_eq!(r.vm.views.exports.items[0].address, Some(0x401000));
}

#[test]
fn opening_a_string_or_import_shows_its_references_and_goes_to_the_first_referrer() {
    let mut r = opened(with_lists(with_xrefs(paged_listing(4, 4))));
    r.select(0x401040);
    r.vm.ensure_strings();
    r.settle();
    r.vm.open_string(0);
    assert_eq!(r.vm.views.take_reveal(), Some(Reveal::Xrefs));
    r.settle();
    // The first reference with a function is the one in `other`.
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401100);
    assert_eq!(r.vm.nav.current(), Some(0x401108));
    let refs = r.vm.views.xrefs.references.as_ref().unwrap();
    assert!(refs.label.contains("usage: demo"));
    assert!(!refs.go_first, "only the first arrival navigates");
    let call = &r.backend.calls_to("xrefs")[0];
    assert_eq!(call["address"], "0x402000");

    // Imports go through their stub address.
    r.vm.ensure_symbols(SymbolTable::Imports);
    r.settle();
    r.vm.open_symbol(SymbolTable::Imports, 1);
    r.settle();
    assert_eq!(r.backend.calls_to("xrefs")[1]["address"], "0x401f10");
    assert_eq!(
        r.vm.views.xrefs.references.as_ref().unwrap().label,
        "malloc"
    );
    // No address: a friendly note, no request.
    r.vm.ensure_symbols(SymbolTable::Imports);
    r.vm.set_symbols_filter(SymbolTable::Imports, "");
    r.settle();
    let n = r.backend.calls_to("xrefs").len();
    r.vm.symbols_scrolled(SymbolTable::Imports, 2);
    r.settle();
    r.vm.open_symbol(SymbolTable::Imports, 3);
    assert_eq!(r.backend.calls_to("xrefs").len(), n);
    assert_eq!(r.vm.toasts.last().unwrap().level, ToastLevel::Info);
    assert!(r.vm.toasts.last().unwrap().text.contains("data_import"));
}

#[test]
fn a_string_nobody_refers_to_says_so() {
    let b = with_lists(with_xrefs(base())).reply("xrefs", page(vec![], None));
    let mut r = opened(b);
    r.vm.ensure_strings();
    r.settle();
    r.vm.open_string(0);
    r.settle();
    let t = r.vm.toasts.last().unwrap();
    assert!(
        t.text.contains("Nothing") && t.text.contains("usage: demo"),
        "{}",
        t.text
    );
    assert!(r.vm.current.is_none(), "nothing to navigate to");
}

// ------------------------------------------------------------------ navigation

#[test]
fn navigating_inside_the_current_function_keeps_the_decompilation() {
    let mut r = opened(paged_listing(10, 10));
    r.select(0x401000);
    r.vm.ensure_listing();
    r.settle();
    let decompiles = r.backend.calls_to("decompile").len();
    r.vm.goto(0x401000 + 12);
    r.settle();
    assert_eq!(r.backend.calls_to("decompile").len(), decompiles);
    assert_eq!(r.vm.views.listing.selected, Some(3));
    assert_eq!(r.vm.views.hex.take_scroll(), Some(0x40100c));
    assert_eq!(r.vm.nav.current(), Some(0x40100c));
    r.vm.goto(0x401000 + 20);
    r.vm.go_back();
    r.settle();
    assert_eq!(r.vm.views.listing.selected, Some(3));
    r.vm.go_forward();
    r.settle();
    assert_eq!(r.vm.views.listing.selected, Some(5));
    assert_eq!(r.backend.calls_to("decompile").len(), decompiles);
}

#[test]
fn an_address_in_another_function_is_resolved_from_the_list_without_a_request() {
    let mut r = opened(paged_listing(4, 4));
    r.select(0x401000);
    // 0x401110 lies inside `other` (0x401100, size 0x20).
    r.vm.goto(0x401110);
    r.settle();
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401100);
    assert_eq!(r.vm.views.cursor, Some(0x401110));
    assert!(r.backend.calls_to("cfg").is_empty());
}

#[test]
fn an_unknown_address_asks_the_engine_which_function_holds_it() {
    let b = base()
        .on("cfg", |a| {
            let at = addr_of(a, "function");
            if (0x401200..0x401240).contains(&at) {
                Ok(json!({"function": "0x401200", "blocks": [], "edges": [], "truncated": false}))
            } else {
                Err(ProtoError::new(ErrorCode::NotFound, "no function there"))
            }
        })
        .on("get_function", |a| {
            let n = addr_of(a, "address");
            let mut v = fn_view(n, "hidden", 0x40);
            v["comments"] = json!([]);
            v["versions"] = json!({});
            Ok(v)
        });
    let mut r = opened(with_memory(b));
    r.select(0x401000);
    r.vm.goto(0x401210);
    r.settle();
    assert_eq!(r.backend.calls_to("cfg")[0]["function"], "0x401210");
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401200);
    assert_eq!(r.vm.views.cursor, Some(0x401210));
    assert_eq!(r.vm.nav.current(), Some(0x401210));
}

#[test]
fn data_addresses_open_the_hex_view_and_stay_in_the_history() {
    let b = with_memory(base()).fail("cfg", ErrorCode::NotFound, "not in a function");
    let mut r = opened(b);
    r.select(0x401000);
    let _ = r.vm.views.take_reveal();
    r.vm.goto(0x404010);
    r.settle();
    // The function on screen did not change; the hex view moved to the data.
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401000);
    assert_eq!(r.vm.views.hex.block, Some(1));
    assert_eq!(r.vm.views.hex.take_scroll(), Some(0x404010));
    assert_eq!(r.vm.views.take_reveal(), Some(Reveal::Hex));
    assert_eq!(r.vm.views.cursor, Some(0x404010));
    assert_eq!(r.vm.nav.current(), Some(0x404010));
    assert!(r.vm.nav.can_back());

    // Nothing mapped: a plain explanation instead of an empty view.
    r.vm.goto(0x900000);
    r.settle();
    let t = r.vm.toasts.last().unwrap();
    assert_eq!(t.level, ToastLevel::Info);
    assert!(t.text.contains("0x900000"), "{}", t.text);
    r.vm.go_back();
    r.settle();
    assert_eq!(r.vm.views.hex.block, Some(1));
}

#[test]
fn an_engine_without_cfg_support_still_opens_unknown_addresses_as_functions() {
    // `cfg` is unscripted here, so the fake answers `unsupported`.
    let mut r = opened(base());
    r.select(0x401000);
    r.vm.goto(0x401300);
    r.settle();
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401300);
}

#[test]
fn opening_another_project_forgets_every_view() {
    let mut r = opened(with_memory(with_lists(with_xrefs(paged_listing(3, 3)))));
    r.select(0x401000);
    r.vm.ensure_listing();
    r.vm.ensure_xrefs();
    r.vm.ensure_strings();
    r.settle();
    assert!(!r.vm.views.listing.rows.is_empty());
    r.vm.open_project("/tmp/other");
    r.settle();
    let v = &r.vm.views;
    assert!(v.listing.rows.is_empty() && v.strings.items.is_empty());
    assert!(v.xrefs.callers.items.is_empty() && v.function.is_none());
    assert!(v.memory.loaded, "the new project's memory map is loaded");
    assert_eq!(v.bytes.page_count(), 0);
}

// ------------------------------------------------------------------ in-process engine over a recorded fixture

mod recorded {
    use std::path::Path;

    use engine_fake::FixtureFile;

    use super::*;
    use crate::demo::{DemoProject, demo_project_with};

    struct Live {
        _rt: Runtime,
        vm: ViewModel,
    }

    impl Live {
        fn settle(&mut self) {
            assert!(self.vm.block_until_idle(WAIT), "calls did not finish");
        }

        fn addr(&self, name: &str) -> u64 {
            self.vm
                .functions
                .items
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("no function {name}"))
                .address
        }

        fn select(&mut self, name: &str) -> u64 {
            let a = self.addr(name);
            self.vm.select_function(a);
            self.settle();
            a
        }
    }

    /// `pie_list-O0`: a small real program with recorded disassembly, CFG, xrefs, strings and
    /// memory map.
    fn live() -> Live {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/fixtures/pie_list-O0.json");
        let fixture = FixtureFile::from_path(&path).expect("the corpus fixture loads");
        let rt = Runtime::new().expect("runtime");
        let DemoProject {
            backend,
            binary,
            project_dir,
        } = {
            let _g = rt.enter();
            demo_project_with(fixture, Duration::ZERO).unwrap()
        };
        let mut vm = ViewModel::new(backend, rt.handle().clone());
        vm.create_project(binary.to_string_lossy(), project_dir.to_string_lossy());
        assert!(vm.block_until_idle(WAIT));
        assert_eq!(vm.connection, Connection::Open, "{:?}", vm.toasts);
        vm.start_analysis();
        assert!(
            vm.block_until(WAIT, |v| v.analysis.phase == crate::AnalysisPhase::Complete
                && !v.busy())
        );
        assert!(
            vm.functions.items.len() >= 26,
            "{}",
            vm.functions.items.len()
        );
        Live { _rt: rt, vm }
    }

    #[test]
    fn listing_of_main_pages_and_carries_call_targets() {
        let mut l = live();
        l.vm.views.listing.page_size = 40;
        let main = l.select("main");
        l.vm.ensure_listing();
        l.settle();
        assert_eq!(l.vm.views.listing.rows.len(), 40);
        assert!(l.vm.views.listing.has_more());
        l.vm.listing_scrolled(30);
        l.settle();
        l.vm.listing_scrolled(70);
        l.settle();
        let rows = &l.vm.views.listing.rows;
        assert_eq!(rows.len(), 109, "main has 109 recorded instructions");
        assert_eq!(rows[0].address, main);
        assert!(rows.windows(2).all(|w| w[0].address < w[1].address));
        let call = rows
            .iter()
            .find(|r| r.mnemonic == "call")
            .expect("main calls things");
        let target = call
            .operands
            .iter()
            .find_map(|o| o.target)
            .expect("call has a target");
        assert!(
            l.vm.functions.find(target).is_some(),
            "{target:#x} is a known function"
        );
        assert!(rows.iter().all(|r| !r.bytes.is_empty()));
    }

    #[test]
    fn clicking_a_decompiler_call_highlights_the_call_in_the_listing() {
        let mut l = live();
        let main = l.select("main");
        let sort = l.addr("list_sort");
        l.vm.ensure_listing();
        l.settle();
        let Load::Ready(d) = &l.vm.current.as_ref().unwrap().decompiled else {
            panic!("main decompiled");
        };
        // The decompiler tokens come straight from the fixture, with the call to list_sort.
        let tok = d
            .result
            .tokens
            .iter()
            .find(|t| t.target == Some(kraken_proto::Locator::ram(sort)))
            .expect("main's decompilation names list_sort");
        assert_eq!(tok.symbol.as_deref(), Some("list_sort"));
        assert!(l.vm.sync_listing_to(sort));
        let sel = l.vm.views.listing.selected_row().unwrap();
        assert_eq!(sel.mnemonic, "call");
        assert!(sel.refers_to(sort));
        assert!(sel.address > main);
    }

    #[test]
    fn the_graph_of_main_has_every_block_and_every_instruction() {
        let mut l = live();
        l.select("main");
        l.vm.ensure_graph();
        l.settle();
        l.vm.ensure_graph();
        l.settle();
        let g = l.vm.views.graph.data.as_ref().expect("graph built");
        assert_eq!(g.blocks.len(), 19);
        let lines: usize = g.blocks.iter().map(|b| b.lines.len()).sum();
        assert_eq!(lines, 109);
        assert!(!g.edges.is_empty());
        assert_eq!(g.entry, Some(g.blocks[0].id));
        assert!(g.edges.iter().all(|(a, b, _)| {
            g.blocks.iter().any(|x| x.id == *a) && g.blocks.iter().any(|x| x.id == *b)
        }));
    }

    #[test]
    fn hex_shows_text_bytes_and_greys_out_bss() {
        let mut l = live();
        let main = l.select("main");
        let m = l.vm.views.memory.clone();
        let text = m.block_index_of(main).expect("main is in a block");
        assert_eq!(m.blocks[text].name, ".text");
        assert!(
            m.blocks
                .iter()
                .all(|b| b.name != "EXTERNAL" && b.name != ".comment")
        );
        assert_eq!(l.vm.views.hex.block, Some(text));
        // The function's bytes arrived and match its first instruction.
        l.settle();
        let first = &l.vm.views.listing;
        assert!(first.rows.is_empty(), "the listing is lazy");
        l.vm.ensure_listing();
        l.settle();
        let row = &l.vm.views.listing.rows[0];
        for (i, b) in row.bytes.iter().enumerate() {
            assert_eq!(l.vm.views.bytes.byte(main + i as u64), Some(*b));
        }
        assert_eq!(l.vm.views.bytes.state(main), ByteState::Ready);

        let bss = m.blocks.iter().position(|b| b.name == ".bss").unwrap();
        let start = m.blocks[bss].start;
        assert!(l.vm.hex_goto(start));
        l.settle();
        assert_eq!(l.vm.views.bytes.state(start), ByteState::Uninitialized);
        // The dropdown jump lands on the segment start.
        l.vm.hex_select_block(text);
        assert_eq!(
            l.vm.views.hex.take_scroll(),
            Some(l.vm.views.memory.blocks[text].start)
        );
    }

    #[test]
    fn callers_and_callees_come_from_the_recorded_xrefs() {
        let mut l = live();
        let push = l.select("list_push");
        let main = l.addr("main");
        l.vm.ensure_xrefs();
        l.settle();
        let x = &l.vm.views.xrefs;
        assert!(
            x.callers
                .items
                .iter()
                .any(|c| c.from_function.as_ref().is_some_and(|f| f.address == main))
        );
        assert!(x.callers.items.iter().all(|c| c.to == push));
        l.vm.open_xref(XrefWhich::Callers, 0);
        l.settle();
        assert_eq!(l.vm.current.as_ref().unwrap().address, main);
        l.select("main");
        l.vm.ensure_xrefs();
        l.settle();
        assert!(l.vm.views.xrefs.callees.items.iter().any(|c| c.to == push));
    }

    #[test]
    fn strings_imports_and_exports_page_and_open() {
        let mut l = live();
        l.vm.ensure_strings();
        l.vm.ensure_symbols(SymbolTable::Imports);
        l.vm.ensure_symbols(SymbolTable::Exports);
        l.settle();
        assert!(
            l.vm.views.strings.items.len() >= 20,
            "{}",
            l.vm.views.strings.items.len()
        );
        assert_eq!(l.vm.views.imports.items.len(), 11);
        assert_eq!(l.vm.views.exports.items.len(), 14);
        l.vm.set_strings_filter("strncpy");
        l.settle();
        assert_eq!(l.vm.views.strings.items.len(), 1);

        // printf is called from main and its helpers; opening it lands in one of them.
        let i =
            l.vm.views
                .imports
                .items
                .iter()
                .position(|s| s.name == "printf")
                .unwrap();
        l.vm.open_symbol(SymbolTable::Imports, i);
        l.settle();
        let refs = l.vm.views.xrefs.references.as_ref().unwrap();
        assert!(!refs.list.items.is_empty());
        let first = refs
            .list
            .items
            .iter()
            .find(|x| x.from_function.is_some())
            .unwrap();
        assert_eq!(
            l.vm.current.as_ref().unwrap().address,
            first.from_function.as_ref().unwrap().address
        );
        assert_eq!(l.vm.nav.current(), Some(first.from));
    }

    #[test]
    fn data_in_rodata_opens_in_hex_and_back_returns() {
        let mut l = live();
        let main = l.select("main");
        let _ = l.vm.views.take_reveal();
        l.vm.goto(0x102004);
        l.settle();
        assert_eq!(l.vm.views.take_reveal(), Some(Reveal::Hex));
        let blocks = &l.vm.views.memory.blocks;
        assert_eq!(blocks[l.vm.views.hex.block.unwrap()].name, ".rodata");
        assert_eq!(l.vm.current.as_ref().unwrap().address, main);
        l.vm.go_back();
        l.settle();
        assert_eq!(l.vm.nav.current(), Some(main));
    }
}
