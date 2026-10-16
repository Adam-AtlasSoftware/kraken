//! Contract checks of the program-data capabilities (memory, listing, references, CFG, strings,
//! symbols). Absent capabilities are skipped.

use kraken_proto::{
    DisasmRow, DisasmScope, ErrorCode, Hex64, Locator, MemoryBlock, Page, PageRequest, StringEntry,
    SymbolEntry, Xref, XrefDirection, XrefKind,
};
use tokio_util::sync::CancellationToken;

use crate::caps::Engine;
use crate::testing::FixtureExpectations;
use crate::types::{DisasmRequest, StringsRequest, XrefRequest};

type Check = Result<(), String>;

macro_rules! ensure {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return Err(format!($($arg)+));
        }
    };
}

macro_rules! call {
    ($ctx:expr, $e:expr) => {
        $e.await.map_err(|e| format!("{}: {}", $ctx, e))?
    };
}

/// A ram address that no fixture maps.
const UNMAPPED: u64 = u64::MAX - 0xfff;
/// Functions examined per check.
const SAMPLE: usize = 3;

fn offset(l: &Locator) -> u64 {
    match l {
        Locator::Native { offset, .. } => offset.0,
        _ => 0,
    }
}

fn expect_code<T: std::fmt::Debug>(
    what: &str,
    r: Result<T, kraken_proto::ProtoError>,
    code: ErrorCode,
) -> Check {
    match r {
        Ok(v) => Err(format!("{what}: expected {code}, got Ok({v:?})")),
        Err(e) => {
            ensure!(e.code == code, "{what}: expected {code}, got {}", e.code);
            Ok(())
        }
    }
}

fn is_hex_bytes(s: &str) -> bool {
    !s.is_empty()
        && s.len().is_multiple_of(2)
        && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn paged_equal<T: PartialEq + std::fmt::Debug>(what: &str, small: &[T], big: &[T]) -> Check {
    ensure!(
        small == big,
        "{what}: listing in small pages ({} items) differs from one big page ({} items)",
        small.len(),
        big.len()
    );
    Ok(())
}

async fn collect<T, F, Fut>(what: &str, limit: u32, mut next: F) -> Result<Vec<T>, String>
where
    F: FnMut(PageRequest) -> Fut,
    Fut: std::future::Future<Output = Result<Page<T>, kraken_proto::ProtoError>>,
{
    let mut out = Vec::new();
    let mut cursor = None;
    for _ in 0..200_000 {
        let page = next(PageRequest {
            cursor: cursor.clone(),
            limit: Some(limit),
        })
        .await
        .map_err(|e| format!("{what}: {e}"))?;
        ensure!(
            page.items.len() <= limit as usize,
            "{what}: page has {} items for limit {limit}",
            page.items.len()
        );
        out.extend(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return Ok(out),
        }
    }
    Err(format!("{what}: pagination did not terminate"))
}

async fn function_rows(
    engine: &dyn Engine,
    entry: u64,
    scope: DisasmScope,
    limit: u32,
) -> Result<Vec<DisasmRow>, String> {
    let Some(dis) = engine.disassembler() else {
        return Ok(Vec::new());
    };
    let cancel = CancellationToken::new();
    let req = DisasmRequest {
        start: Hex64(entry),
        scope,
    };
    let rows = collect("disassemble", limit, |page| {
        let (cancel, req) = (&cancel, &req);
        async move { dis.disassemble(req, &page, cancel).await }
    })
    .await?;
    // linear scans never end on their own in real programs; callers cap them
    Ok(rows)
}

pub(crate) async fn check_program_data(engine: &dyn Engine, exp: &FixtureExpectations) -> Check {
    let sample: Vec<u64> = exp
        .functions
        .iter()
        .take(SAMPLE)
        .map(|f| offset(&f.locator))
        .collect();
    let Some(&first) = sample.first() else {
        return Ok(());
    };
    check_memory(engine, first).await?;
    check_listing_rows(engine, &sample).await?;
    check_xrefs(engine, &sample).await?;
    check_cfg(engine, &sample).await?;
    check_strings(engine).await?;
    check_symbols(engine).await
}

async fn check_memory(engine: &dyn Engine, first: u64) -> Check {
    let Some(mem) = engine.memory_reader() else {
        return Ok(());
    };
    let cancel = CancellationToken::new();
    let blocks: Vec<MemoryBlock> = call!("memory_map", mem.memory_map(&cancel));
    ensure!(!blocks.is_empty(), "memory_map is empty");
    for b in &blocks {
        ensure!(b.end > b.start, "block {} is empty", b.name);
        let p = b.perms.as_bytes();
        ensure!(
            p.len() == 3
                && matches!(p[0], b'r' | b'-')
                && matches!(p[1], b'w' | b'-')
                && matches!(p[2], b'x' | b'-'),
            "block {} has permissions {:?}",
            b.name,
            b.perms
        );
    }
    let holder = blocks
        .iter()
        .find(|b| b.space == "ram" && b.start.0 <= first && first < b.end.0);
    ensure!(
        holder.is_some_and(|b| b.initialized && b.perms.ends_with('x')),
        "no initialized executable block holds the function at {first:#x}"
    );

    let at = Locator::ram(first);
    let read = call!("read_bytes", mem.read_bytes(&at, 16, &cancel));
    ensure!(read.start.0 == first, "read starts at {}", read.start);
    ensure!(
        !read.bytes.is_empty() && read.bytes.len() <= 16,
        "read returned {} bytes",
        read.bytes.len()
    );
    ensure!(
        read.uninitialized.is_empty(),
        "code reads as uninitialized: {:?}",
        read.uninitialized
    );
    expect_code(
        "read_bytes of length 0",
        mem.read_bytes(&at, 0, &cancel).await,
        ErrorCode::InvalidArgument,
    )?;
    expect_code(
        "read_bytes at an unmapped address",
        mem.read_bytes(&Locator::ram(UNMAPPED), 4, &cancel).await,
        ErrorCode::NotFound,
    )?;

    // the bytes of a read agree with the listing
    if engine.disassembler().is_some() {
        let rows = function_rows(engine, first, DisasmScope::Function, 500).await?;
        let want: String = rows.iter().map(|r| r.bytes.as_str()).collect();
        let got: String = read.bytes.iter().map(|b| format!("{b:02x}")).collect();
        let n = got.len().min(want.len());
        ensure!(
            n > 0 && want[..n] == got[..n],
            "read_bytes {got} disagrees with the listing {}",
            &want[..n]
        );
    }
    // a read that starts in uninitialized memory reports it
    if let Some(b) = blocks
        .iter()
        .find(|b| b.space == "ram" && !b.initialized && b.len() >= 4)
    {
        let r = call!(
            "read_bytes",
            mem.read_bytes(
                &Locator::Native {
                    space: "ram".into(),
                    offset: b.start
                },
                4,
                &cancel
            )
        );
        ensure!(
            !r.uninitialized.is_empty() && r.bytes.iter().all(|x| *x == 0),
            "uninitialized block {} did not read as zeros",
            b.name
        );
    }
    Ok(())
}

async fn check_listing_rows(engine: &dyn Engine, sample: &[u64]) -> Check {
    let Some(dis) = engine.disassembler() else {
        return Ok(());
    };
    let cancel = CancellationToken::new();
    for &entry in sample {
        let small = function_rows(engine, entry, DisasmScope::Function, 5).await?;
        let big = function_rows(engine, entry, DisasmScope::Function, 500).await?;
        paged_equal("function disassembly", &small, &big)?;
        ensure!(!big.is_empty(), "function {entry:#x} has no instructions");
        // a function with a cold part has rows below its entry, so only look for the entry
        ensure!(
            big.iter().any(|r| r.address.0 == entry),
            "the disassembly of {entry:#x} has no instruction at the entry"
        );
        let mut prev = None;
        for r in &big {
            ensure!(
                prev.is_none_or(|p| r.address > p),
                "rows are not ascending at {}",
                r.address
            );
            prev = Some(r.address);
            ensure!(
                is_hex_bytes(&r.bytes),
                "row {} has bytes {:?}",
                r.address,
                r.bytes
            );
            ensure!(!r.mnemonic.is_empty(), "row {} has no mnemonic", r.address);
        }
        // a linear scan from the entry begins with the same rows
        let req = DisasmRequest {
            start: Hex64(entry),
            scope: DisasmScope::Linear,
        };
        let page = call!(
            "disassemble linear",
            dis.disassemble(
                &req,
                &PageRequest {
                    cursor: None,
                    limit: Some(4)
                },
                &cancel
            )
        );
        let n = page.items.len().min(big.len());
        ensure!(
            n > 0 && page.items[..n] == big[..n],
            "linear disassembly differs from the function's at {entry:#x}"
        );
    }
    let req = DisasmRequest {
        start: Hex64(sample[0]),
        scope: DisasmScope::Function,
    };
    expect_code(
        "disassemble with a malformed cursor",
        dis.disassemble(
            &req,
            &PageRequest {
                cursor: Some("not-a-cursor".into()),
                limit: None,
            },
            &cancel,
        )
        .await,
        ErrorCode::InvalidArgument,
    )?;
    let unmapped = DisasmRequest {
        start: Hex64(UNMAPPED),
        scope: DisasmScope::Function,
    };
    expect_code(
        "disassemble an unmapped function",
        dis.disassemble(&unmapped, &PageRequest::default(), &cancel)
            .await,
        ErrorCode::NotFound,
    )
}

async fn all_xrefs(engine: &dyn Engine, req: XrefRequest, limit: u32) -> Result<Vec<Xref>, String> {
    let Some(x) = engine.xref_provider() else {
        return Ok(Vec::new());
    };
    let cancel = CancellationToken::new();
    collect("xrefs", limit, |page| {
        let (cancel, req) = (&cancel, &req);
        async move { x.xrefs(req, &page, cancel).await }
    })
    .await
}

async fn check_xrefs(engine: &dyn Engine, sample: &[u64]) -> Check {
    let Some(provider) = engine.xref_provider() else {
        return Ok(());
    };
    let cancel = CancellationToken::new();
    let from_req = |entry: u64, kind: Option<XrefKind>| XrefRequest {
        address: Hex64(entry),
        direction: XrefDirection::From,
        kind,
        whole_function: true,
    };
    let mut checked_to = false;
    for &entry in sample {
        let small = all_xrefs(engine, from_req(entry, None), 2).await?;
        let big = all_xrefs(engine, from_req(entry, None), 500).await?;
        paged_equal("xrefs from a function", &small, &big)?;
        for x in &big {
            ensure!(
                x.from_function
                    .as_ref()
                    .is_none_or(|f| f.address.0 == entry),
                "reference {} -> {} is attributed to another function",
                x.from,
                x.to
            );
        }
        for kind in [XrefKind::Call, XrefKind::Data] {
            let filtered = all_xrefs(engine, from_req(entry, Some(kind)), 500).await?;
            ensure!(
                filtered.iter().all(|x| x.kind == kind),
                "the {kind:?} filter let other kinds through"
            );
            let expected = big.iter().filter(|x| x.kind == kind).count();
            ensure!(
                filtered.len() == expected,
                "the {kind:?} filter found {} of {expected} references",
                filtered.len()
            );
        }
        if !checked_to
            && let Some(call) = big
                .iter()
                .find(|x| x.kind == XrefKind::Call && x.to_function.is_some())
        {
            let to = XrefRequest {
                address: call.to,
                direction: XrefDirection::To,
                kind: Some(XrefKind::Call),
                whole_function: false,
            };
            let callers = all_xrefs(engine, to, 500).await?;
            ensure!(
                callers.iter().any(|x| x.from == call.from),
                "the call at {} is missing from the callee's incoming references",
                call.from
            );
            checked_to = true;
        }
    }
    let bad = XrefRequest {
        address: Hex64(sample[0]),
        direction: XrefDirection::To,
        kind: None,
        whole_function: false,
    };
    expect_code(
        "xrefs with a malformed cursor",
        provider
            .xrefs(
                &bad,
                &PageRequest {
                    cursor: Some("not-a-cursor".into()),
                    limit: None,
                },
                &cancel,
            )
            .await,
        ErrorCode::InvalidArgument,
    )
}

async fn check_cfg(engine: &dyn Engine, sample: &[u64]) -> Check {
    let Some(graph) = engine.flow_graph() else {
        return Ok(());
    };
    let cancel = CancellationToken::new();
    for &entry in sample {
        let cfg = call!("cfg", graph.cfg(&Locator::ram(entry), &cancel));
        ensure!(cfg.function.0 == entry, "cfg is for {}", cfg.function);
        ensure!(!cfg.blocks.is_empty(), "cfg of {entry:#x} has no blocks");
        let mut prev = None;
        let mut insns = 0u64;
        for b in &cfg.blocks {
            ensure!(b.end > b.start && b.instructions > 0, "bad block {b:?}");
            ensure!(
                prev.is_none_or(|p| b.start > p),
                "blocks are not ordered at {}",
                b.start
            );
            prev = Some(b.start);
            insns += u64::from(b.instructions);
        }
        ensure!(
            cfg.blocks.iter().any(|b| b.start.0 == entry),
            "no block starts at the entry {entry:#x}"
        );
        for e in &cfg.edges {
            ensure!(
                cfg.blocks.iter().any(|b| b.start == e.from)
                    && cfg.blocks.iter().any(|b| b.start == e.to),
                "edge {e:?} joins unknown blocks"
            );
        }
        if engine.disassembler().is_some() {
            let rows = function_rows(engine, entry, DisasmScope::Function, 500).await?;
            ensure!(
                insns == rows.len() as u64,
                "cfg counts {insns} instructions, the listing has {}",
                rows.len()
            );
        }
    }
    expect_code(
        "cfg of an unmapped address",
        graph.cfg(&Locator::ram(UNMAPPED), &cancel).await,
        ErrorCode::NotFound,
    )
}

async fn all_strings(
    engine: &dyn Engine,
    req: StringsRequest,
    limit: u32,
) -> Result<Vec<StringEntry>, String> {
    let Some(s) = engine.string_lister() else {
        return Ok(Vec::new());
    };
    let cancel = CancellationToken::new();
    collect("strings", limit, |page| {
        let (cancel, req) = (&cancel, &req);
        async move { s.strings(req, &page, cancel).await }
    })
    .await
}

async fn check_strings(engine: &dyn Engine) -> Check {
    let Some(lister) = engine.string_lister() else {
        return Ok(());
    };
    let req = StringsRequest {
        min_len: 4,
        filter: None,
    };
    let small = all_strings(engine, req.clone(), 7).await?;
    let big = all_strings(engine, req, 500).await?;
    paged_equal("strings", &small, &big)?;
    let mut prev = None;
    for s in &big {
        ensure!(
            prev.is_none_or(|p| s.address > p),
            "strings are not ascending at {}",
            s.address
        );
        prev = Some(s.address);
        ensure!(
            s.value.chars().count() >= 4,
            "string {:?} is shorter than min_len",
            s.value
        );
        ensure!(s.length > 0, "string at {} has length 0", s.address);
    }
    if let Some(sample) = big.get(big.len() / 2) {
        let needle: String = sample.value.chars().take(3).collect();
        let hits = all_strings(
            engine,
            StringsRequest {
                min_len: 4,
                filter: Some(needle.to_uppercase()),
            },
            500,
        )
        .await?;
        ensure!(
            hits.iter().any(|h| h.address == sample.address),
            "filter {needle:?} lost the string at {}",
            sample.address
        );
        ensure!(
            hits.iter()
                .all(|h| h.value.to_lowercase().contains(&needle.to_lowercase())),
            "filter {needle:?} let non-matching strings through"
        );
    }
    expect_code(
        "strings with a malformed cursor",
        lister
            .strings(
                &StringsRequest::default(),
                &PageRequest {
                    cursor: Some("not-a-cursor".into()),
                    limit: None,
                },
                &CancellationToken::new(),
            )
            .await,
        ErrorCode::InvalidArgument,
    )
}

async fn check_symbols(engine: &dyn Engine) -> Check {
    let Some(lister) = engine.symbol_lister() else {
        return Ok(());
    };
    let cancel = CancellationToken::new();
    let imports_small: Vec<SymbolEntry> = collect("imports", 3, |page| {
        let cancel = &cancel;
        async move { lister.imports(&page, cancel).await }
    })
    .await?;
    let imports_big: Vec<SymbolEntry> = collect("imports", 500, |page| {
        let cancel = &cancel;
        async move { lister.imports(&page, cancel).await }
    })
    .await?;
    paged_equal("imports", &imports_small, &imports_big)?;
    let exports_small: Vec<SymbolEntry> = collect("exports", 2, |page| {
        let cancel = &cancel;
        async move { lister.exports(&page, cancel).await }
    })
    .await?;
    let exports_big: Vec<SymbolEntry> = collect("exports", 500, |page| {
        let cancel = &cancel;
        async move { lister.exports(&page, cancel).await }
    })
    .await?;
    paged_equal("exports", &exports_small, &exports_big)?;
    ensure!(
        exports_big.iter().all(|e| e.address.is_some()),
        "an export has no address"
    );
    ensure!(
        imports_big.iter().all(|e| !e.name.is_empty()),
        "an import has no name"
    );
    expect_code(
        "imports with a malformed cursor",
        lister
            .imports(
                &PageRequest {
                    cursor: Some("not-a-cursor".into()),
                    limit: None,
                },
                &cancel,
            )
            .await,
        ErrorCode::InvalidArgument,
    )
}
