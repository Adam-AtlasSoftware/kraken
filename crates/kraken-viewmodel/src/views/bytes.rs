//! A lazy page cache over `read_bytes`, so the hex view can show any address without loading
//! the whole program.
//!
//! Readers (the hex widget, painting on the UI thread) call [`ByteCache::read`] and
//! [`ByteCache::state`], which only look at what is cached and note which pages are missing.
//! [`ViewModel::service_bytes`](crate::ViewModel::service_bytes) then fetches the missing pages,
//! merging neighbours into one run and, when the memory map is known, asking only for the parts
//! of the run that are mapped (a read stops at the first gap in memory).

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

use kraken_proto::BytesRead;

/// Bytes per cached page.
pub const PAGE_SIZE: u64 = 4096;
/// Pages kept before the least recently used ones are dropped (2 MiB).
pub const MAX_PAGES: usize = 512;
/// Pages merged into one run (64 KiB, the command's limit).
pub const MAX_RUN_PAGES: u64 = 16;
/// Runs fetched at once.
pub const MAX_IN_FLIGHT: usize = 4;

/// What is known about one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteState {
    /// A real value.
    Ready,
    /// Memory without contents (like `.bss`); reads as zero.
    Uninitialized,
    /// Being fetched or about to be.
    Loading,
    /// Nothing is mapped here, or the read failed.
    Unmapped,
}

#[derive(Debug, Clone)]
enum Page {
    Loading,
    Ready {
        /// [`PAGE_SIZE`] bytes; only the `mapped` parts are meaningful.
        data: Vec<u8>,
        /// Absolute ranges inside the page that were read.
        mapped: Vec<Range<u64>>,
        /// Absolute ranges inside the page that are uninitialized.
        uninit: Vec<Range<u64>>,
        /// Fetched before the memory map was known, so gaps may have cut the read short.
        blind: bool,
    },
    Failed,
}

#[derive(Debug, Clone)]
struct Entry {
    page: Page,
    used: u64,
}

#[derive(Debug)]
struct Progress {
    remaining: usize,
    blind: bool,
    parts: Vec<(u64, Result<BytesRead, ()>)>,
}

#[derive(Debug, Default)]
struct Inner {
    pages: HashMap<u64, Entry>,
    wanted: BTreeSet<u64>,
    /// Mapped ranges of the program, sorted; empty while unknown.
    blocks: Vec<Range<u64>>,
    progress: HashMap<u64, Progress>,
    in_flight: usize,
    tick: u64,
    fetched_runs: u64,
}

/// Cached program bytes in 4 KiB pages.
#[derive(Debug, Default)]
pub struct ByteCache {
    inner: RefCell<Inner>,
}

/// A run of consecutive pages fetched together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRun {
    /// Index of the first page (`address / PAGE_SIZE`).
    pub first: u64,
    /// Number of pages.
    pub count: u64,
}

impl PageRun {
    /// Address of the first byte.
    pub fn start(&self) -> u64 {
        self.first * PAGE_SIZE
    }

    /// Bytes covered.
    pub fn length(&self) -> u64 {
        self.count * PAGE_SIZE
    }
}

fn page_of(addr: u64) -> u64 {
    addr / PAGE_SIZE
}

fn contains(ranges: &[Range<u64>], addr: u64) -> bool {
    ranges.iter().any(|r| r.contains(&addr))
}

fn clip(r: Range<u64>, to: &Range<u64>) -> Option<Range<u64>> {
    let (s, e) = (r.start.max(to.start), r.end.min(to.end));
    (s < e).then_some(s..e)
}

impl ByteCache {
    /// What is known about the byte at `addr`. A page that is not cached yet is noted as wanted.
    pub fn state(&self, addr: u64) -> ByteState {
        let mut g = self.inner.borrow_mut();
        let p = page_of(addr);
        g.tick += 1;
        let tick = g.tick;
        match g.pages.get_mut(&p) {
            Some(e) => {
                e.used = tick;
                match &e.page {
                    Page::Loading => ByteState::Loading,
                    Page::Failed => ByteState::Unmapped,
                    Page::Ready { mapped, uninit, .. } => {
                        if !contains(mapped, addr) {
                            ByteState::Unmapped
                        } else if contains(uninit, addr) {
                            ByteState::Uninitialized
                        } else {
                            ByteState::Ready
                        }
                    }
                }
            }
            None => {
                g.wanted.insert(p);
                ByteState::Loading
            }
        }
    }

    /// The byte at `addr` when it is cached and mapped (zero for uninitialized memory).
    pub fn byte(&self, addr: u64) -> Option<u8> {
        let g = self.inner.borrow();
        let p = page_of(addr);
        match &g.pages.get(&p)?.page {
            Page::Ready { data, mapped, .. } if contains(mapped, addr) => {
                data.get((addr - p * PAGE_SIZE) as usize).copied()
            }
            _ => None,
        }
    }

    /// Fills `buf` from `addr`; bytes that are not cached or mapped read as zero. Missing pages
    /// are noted as wanted. Returns `buf.len()`.
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> usize {
        for (i, slot) in buf.iter_mut().enumerate() {
            let a = addr.wrapping_add(i as u64);
            if i == 0 || a.is_multiple_of(PAGE_SIZE) {
                // Touch the page (and note it as wanted) once per page.
                let _ = self.state(a);
            }
            *slot = self.byte(a).unwrap_or(0);
        }
        buf.len()
    }

    /// Notes the pages covering `addr..addr + len` as wanted.
    pub fn want_range(&self, addr: u64, len: u64) {
        if len == 0 {
            return;
        }
        let last = addr.saturating_add(len - 1);
        let mut g = self.inner.borrow_mut();
        for p in page_of(addr)..=page_of(last) {
            if !g.pages.contains_key(&p) {
                g.wanted.insert(p);
            }
        }
    }

    /// True when every byte of `addr..addr + len` is cached (loaded, failed or unmapped).
    pub fn is_settled(&self, addr: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let g = self.inner.borrow();
        let last = addr.saturating_add(len - 1);
        (page_of(addr)..=page_of(last)).all(|p| {
            g.pages
                .get(&p)
                .is_some_and(|e| !matches!(e.page, Page::Loading))
        })
    }

    /// Pages currently cached.
    pub fn page_count(&self) -> usize {
        self.inner.borrow().pages.len()
    }

    /// Pages waiting to be fetched.
    pub fn wanted_count(&self) -> usize {
        self.inner.borrow().wanted.len()
    }

    /// Runs started so far.
    pub fn fetched_runs(&self) -> u64 {
        self.inner.borrow().fetched_runs
    }

    /// Forgets failed pages so they are fetched again when needed.
    pub fn retry_failed(&self) {
        self.inner
            .borrow_mut()
            .pages
            .retain(|_, e| !matches!(e.page, Page::Failed));
    }

    /// Tells the cache which address ranges are mapped. Pages fetched before this was known
    /// are dropped, because a gap may have cut their reads short.
    pub fn set_blocks(&self, mut blocks: Vec<Range<u64>>) {
        blocks.sort_by_key(|b| b.start);
        let mut g = self.inner.borrow_mut();
        g.blocks = blocks;
        g.pages
            .retain(|_, e| !matches!(e.page, Page::Ready { blind: true, .. }));
    }

    /// Takes the wanted pages as runs to fetch, each with the address ranges to read, marking
    /// the pages as loading. At most [`MAX_IN_FLIGHT`] runs are out at once. Runs that hold
    /// nothing mapped are settled right away.
    pub(crate) fn take_runs(&self) -> Vec<(PageRun, Vec<Range<u64>>)> {
        let mut g = self.inner.borrow_mut();
        let mut out = Vec::new();
        while g.in_flight < MAX_IN_FLIGHT {
            let Some(&first) = g.wanted.iter().next() else {
                break;
            };
            let mut count = 0;
            while count < MAX_RUN_PAGES && g.wanted.remove(&(first + count)) {
                count += 1;
            }
            let run = PageRun { first, count };
            let whole = run.start()..run.start() + run.length();
            let blind = g.blocks.is_empty();
            let segments: Vec<Range<u64>> = if blind {
                vec![whole]
            } else {
                g.blocks
                    .iter()
                    .filter_map(|b| clip(b.clone(), &whole))
                    .collect()
            };
            g.tick += 1;
            let tick = g.tick;
            if segments.is_empty() {
                for p in first..first + count {
                    g.pages.insert(
                        p,
                        Entry {
                            page: empty_page(blind),
                            used: tick,
                        },
                    );
                }
                continue;
            }
            for p in first..first + count {
                g.pages.insert(
                    p,
                    Entry {
                        page: Page::Loading,
                        used: 0,
                    },
                );
            }
            g.in_flight += 1;
            g.fetched_runs += 1;
            g.progress.insert(
                first,
                Progress {
                    remaining: segments.len(),
                    blind,
                    parts: Vec::new(),
                },
            );
            out.push((run, segments));
        }
        out
    }

    /// Stores the answer to one read of a run; the run's pages are filled in once all its reads
    /// have come back.
    pub(crate) fn finish_segment(&self, run: PageRun, start: u64, result: Result<BytesRead, ()>) {
        let mut g = self.inner.borrow_mut();
        let Some(pr) = g.progress.get_mut(&run.first) else {
            return;
        };
        pr.parts.push((start, result));
        pr.remaining = pr.remaining.saturating_sub(1);
        if pr.remaining > 0 {
            return;
        }
        let Some(pr) = g.progress.remove(&run.first) else {
            return;
        };
        g.in_flight = g.in_flight.saturating_sub(1);
        g.tick += 1;
        let tick = g.tick;
        let failed = pr.parts.iter().all(|(_, r)| r.is_err());
        for p in run.first..run.first + run.count {
            let page_start = p * PAGE_SIZE;
            let range = page_start..page_start + PAGE_SIZE;
            let page = if failed {
                Page::Failed
            } else {
                let mut data = vec![0u8; PAGE_SIZE as usize];
                let (mut mapped, mut uninit) = (Vec::new(), Vec::new());
                for (_, part) in &pr.parts {
                    let Ok(read) = part else { continue };
                    let span = read.start.0..read.start.0 + read.bytes.len() as u64;
                    if let Some(hit) = clip(span, &range) {
                        let src =
                            (hit.start - read.start.0) as usize..(hit.end - read.start.0) as usize;
                        let dst =
                            (hit.start - page_start) as usize..(hit.end - page_start) as usize;
                        data[dst].copy_from_slice(&read.bytes[src]);
                        mapped.push(hit.clone());
                        uninit.extend(
                            read.uninitialized
                                .iter()
                                .filter_map(|r| clip(r.start.0..r.end.0, &hit)),
                        );
                    }
                }
                Page::Ready {
                    data,
                    mapped,
                    uninit,
                    blind: pr.blind,
                }
            };
            g.pages.insert(p, Entry { page, used: tick });
        }
        if g.pages.len() > MAX_PAGES {
            let mut order: Vec<(u64, u64)> = g
                .pages
                .iter()
                .filter(|(_, e)| !matches!(e.page, Page::Loading))
                .map(|(p, e)| (e.used, *p))
                .collect();
            order.sort_unstable();
            let excess = g.pages.len() - MAX_PAGES;
            for (_, p) in order.into_iter().take(excess) {
                g.pages.remove(&p);
            }
        }
    }
}

fn empty_page(blind: bool) -> Page {
    Page::Ready {
        data: vec![0; PAGE_SIZE as usize],
        mapped: Vec::new(),
        uninit: Vec::new(),
        blind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::{AddressRange, Hex64};

    fn read(start: u64, bytes: Vec<u8>, uninit: &[(u64, u64)]) -> BytesRead {
        BytesRead {
            start: Hex64(start),
            bytes,
            uninitialized: uninit
                .iter()
                .map(|&(s, e)| AddressRange {
                    space: "ram".into(),
                    start: Hex64(s),
                    end: Hex64(e),
                })
                .collect(),
        }
    }

    fn finish_all(c: &ByteCache, runs: Vec<(PageRun, Vec<Range<u64>>)>) {
        for (run, segs) in runs {
            for s in segs {
                let len = (s.end - s.start) as usize;
                c.finish_segment(run, s.start, Ok(read(s.start, vec![7; len], &[])));
            }
        }
    }

    #[test]
    fn misses_are_noted_and_merged_into_runs() {
        let c = ByteCache::default();
        assert_eq!(c.state(0x1000), ByteState::Loading);
        let mut buf = [0u8; 16];
        c.read(0x2ff8, &mut buf); // straddles pages 2 and 3
        c.want_range(0x8000, 3);
        assert_eq!(c.wanted_count(), 4);
        let runs = c.take_runs();
        let shapes: Vec<PageRun> = runs.iter().map(|r| r.0).collect();
        assert_eq!(
            shapes,
            vec![
                PageRun { first: 1, count: 3 },
                PageRun { first: 8, count: 1 }
            ]
        );
        assert_eq!(shapes[0].start(), 0x1000);
        assert_eq!(shapes[0].length(), 3 * PAGE_SIZE);
        // Without a memory map the whole run is read in one piece.
        assert_eq!(runs[0].1, vec![0x1000..0x4000]);
        assert_eq!(c.state(0x1000), ByteState::Loading);
        assert_eq!(c.wanted_count(), 0);
    }

    #[test]
    fn reads_follow_the_memory_map_and_skip_gaps() {
        let c = ByteCache::default();
        c.set_blocks(vec![0x1800..0x1900, 0x1000..0x1100, 0x5000..0x6000]);
        c.want_range(0x1000, 2 * PAGE_SIZE);
        let runs = c.take_runs();
        assert_eq!(runs.len(), 1);
        // Two blocks inside the run; the gap between them is never requested.
        assert_eq!(runs[0].1, vec![0x1000..0x1100, 0x1800..0x1900]);
        let (run, segs) = &runs[0];
        c.finish_segment(
            *run,
            segs[1].start,
            Ok(read(0x1800, vec![2; 0x100], &[(0x1880, 0x1900)])),
        );
        assert_eq!(c.state(0x1000), ByteState::Loading, "waits for every read");
        c.finish_segment(*run, segs[0].start, Ok(read(0x1000, vec![1; 0x100], &[])));
        assert_eq!(c.state(0x1000), ByteState::Ready);
        assert_eq!(c.byte(0x10ff), Some(1));
        assert_eq!(c.state(0x1100), ByteState::Unmapped);
        assert_eq!(c.byte(0x1100), None);
        assert_eq!(c.state(0x1800), ByteState::Ready);
        assert_eq!(c.state(0x1880), ByteState::Uninitialized);
        assert_eq!(c.state(0x1900), ByteState::Unmapped);
        // A page with nothing mapped is settled without any request.
        c.want_range(0x3000, 1);
        assert!(c.take_runs().is_empty());
        assert_eq!(c.state(0x3000), ByteState::Unmapped);
        assert!(c.is_settled(0x1000, 2 * PAGE_SIZE));
        let mut buf = [9u8; 4];
        c.read(0x10fe, &mut buf);
        assert_eq!(buf, [1, 1, 0, 0]);
    }

    #[test]
    fn pages_fetched_before_the_map_arrived_are_dropped_when_it_does() {
        let c = ByteCache::default();
        c.want_range(0x1000, 1);
        let runs = c.take_runs();
        c.finish_segment(runs[0].0, 0x1000, Ok(read(0x1000, vec![5; 0x17], &[])));
        assert_eq!(c.state(0x1000), ByteState::Ready);
        assert_eq!(
            c.state(0x1100),
            ByteState::Unmapped,
            "the read stopped at a gap"
        );
        c.set_blocks(vec![0x1000..0x1017, 0x1100..0x1200]);
        assert_eq!(c.page_count(), 0);
        assert_eq!(c.state(0x1100), ByteState::Loading);
    }

    #[test]
    fn failures_mark_pages_unmapped_until_retried() {
        let c = ByteCache::default();
        c.want_range(0x4000, 1);
        let runs = c.take_runs();
        c.finish_segment(runs[0].0, 0x4000, Err(()));
        assert_eq!(c.state(0x4000), ByteState::Unmapped);
        assert_eq!(c.wanted_count(), 0);
        c.retry_failed();
        assert_eq!(c.state(0x4000), ByteState::Loading);
        assert_eq!(c.wanted_count(), 1);
    }

    #[test]
    fn in_flight_runs_are_capped_and_old_pages_dropped() {
        let c = ByteCache::default();
        for i in 0..10 {
            c.want_range(i * 0x20_000, 1);
        }
        let runs = c.take_runs();
        assert_eq!(runs.len(), MAX_IN_FLIGHT);
        assert!(c.take_runs().is_empty());
        finish_all(&c, runs);
        assert_eq!(c.take_runs().len(), MAX_IN_FLIGHT);

        let c = ByteCache::default();
        let n = MAX_PAGES as u64 + 20;
        for p in 0..n {
            c.want_range(p * PAGE_SIZE, 1);
        }
        let mut guard = 0;
        while c.wanted_count() > 0 || guard == 0 {
            guard += 1;
            finish_all(&c, c.take_runs());
            assert!(guard < 100);
        }
        assert!(c.page_count() <= MAX_PAGES);
    }
}
