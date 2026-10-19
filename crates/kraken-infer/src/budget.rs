use crate::error::{InferError, Result};

pub const GIB: u64 = 1024 * 1024 * 1024;
const RAM_WARN_FRACTION: f64 = 0.85;
const VRAM_WARN_FRACTION: f64 = 0.90;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub name: String,
    pub ram: u64,
    pub vram: u64,
}

impl Reservation {
    pub fn new(name: impl Into<String>, ram: u64, vram: u64) -> Self {
        Self {
            name: name.into(),
            ram,
            vram,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Approve,
    Warn(Vec<String>),
    Deny(Vec<String>),
}

impl Verdict {
    pub fn is_denied(&self) -> bool {
        matches!(self, Verdict::Deny(_))
    }
}

/// Machine memory (bytes) plus reservations already made; new requests are checked against it.
#[derive(Debug, Clone)]
pub struct MemoryBudget {
    total_ram: u64,
    total_vram: Option<u64>,
    reservations: Vec<Reservation>,
}

impl MemoryBudget {
    pub fn new(total_ram: u64, total_vram: Option<u64>) -> Self {
        Self {
            total_ram,
            total_vram,
            reservations: Vec::new(),
        }
    }

    /// Reads total RAM from `/proc/meminfo` on Linux, `sysctl` on macOS and
    /// `GlobalMemoryStatusEx` on Windows. VRAM is not probed; set it with [`MemoryBudget::with_vram`].
    pub fn from_system() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let text = std::fs::read_to_string("/proc/meminfo")?;
            let total = parse_meminfo_total(&text)
                .ok_or_else(|| InferError::Unsupported("no MemTotal in /proc/meminfo".into()))?;
            Ok(Self::new(total, None))
        }
        #[cfg(not(target_os = "linux"))]
        {
            kraken_procguard::total_memory_bytes()
                .map(|total| Self::new(total, None))
                .ok_or_else(|| InferError::Unsupported("cannot read total system memory".into()))
        }
    }

    pub fn with_vram(mut self, vram: u64) -> Self {
        self.total_vram = Some(vram);
        self
    }

    pub fn reserve(&mut self, r: Reservation) {
        self.reservations.push(r);
    }

    pub fn with_reservation(mut self, r: Reservation) -> Self {
        self.reserve(r);
        self
    }

    pub fn total_ram(&self) -> u64 {
        self.total_ram
    }

    pub fn total_vram(&self) -> Option<u64> {
        self.total_vram
    }

    pub fn committed_ram(&self) -> u64 {
        self.reservations.iter().map(|r| r.ram).sum()
    }

    pub fn committed_vram(&self) -> u64 {
        self.reservations.iter().map(|r| r.vram).sum()
    }

    /// Approves, warns or denies adding `req` on top of the existing reservations.
    pub fn check(&self, req: &Reservation) -> Verdict {
        let mut warn = Vec::new();
        let mut deny = Vec::new();

        let ram_after = self.committed_ram().saturating_add(req.ram);
        if ram_after > self.total_ram {
            deny.push(format!(
                "{}: needs {} of RAM but only {} remain of {}",
                req.name,
                fmt_bytes(req.ram),
                fmt_bytes(self.total_ram.saturating_sub(self.committed_ram())),
                fmt_bytes(self.total_ram)
            ));
        } else if ram_after as f64 > self.total_ram as f64 * RAM_WARN_FRACTION {
            warn.push(format!(
                "{}: RAM would be {} committed of {} (over {:.0}%)",
                req.name,
                fmt_bytes(ram_after),
                fmt_bytes(self.total_ram),
                RAM_WARN_FRACTION * 100.0
            ));
        }

        if req.vram > 0 {
            match self.total_vram {
                None => warn.push(format!(
                    "{}: needs {} of VRAM but total VRAM is unknown",
                    req.name,
                    fmt_bytes(req.vram)
                )),
                Some(total) => {
                    let after = self.committed_vram().saturating_add(req.vram);
                    if after > total {
                        deny.push(format!(
                            "{}: needs {} of VRAM but only {} remain of {}",
                            req.name,
                            fmt_bytes(req.vram),
                            fmt_bytes(total.saturating_sub(self.committed_vram())),
                            fmt_bytes(total)
                        ));
                    } else if after as f64 > total as f64 * VRAM_WARN_FRACTION {
                        warn.push(format!(
                            "{}: VRAM would be {} committed of {}",
                            req.name,
                            fmt_bytes(after),
                            fmt_bytes(total)
                        ));
                    }
                }
            }
        }

        if !deny.is_empty() {
            Verdict::Deny(deny)
        } else if !warn.is_empty() {
            Verdict::Warn(warn)
        } else {
            Verdict::Approve
        }
    }

    /// Checks `req`; denial becomes an error, warnings are returned for the caller to surface.
    pub fn enforce(&self, req: &Reservation) -> Result<Vec<String>> {
        match self.check(req) {
            Verdict::Approve => Ok(Vec::new()),
            Verdict::Warn(w) => Ok(w),
            Verdict::Deny(d) => Err(InferError::Overcommit(d.join("; "))),
        }
    }
}

/// Memory left in one place (a card, or the computer's RAM for a processor-only run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPool {
    /// Free right now, read again at each start.
    pub free: u64,
    /// Already promised to models that are still loading.
    pub reserved: u64,
}

impl MemoryPool {
    fn available(&self) -> u64 {
        self.free.saturating_sub(self.reserved)
    }
}

/// Whether a model fits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    /// Fits with room to spare.
    Fits,
    /// Fits, but with little room left.
    Tight,
    /// Does not fit.
    NoFit,
}

/// Rough cost of one token of context (the KV cache) in bytes.
const KV_BYTES_PER_TOKEN: u64 = 128 * 1024;
/// Engine buffers on top of weights and context.
const ENGINE_OVERHEAD: u64 = 512 * 1024 * 1024;
const MIN_MARGIN: u64 = 512 * 1024 * 1024;

/// Whether a model of `model_bytes` with `context_size` tokens of context fits the `pools` it
/// would use (one per selected card, or the RAM pool alone for a processor-only run).
///
/// `CopyPerCard` needs the model in every pool; other modes spread it, so the pools add up.
/// `Fits` leaves a margin of a tenth of the need (at least 512 MiB); less is `Tight`.
pub fn fit(
    model_bytes: u64,
    context_size: u32,
    pools: &[MemoryPool],
    mode: kraken_proto::infer::MultiGpuMode,
) -> Fit {
    use kraken_proto::infer::MultiGpuMode;
    if pools.is_empty() {
        return Fit::NoFit;
    }
    let need = model_bytes
        .saturating_add(u64::from(context_size) * KV_BYTES_PER_TOKEN)
        .saturating_add(ENGINE_OVERHEAD);
    let margin = (need / 10).max(MIN_MARGIN);
    let have = match mode {
        MultiGpuMode::CopyPerCard => pools.iter().map(MemoryPool::available).min().unwrap_or(0),
        _ => pools.iter().map(MemoryPool::available).sum(),
    };
    if have >= need.saturating_add(margin) {
        Fit::Fits
    } else if have >= need {
        Fit::Tight
    } else {
        Fit::NoFit
    }
}

fn fmt_bytes(b: u64) -> String {
    format!("{:.1} GiB", b as f64 / GIB as f64)
}

/// Extracts `MemTotal` (reported in kB) as bytes.
pub fn parse_meminfo_total(text: &str) -> Option<u64> {
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(free_gib: u64, reserved_gib: u64) -> MemoryPool {
        MemoryPool {
            free: free_gib * GIB,
            reserved: reserved_gib * GIB,
        }
    }

    #[test]
    fn fit_has_three_answers() {
        use kraken_proto::infer::MultiGpuMode::Split;
        // 8 GiB model, 4096 context: need 8 + 0.5 + 0.5 = 9 GiB, margin 0.9 GiB.
        assert_eq!(fit(8 * GIB, 4096, &[pool(24, 0)], Split), Fit::Fits);
        assert_eq!(fit(8 * GIB, 4096, &[pool(9, 0)], Split), Fit::Tight);
        assert_eq!(fit(8 * GIB, 4096, &[pool(8, 0)], Split), Fit::NoFit);
        assert_eq!(fit(8 * GIB, 4096, &[], Split), Fit::NoFit);
    }

    #[test]
    fn loading_models_reserve_their_share() {
        use kraken_proto::infer::MultiGpuMode::Split;
        assert_eq!(fit(8 * GIB, 4096, &[pool(24, 20)], Split), Fit::NoFit);
        assert_eq!(
            fit(8 * GIB, 4096, &[pool(12, 0), pool(12, 12)], Split),
            Fit::Fits
        );
    }

    #[test]
    fn split_adds_cards_but_copies_need_each() {
        use kraken_proto::infer::MultiGpuMode::{CopyPerCard, Split};
        let two = [pool(6, 0), pool(6, 0)];
        assert_eq!(fit(8 * GIB, 2048, &two, Split), Fit::Fits);
        assert_eq!(fit(8 * GIB, 2048, &two, CopyPerCard), Fit::NoFit);
    }

    #[test]
    fn context_counts() {
        use kraken_proto::infer::MultiGpuMode::Split;
        // 32768 tokens of context cost 4 GiB.
        assert_eq!(fit(8 * GIB, 32768, &[pool(12, 0)], Split), Fit::NoFit);
        assert_eq!(fit(8 * GIB, 32768, &[pool(16, 0)], Split), Fit::Fits);
    }

    #[test]
    fn meminfo_parse() {
        let t = "MemTotal:       32768000 kB\nMemFree: 1 kB\n";
        assert_eq!(parse_meminfo_total(t), Some(32_768_000 * 1024));
        assert_eq!(parse_meminfo_total("nothing"), None);
    }

    #[test]
    fn approve_warn_deny_ram() {
        let b = MemoryBudget::new(64 * GIB, None).with_reservation(Reservation::new(
            "ghidra",
            8 * GIB,
            0,
        ));
        assert_eq!(
            b.check(&Reservation::new("m", 20 * GIB, 0)),
            Verdict::Approve
        );
        assert!(matches!(
            b.check(&Reservation::new("m", 50 * GIB, 0)),
            Verdict::Warn(_)
        ));
        assert!(b.check(&Reservation::new("m", 57 * GIB, 0)).is_denied());
        assert!(b.enforce(&Reservation::new("m", 57 * GIB, 0)).is_err());
    }

    #[test]
    fn vram_rules() {
        let b = MemoryBudget::new(64 * GIB, Some(8 * GIB));
        assert_eq!(
            b.check(&Reservation::new("m", GIB, 4 * GIB)),
            Verdict::Approve
        );
        assert!(matches!(
            b.check(&Reservation::new("m", GIB, 7600 * 1024 * 1024)),
            Verdict::Warn(_)
        ));
        assert!(b.check(&Reservation::new("m", GIB, 9 * GIB)).is_denied());
        let unknown = MemoryBudget::new(64 * GIB, None);
        assert!(matches!(
            unknown.check(&Reservation::new("m", GIB, GIB)),
            Verdict::Warn(_)
        ));
    }

    #[test]
    fn reservations_accumulate() {
        let mut b = MemoryBudget::new(16 * GIB, Some(4 * GIB));
        b.reserve(Reservation::new("a", 4 * GIB, GIB));
        b.reserve(Reservation::new("b", 2 * GIB, GIB));
        assert_eq!(b.committed_ram(), 6 * GIB);
        assert_eq!(b.committed_vram(), 2 * GIB);
    }
}
