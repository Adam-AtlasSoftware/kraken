//! The built-in demo project: the fake engine serving the tiny fixture plus a few more functions.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile, FixtureFunction};
use kraken_engine::SharedEngine;
use kraken_proto::{Completeness, DecompileResult, FunctionSummary, Locator, ProtoError};
use kraken_registry::EngineFactory;

use crate::inprocess::InProcessBackend;
use crate::tokens::tokenize;

const TINY: &str = include_str!("../../engine-fake/fixtures/tiny.json");

/// Time the fake engine spends per analysis step, so progress is visible in the demo.
pub const DEMO_STAGE_DELAY: Duration = Duration::from_millis(140);

const MAIN: &str = "int main(int argc, char **argv)
{
  Config cfg;
  int status;

  // parse the command line and load settings
  if (parse_args(argc, argv, &cfg) != 0) {
    log_error(\"usage: demo <file>\", argc);
    return 2;
  }
  init_session(&cfg);
  helper(argc);
  status = process_packet(cfg.buffer, cfg.length);
  if (status != 0) {
    log_error(\"packet rejected\", status);
  }
  cleanup();
  return status;
}
";

const EXTRA: &[(u64, &str, &str)] = &[
    (
        0x4010c0,
        "parse_args",
        "int parse_args(int argc, char **argv, Config *cfg)
{
  int i;

  cfg->length = 0;
  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '-') {
      return read_config(argv[i], cfg);
    }
  }
  return argc < 2;
}
",
    ),
    (
        0x401120,
        "init_session",
        "void init_session(Config *cfg)
{
  cfg->buffer = FUN_00401300(cfg->length);
  cfg->flags = 0x4b524b4e;
}
",
    ),
    (
        0x4011a0,
        "process_packet",
        "int process_packet(uint8_t *buf, size_t len)
{
  uint32_t sum;

  if (buf == NULL || len < 12) {
    log_error(\"short packet\", len);
    return -1;
  }
  sum = checksum(buf, len);
  if (sum != *(uint32_t *)buf) {
    log_error(\"bad checksum\", sum);
    return -3;
  }
  return handle_hello(buf + 12, len - 12);
}
",
    ),
    (
        0x401240,
        "checksum",
        "uint32_t checksum(uint8_t *buf, size_t len)
{
  uint32_t sum;
  size_t i;

  sum = 0;
  for (i = 0; i < len; i++) {
    sum = (sum << 5) + sum + buf[i];
  }
  return sum;
}
",
    ),
    (
        0x4012a0,
        "log_error",
        "void log_error(char *msg, int code)
{
  fprintf(stderr, \"error %d: %s\\n\", code, msg);
}
",
    ),
    (
        0x401300,
        "FUN_00401300",
        "undefined8 FUN_00401300(int param_1)
{
  undefined8 pvVar1;

  pvVar1 = malloc(param_1 + 16);
  if (pvVar1 == NULL) {
    FUN_00401340(1);
  }
  return pvVar1;
}
",
    ),
    (
        0x401340,
        "FUN_00401340",
        "void FUN_00401340(int param_1)
{
  log_error(\"out of memory\", param_1);
  exit(param_1);
}
",
    ),
    (
        0x401380,
        "handle_hello",
        "int handle_hello(uint8_t *payload, size_t len)
{
  if (len < 4) {
    return -4;
  }
  return FUN_00401440(payload, len) == 0x6f6c6c65;
}
",
    ),
    (
        0x4013e0,
        "read_config",
        "int read_config(char *path, Config *cfg)
{
  FILE *fp;

  fp = fopen(path, \"rb\");
  if (fp == NULL) {
    log_error(\"cannot open config\", 0);
    return -1;
  }
  cfg->length = fread(cfg->buffer, 1, 4096, fp);
  fclose(fp);
  return 0;
}
",
    ),
    (
        0x401440,
        "FUN_00401440",
        "uint32_t FUN_00401440(uint8_t *param_1, size_t param_2)
{
  return *(uint32_t *)param_1 ^ param_2;
}
",
    ),
];

fn function(addr: u64, name: &str, text: &str, targets: &HashMap<String, u64>) -> FixtureFunction {
    let locator = Locator::ram(addr);
    let signature = text.lines().next().unwrap_or("").trim().to_string();
    let lines = text.lines().count() as u64;
    FixtureFunction::new(
        FunctionSummary {
            locator: locator.clone(),
            name: name.to_string(),
            size: Some(lines * 12),
            signature: Some(signature),
            fn_hash: Some(format!("h-{name}")),
            completeness: Completeness::Complete,
            mangled: None,
        },
        DecompileResult {
            function: locator,
            language: "c".into(),
            text: text.to_string(),
            tokens: tokenize(text, targets),
            warnings: Vec::new(),
            completeness: Completeness::Complete,
        },
    )
}

/// The tiny fixture with `main` rewritten and nine more functions added.
pub fn demo_fixture() -> FixtureFile {
    let mut fx = FixtureFile::from_json(TINY).expect("the tiny fixture is valid");
    let mut targets: HashMap<String, u64> = HashMap::new();
    for f in &fx.functions {
        if let Locator::Native { offset, .. } = &f.summary.locator {
            targets.insert(f.summary.name.clone(), offset.0);
        }
    }
    for (addr, name, _) in EXTRA {
        targets.insert((*name).to_string(), *addr);
    }
    for f in &mut fx.functions {
        if f.summary.name == "main"
            && let Locator::Native { offset, .. } = &f.summary.locator
        {
            *f = function(offset.0, "main", MAIN, &targets);
        }
    }
    for (addr, name, text) in EXTRA {
        fx.functions.push(function(*addr, name, text, &targets));
    }
    fx.program.size = 24_576;
    fx
}

/// Builds fake engines from a fixture.
pub struct DemoEngineFactory {
    fixture: FixtureFile,
    stage_delay: Duration,
    /// Make the open take this long, counting to this many functions.
    slow_open: Option<(Duration, u64)>,
}

impl DemoEngineFactory {
    /// A factory serving `fixture`, taking `stage_delay` per analysis step.
    pub fn new(fixture: FixtureFile, stage_delay: Duration) -> Self {
        DemoEngineFactory {
            fixture,
            stage_delay,
            slow_open: None,
        }
    }
}

#[async_trait]
impl EngineFactory for DemoEngineFactory {
    async fn create(&self, _engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        let mut engine = FakeEngine::new(self.fixture.clone()).with_stage_delay(self.stage_delay);
        if let Some((delay, functions)) = self.slow_open {
            engine = engine.with_open_delay(delay).with_open_functions(functions);
        }
        Ok(Arc::new(engine))
    }
}

/// The demo with an open that takes `delay` and counts to `functions` while it finds them:
/// the loading screen of a big program, for screenshots and tests.
pub fn demo_project_loading(delay: Duration, functions: u64) -> std::io::Result<DemoProject> {
    let tmp = tempfile::tempdir()?;
    let binary = tmp.path().join("libpython3.14.so");
    std::fs::write(&binary, b"\x7fELF placeholder for the KRAKEN demo project")?;
    let project_dir = tmp.path().join("project");
    let factory = DemoEngineFactory {
        slow_open: Some((delay, functions)),
        ..DemoEngineFactory::new(demo_fixture(), DEMO_STAGE_DELAY)
    };
    let session = kraken_registry::Session::new(Arc::new(factory));
    let backend = InProcessBackend::with_session(session).with_keepalive(Box::new(tmp));
    Ok(DemoProject {
        backend: Arc::new(backend),
        binary,
        project_dir,
    })
}

/// Everything needed to open the demo project through a [`ViewModel`](crate::ViewModel).
pub struct DemoProject {
    /// Backend over the fake engine; owns the temporary directory.
    pub backend: Arc<InProcessBackend>,
    /// Fake binary to pass to `project_create`.
    pub binary: PathBuf,
    /// Empty directory to pass to `project_create`.
    pub project_dir: PathBuf,
}

/// Sets up the demo: a temp directory with a placeholder binary and a backend whose engine serves
/// [`demo_fixture`].
pub fn demo_project() -> std::io::Result<DemoProject> {
    demo_project_with(demo_fixture(), DEMO_STAGE_DELAY)
}

/// Like [`demo_project`] with a chosen fixture and step delay.
pub fn demo_project_with(
    fixture: FixtureFile,
    stage_delay: Duration,
) -> std::io::Result<DemoProject> {
    let tmp = tempfile::tempdir()?;
    let binary = tmp.path().join("demo-server");
    // `KRAKEN_DEMO_BINARY` swaps the placeholder for a real program, so the Debug tab can run it.
    match std::env::var_os("KRAKEN_DEMO_BINARY").filter(|p| std::path::Path::new(p).is_file()) {
        Some(real) => {
            std::fs::copy(real, &binary)?;
        }
        None => std::fs::write(&binary, b"\x7fELF placeholder for the KRAKEN demo project")?,
    }
    let project_dir = tmp.path().join("project");
    // The Rewrite tab runs against a scripted pipeline; nothing is translated or run.
    let rewrite = crate::rewrite::demo::DemoRewrite::new();
    let session =
        kraken_registry::Session::new(Arc::new(DemoEngineFactory::new(fixture, stage_delay)))
            .with_rewrite(Arc::new(rewrite.clone()));
    let backend = InProcessBackend::with_session(session).with_keepalive(Box::new(tmp));
    Ok(DemoProject {
        backend: Arc::new(backend),
        binary,
        project_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_fixture_is_valid_and_larger_than_tiny() {
        let fx = demo_fixture();
        assert!(fx.functions.len() >= 10);
        for f in &fx.functions {
            f.decompile.validate_tokens().expect("tokens valid");
            assert_eq!(f.decompile.function, f.summary.locator);
        }
        let main = fx
            .functions
            .iter()
            .find(|f| f.summary.name == "main")
            .expect("main exists");
        assert!(main.decompile.text.contains("process_packet"));
        // The call to helper keeps pointing at the tiny fixture's helper.
        assert!(main.decompile.tokens.iter().any(|t| {
            t.symbol.as_deref() == Some("helper") && t.target == Some(Locator::ram(0x401040))
        }));
    }
}
