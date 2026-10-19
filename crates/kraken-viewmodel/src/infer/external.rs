//! Watches the server the person runs for the assistant (Ollama, vLLM, a LAN machine): a light
//! look at its model list every 30 seconds, off the window's thread, and the speed of the
//! replies the assistant has had from it. It cannot be started or stopped from here.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kraken_agent::ProviderConfig;
use tokio::runtime::Handle;

use super::chips::ExternalServer;
use crate::assist::{ProviderStore, external_server};

/// How often the server is looked at.
pub const LOOK_EVERY: Duration = Duration::from_secs(30);

/// The id the assistant's OpenAI-compatible provider reports its replies under.
const PROVIDER_ID: &str = "openai-compatible";

type Repaint = Arc<dyn Fn() + Send + Sync>;

struct Target {
    cfg: ProviderConfig,
    name: String,
    url: String,
}

/// The watch.
pub struct ExternalWatch {
    rt: Handle,
    config_path: Option<PathBuf>,
    repaint: Option<Repaint>,
    target: Option<Target>,
    loaded: bool,
    seen: Arc<Mutex<Option<bool>>>,
    in_flight: Arc<Mutex<bool>>,
    next: Instant,
}

impl ExternalWatch {
    /// A watch over the assistant's server named in the configuration file at `config_path`.
    pub fn new(rt: Handle, config_path: Option<PathBuf>) -> Self {
        ExternalWatch {
            rt,
            config_path,
            repaint: None,
            target: None,
            loaded: false,
            seen: Arc::default(),
            in_flight: Arc::default(),
            next: Instant::now(),
        }
    }

    /// Wakes the window when an answer came.
    pub fn with_repaint(mut self, f: Repaint) -> Self {
        self.repaint = Some(f);
        self
    }

    /// Reads the configuration again (after the assistant's settings changed).
    pub fn reload(&mut self) {
        self.loaded = false;
    }

    /// The server to show a chip for, if the assistant or rewriting uses one.
    pub fn server(&self) -> Option<ExternalServer> {
        let t = self.target.as_ref()?;
        Some(ExternalServer {
            name: t.name.clone(),
            url: t.url.clone(),
            reachable: *self.seen.lock().unwrap_or_else(PoisonError::into_inner),
            tok_s: kraken_assist::measured_tok_s(PROVIDER_ID),
        })
    }

    fn load(&mut self) {
        self.loaded = true;
        let path = self.config_path.as_deref();
        let assistant = kraken_assist::load_provider_config(path).ok();
        let rewrite = kraken_assist::load_rewrite_config(path).ok().flatten();
        let found = assistant
            .into_iter()
            .chain(rewrite)
            .find_map(|cfg| external_server(&cfg).map(|(name, url)| Target { cfg, name, url }));
        if found.as_ref().map(|t| &t.url) != self.target.as_ref().map(|t| &t.url) {
            *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = None;
            self.next = Instant::now();
        }
        self.target = found;
    }

    /// Looks now if it is time. Call each frame; returns when to call again.
    pub fn poll(&mut self, now: Instant) -> Duration {
        if !self.loaded {
            self.load();
        }
        let Some(t) = &self.target else {
            return LOOK_EVERY;
        };
        if now >= self.next {
            self.next = now + LOOK_EVERY;
            let mut busy = self
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !*busy {
                *busy = true;
                let (cfg, seen, flight, repaint) = (
                    t.cfg.clone(),
                    self.seen.clone(),
                    self.in_flight.clone(),
                    self.repaint.clone(),
                );
                let store = ProviderStore::new(self.config_path.clone());
                self.rt.spawn(async move {
                    let list = store.model_choices(&cfg).await;
                    *seen.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some(list.source == kraken_agent::ModelSource::Live);
                    *flight.lock().unwrap_or_else(PoisonError::into_inner) = false;
                    if let Some(f) = &repaint {
                        f();
                    }
                });
            }
        }
        self.next.saturating_duration_since(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &std::path::Path, text: &str) -> PathBuf {
        let p = dir.join("config.toml");
        std::fs::write(&p, text).unwrap();
        p
    }

    fn wait(w: &mut ExternalWatch, want: Option<bool>) {
        let end = Instant::now() + Duration::from_secs(15);
        loop {
            w.poll(Instant::now());
            if w.server().is_some_and(|s| s.reachable == want) {
                return;
            }
            assert!(Instant::now() < end, "no answer: {:?}", w.server());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn a_cloud_or_local_model_has_no_server_chip() {
        let dir = tempfile::tempdir().unwrap();
        let rt = rt();
        for text in [
            "[provider]\nkind = \"anthropic\"\nmodel = \"x\"\n",
            "[provider]\nkind = \"openai_compatible\"\nbase_url = \"https://api.openai.com/v1\"\nmodel = \"x\"\n",
            "[provider]\nkind = \"local\"\nmodel = \"qwen\"\n",
            "",
        ] {
            let mut w = ExternalWatch::new(rt.handle().clone(), Some(write(dir.path(), text)));
            w.poll(Instant::now());
            assert!(w.server().is_none(), "{text}");
        }
    }

    #[test]
    fn a_server_that_answers_is_reachable_and_one_that_does_not_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let rt = rt();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            while let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let body = r#"{"data":[{"id":"llama3"}]}"#;
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let cfg = |p: u16| {
            format!(
                "[provider]\nkind = \"openai_compatible\"\nbase_url = \"http://127.0.0.1:{p}/v1\"\nmodel = \"llama3\"\n"
            )
        };
        let mut w = ExternalWatch::new(rt.handle().clone(), Some(write(dir.path(), &cfg(port))));
        w.poll(Instant::now());
        assert_eq!(w.server().unwrap().reachable, None, "not looked yet");
        wait(&mut w, Some(true));

        // Nothing listens on port 1.
        write(dir.path(), &cfg(1));
        w.reload();
        w.poll(Instant::now());
        assert_eq!(
            w.server().unwrap().reachable,
            None,
            "a new address starts over"
        );
        wait(&mut w, Some(false));
    }
}
