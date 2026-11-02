//! Shared test doubles: a keychain and an approval transport that count how
//! often they are used, a TCP listener that counts connections, the
//! hostile-input corpus reader. Test-only.

use async_trait::async_trait;
use mcp_warden_core::approval::{ApprovalDecision, ApprovalRequest, ApprovalTransport};
use mcp_warden_core::error::Result;
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::keychain::memory::InMemoryKeychain;
use mcp_warden_core::secret::Secret;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// An in-memory keychain that counts reads.
#[derive(Default)]
pub struct CountingKeychain {
    inner: InMemoryKeychain,
    gets: AtomicUsize,
}

impl CountingKeychain {
    pub fn with(entries: &[(&str, &str)]) -> Arc<Self> {
        let kc = Self::default();
        for (name, value) in entries {
            kc.inner.set(name, Secret::new(value.to_string())).unwrap();
        }
        Arc::new(kc)
    }

    pub fn gets(&self) -> usize {
        self.gets.load(Ordering::SeqCst)
    }
}

impl KeychainStore for CountingKeychain {
    fn set(&self, name: &str, value: Secret) -> Result<()> {
        self.inner.set(name, value)
    }
    fn get(&self, name: &str) -> Result<Option<Secret>> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get(name)
    }
    fn delete(&self, name: &str) -> Result<()> {
        self.inner.delete(name)
    }
    fn list_names(&self) -> Result<Vec<String>> {
        self.inner.list_names()
    }
}

/// An approval transport that answers every prompt with one decision and
/// keeps what it was shown.
pub struct CountingApproval {
    decision: ApprovalDecision,
    pub shown: Mutex<Vec<ApprovalRequest>>,
}

impl CountingApproval {
    pub fn new(decision: ApprovalDecision) -> Arc<Self> {
        Arc::new(Self {
            decision,
            shown: Mutex::new(Vec::new()),
        })
    }

    pub fn calls(&self) -> usize {
        self.shown.lock().unwrap().len()
    }
}

#[async_trait]
impl ApprovalTransport for CountingApproval {
    async fn request(&self, req: ApprovalRequest) -> Result<ApprovalDecision> {
        self.shown.lock().unwrap().push(req);
        Ok(self.decision)
    }
}

/// A TCP listener on 127.0.0.1 that accepts and counts connections, so a
/// test can prove that nothing was sent to an "upstream".
pub struct CountingListener {
    pub port: u16,
    accepted: Arc<AtomicUsize>,
}

impl CountingListener {
    pub fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                count.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        Self { port, accepted }
    }

    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// A TCP listener on 127.0.0.1 that accepts connections and never answers
/// or closes them: an upstream that hangs.
pub struct SilentListener {
    pub port: u16,
}

impl SilentListener {
    pub fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                held.push(stream);
            }
        });
        Self { port }
    }
}

/// A minimal Redis server on 127.0.0.1: it reads RESP commands and answers
/// each with what `reply` returns for its arguments.
pub struct FakeRedis {
    pub port: u16,
}

impl FakeRedis {
    pub async fn start(reply: impl Fn(&[String]) -> Vec<u8> + Send + Sync + 'static) -> Self {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let reply = Arc::new(reply);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut stream = tokio::io::BufReader::new(stream);
                    while let Some(args) = read_resp_command(&mut stream).await {
                        if stream.get_mut().write_all(&reply(&args)).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Self { port }
    }
}

async fn read_resp_command(
    r: &mut tokio::io::BufReader<tokio::net::TcpStream>,
) -> Option<Vec<String>> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let mut line = String::new();
    if r.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let n: usize = line.trim().strip_prefix('*')?.parse().ok()?;
    let mut args = Vec::with_capacity(n);
    for _ in 0..n {
        line.clear();
        r.read_line(&mut line).await.ok()?;
        let len: usize = line.trim().strip_prefix('$')?.parse().ok()?;
        let mut buf = vec![0; len + 2];
        r.read_exact(&mut buf).await.ok()?;
        args.push(String::from_utf8_lossy(&buf[..len]).into_owned());
    }
    Some(args)
}

/// `tests/corpus/*.txt` entries as `(line, input, note)`. The format is
/// described at the top of each file.
pub fn corpus(text: &str) -> Vec<(usize, String, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(i, line)| {
            let (raw, note) = line
                .split_once("  # ")
                .unwrap_or_else(|| panic!("line {}: no `  # <note>`: {line:?}", i + 1));
            assert!(
                note.contains("(since v"),
                "line {}: the note must say `(since vX.Y.Z)`: {line:?}",
                i + 1
            );
            (i + 1, unescape(raw, i + 1), note.to_string())
        })
        .collect()
}

pub fn unescape(raw: &str, line: usize) -> String {
    let mut out = String::new();
    let mut chars = raw.chars();
    let bad = |what: &str| -> ! { panic!("line {line}: {what} in {raw:?}") };
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('x') => {
                let hex: String = chars.by_ref().take(2).collect();
                let byte = u8::from_str_radix(&hex, 16).unwrap_or_else(|_| bad("bad \\xNN"));
                out.push(char::from(byte));
            }
            Some('u') => {
                if chars.next() != Some('{') {
                    bad("\\u without {");
                }
                let hex: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let code = u32::from_str_radix(&hex, 16).unwrap_or_else(|_| bad("bad \\u{}"));
                out.push(char::from_u32(code).unwrap_or_else(|| bad("bad \\u{}")));
            }
            Some('{') => {
                let spec: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let (c, n) = spec.split_once('*').unwrap_or_else(|| bad("bad \\{c*N}"));
                let n: usize = n.parse().unwrap_or_else(|_| bad("bad \\{c*N}"));
                out.push_str(&c.repeat(n));
            }
            _ => bad("unknown escape"),
        }
    }
    out
}
