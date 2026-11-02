//! An in-process SSH server for tests: a fresh host key pinned in a
//! temporary known_hosts file, a fresh client key, and a chosen behaviour —
//! including hostile ones (endless output, hanging after authentication).

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::{self, LineEnding, PrivateKey};
use russh::server::{Auth, Config, Handler, Msg, Session};
use russh::{Channel, ChannelId};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub enum Behaviour {
    /// Answer `ran: <command>` on stdout and exit 0.
    Echo,
    /// Stream stdout and stderr without end.
    Flood,
    /// Accept the key, then never open the session channel.
    HangAfterAuth,
}

pub struct TestSshServer {
    pub port: u16,
    pub known_hosts: PathBuf,
    /// The client's private key, OpenSSH PEM — what the keychain holds.
    pub client_key: String,
    /// Commands the server was asked to run.
    pub commands: Arc<Mutex<Vec<String>>>,
    _dir: tempfile::TempDir,
}

fn fresh_key() -> PrivateKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
}

impl TestSshServer {
    pub async fn start(behaviour: Behaviour) -> Self {
        let host_key = fresh_key();
        let client = fresh_key();
        let config = Arc::new(Config {
            keys: vec![host_key.clone()],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: Some(Duration::from_secs(120)),
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let seen = commands.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handler = TestHandler {
                    behaviour,
                    commands: seen.clone(),
                };
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                        let _ = session.await;
                    }
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let known_hosts = dir.path().join("known_hosts");
        std::fs::write(
            &known_hosts,
            format!(
                "[127.0.0.1]:{port} {}\n",
                host_key.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        Self {
            port,
            known_hosts,
            client_key: client.to_openssh(LineEnding::LF).unwrap().to_string(),
            commands,
            _dir: dir,
        }
    }
}

struct TestHandler {
    behaviour: Behaviour,
    commands: Arc<Mutex<Vec<String>>>,
}

impl Handler for TestHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if let Behaviour::HangAfterAuth = self.behaviour {
            std::future::pending::<()>().await;
        }
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.commands.lock().unwrap().push(command.clone());
        session.channel_success(channel)?;
        match self.behaviour {
            Behaviour::Echo => {
                session.data(channel, format!("ran: {command}\n").into_bytes())?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            Behaviour::Flood => {
                let handle = session.handle();
                tokio::spawn(async move {
                    let chunk = vec![b'x'; 32 * 1024];
                    loop {
                        let out = handle.data(channel, chunk.clone()).await;
                        let err = handle.extended_data(channel, 1, chunk.clone()).await;
                        if out.is_err() || err.is_err() {
                            break;
                        }
                    }
                });
            }
            Behaviour::HangAfterAuth => {}
        }
        Ok(())
    }
}
