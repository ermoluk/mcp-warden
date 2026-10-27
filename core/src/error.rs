use thiserror::Error;

#[derive(Debug, Error)]
pub enum WardenError {
    #[error("config error: {0}")]
    Config(String),
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("preset not found: {0}")]
    PresetNotFound(String),
    #[error("preset references missing secret: preset='{preset}' secret='{secret}'")]
    MissingSecret { preset: String, secret: String },
    #[error("validation error: {0}")]
    Validation(String),
    #[error("approval denied")]
    ApprovalDenied,
    #[error("approval timeout")]
    ApprovalTimeout,
    #[error(
        "mcp-warden is locked: every call is refused until the user runs `mcp-warden unlock` \
         and restarts the MCP server"
    )]
    Locked,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ssh: {0}")]
    Ssh(String),
    #[error("audit: {0}")]
    Audit(String),
    #[error("executor: {0}")]
    Executor(String),
}

pub type Result<T> = std::result::Result<T, WardenError>;

impl From<russh::Error> for WardenError {
    fn from(e: russh::Error) -> Self {
        WardenError::Ssh(e.to_string())
    }
}
