//! Hard limits shared by config validation and the executor.

/// `ssh_exec` command, in bytes. A named command's longest possible
/// expansion must fit too.
pub const MAX_SSH_COMMAND_BYTES: usize = 1024;

/// `ssh_exec` stdout and stderr, each, in bytes. Output beyond it is not
/// read: the call ends and says so. A preset's or command's
/// `max_output_bytes` can only lower it.
pub const MAX_SSH_OUTPUT_BYTES: usize = 1024 * 1024;

/// `ssh_run` parameters.
pub const MAX_SSH_RUN_PARAMS: usize = 16;

/// Each `ssh_run` parameter value, in bytes.
pub const MAX_SSH_RUN_PARAM_BYTES: usize = 256;
