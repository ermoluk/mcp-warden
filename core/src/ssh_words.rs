//! The shell-syntax check every SSH command passes, whatever a preset's
//! patterns allow (invariant 5). It lives in core so config validation can
//! check the literal words of a named command's template at startup.

use crate::error::{Result, WardenError};

/// Refuse shell syntax, whatever the preset's patterns allow (invariant 5).
///
/// The exec channel hands the command to sshd, which runs it with the
/// remote user's login shell (`$SHELL -c`), so `git checkout \S+` would
/// also let `git checkout $(curl …|sh)` through. Each space-separated word
/// may hold only characters no common shell (sh, bash, zsh, dash, ksh,
/// tcsh, csh, fish) expands, splits or chains on; the shell then runs
/// exactly the words the allow-list matched — checked against every one of
/// those shells by `shells_split_permitted_words_as_written`.
///
/// Two uses of permitted characters still mean something to a shell, so
/// they are refused too: a leading `NAME=value` word, which every one of
/// those shells reads as an environment variable for the command
/// (`LD_PRELOAD=/tmp/x.so git pull`), and a word starting with `%`, which
/// fish expands (`%self` is its PID) and other shells read as a job.
pub fn check_words(command: &str) -> Result<()> {
    let refuse = |why: String| {
        WardenError::Validation(format!(
            "command refused ({why}): ssh_exec words may only contain letters, digits \
             and - _ . / : = @ , + % (no leading '=' or '%', no leading NAME=value), \
             separated by single spaces"
        ))
    };
    if command.split(' ').next().is_some_and(is_assignment) {
        return Err(refuse(
            "starts with NAME=value, an environment assignment".into(),
        ));
    }
    for word in command.split(' ') {
        if word.is_empty() {
            return Err(refuse(
                "empty word: leading, trailing or double space".into(),
            ));
        }
        // zsh expands `=cmd` to the command's path.
        if word.starts_with('=') {
            return Err(refuse("word starts with '='".into()));
        }
        if word.starts_with('%') {
            return Err(refuse("word starts with '%'".into()));
        }
        if let Some(c) = word.chars().find(|c| {
            !(c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | '@' | ',' | '+' | '%'))
        }) {
            return Err(refuse(format!("contains {c:?}")));
        }
    }
    Ok(())
}

/// `NAME=value`, as shells read an assignment in front of a command.
fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
