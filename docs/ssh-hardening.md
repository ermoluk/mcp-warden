# Hardening the SSH side

`mcp-warden` checks every `ssh_exec` command before it connects: the preset's
anchored `allowed_commands` patterns, a per-word character filter that refuses
shell syntax whatever the patterns say, and a 1024-byte limit. That is the
first allow-list. This guide sets up a second one on the server, so a pattern
that is too broad — or a key that leaks — still can't run anything you didn't
plan for.

The setup has four parts:

1. a dedicated account with the fewest rights the job needs and no interactive login;
2. its key pinned to a gate script (`command=` and `restrict` in `authorized_keys`, or `ForceCommand` in `sshd_config`);
3. a gate script that runs only the commands you list;
4. a separate account and key for SFTP, if you use `sftp_transfer`.

## Why the remote shell is involved at all

SSH has no request for "run this program with these arguments". The exec
request carries a single string, and sshd hands it to the account's login
shell as `$SHELL -c "<string>"`. No client can avoid that — not OpenSSH's
`ssh host cmd`, and not the `russh` exec channel `mcp-warden` uses. So
whatever the shell would expand (`$(…)`, backticks, `;`, `|`, globs, `~`,
zsh's `=cmd`) is executable on the server.

That is why `ssh_exec` refuses shell syntax before it matches the pattern:
each space-separated word may contain only letters, digits and
`- _ . / : = @ , + %`, and none may start with `=`. The shell then runs exactly
the words the allow-list matched. A forced command on the server goes one step
further: the shell runs your gate script instead of the request, and the
request only arrives as data, in `$SSH_ORIGINAL_COMMAND`.

One consequence: the account needs a real login shell such as `/bin/sh`.
With `/usr/sbin/nologin` as its shell, sshd runs `nologin -c …`, which refuses
everything — including your gate. Interactive login is blocked by the forced
command and by `restrict` / `PermitTTY no` instead.

## 1. A dedicated account

On the server:

```sh
sudo useradd --create-home --shell /bin/sh warden-deploy
sudo passwd --lock warden-deploy          # no password login, ever
sudo install -d -m 700 -o warden-deploy -g warden-deploy ~warden-deploy/.ssh
```

Give it only what the commands need:

- **sudo for exact commands**, with fixed arguments, if a command needs root:
  ```
  # /etc/sudoers.d/warden-deploy   (edit with `sudo visudo -f …`)
  warden-deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app.service
  ```
- **Not the `docker` group** unless you accept that it is root: anyone in it
  can start a container that mounts `/`. Prefer a gate entry that runs
  `docker compose` through a sudo rule for the one compose file.
- **Ownership of only the directories it deploys to**, e.g. `/srv/app`.

On your machine, make a key for it and move the private half into the
keychain. `mcp-warden secret add` reads the value from stdin, so it never
appears in your shell history or on the command line:

```sh
ssh-keygen -t ed25519 -N '' -C mcp-warden -f ./warden-deploy
mcp-warden secret add deploy_key < ./warden-deploy
cat ./warden-deploy.pub                   # goes into authorized_keys below
```

Keep `./warden-deploy` only until you have tested the gate (end of step 3),
then delete it: the keychain holds the key.

Pin the host key, since `mcp-warden` refuses hosts it can't verify:
`ssh-keyscan -t ed25519 deploy.example.com >> ~/.ssh/known_hosts`, then check
the fingerprint (`ssh-keygen -lf ~/.ssh/known_hosts`) against the one the
server shows (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`).

## 2. Pin the key to the gate

In `~warden-deploy/.ssh/authorized_keys`, put the options in front of the key:

```
restrict,command="/usr/local/bin/warden-gate" ssh-ed25519 AAAAC3Nza… mcp-warden
```

- `command="…"` makes sshd run the gate instead of whatever the client asked
  for. The request is passed in `$SSH_ORIGINAL_COMMAND`.
- `restrict` turns off port, agent and X11 forwarding, PTY allocation and
  `~/.ssh/rc` for this key.

An account that can write its own `authorized_keys` could remove those options
with a command you allowed by mistake. Either keep the file root-owned
(`AuthorizedKeysFile /etc/ssh/authorized_keys/%u` in `sshd_config`, the file
`root:root 0644`), or set the same rules for the whole account in
`sshd_config`, where the account can't touch them:

```
# /etc/ssh/sshd_config.d/warden.conf
Match User warden-deploy
    ForceCommand /usr/local/bin/warden-gate
    AuthenticationMethods publickey
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserRC no
```

Check and reload: `sudo sshd -t && sudo systemctl reload ssh` (the unit is
`sshd` on some distributions).

## 3. The gate script

The gate matches the whole request against fixed strings and runs a fixed
program for each. It never passes the request to a shell or to `eval`, and
never splits it into words itself.

```sh
#!/bin/sh
# /usr/local/bin/warden-gate — the server's own allow-list for mcp-warden.
# sshd runs this instead of the requested command, which arrives in
# $SSH_ORIGINAL_COMMAND. Each branch runs a fixed program; the request is
# only compared, never executed. Anything else is refused and logged.
set -eu

req=${SSH_ORIGINAL_COMMAND-}

case $req in
  'uptime')
    exec /usr/bin/uptime ;;
  'docker compose ps')
    cd /srv/app && exec sudo -n /usr/bin/docker compose ps ;;
  'docker compose pull')
    cd /srv/app && exec sudo -n /usr/bin/docker compose pull ;;
  'docker compose up -d')
    cd /srv/app && exec sudo -n /usr/bin/docker compose up -d ;;
  'journalctl -u app -n '[1-9] | \
  'journalctl -u app -n '[1-9][0-9] | \
  'journalctl -u app -n '[1-9][0-9][0-9])
    # The pattern above allows only 1-999 after `-n `.
    exec /usr/bin/journalctl -u app -n "${req##* }" --no-pager ;;
esac

# Keep the log line printable: the request is untrusted text.
logger -t warden-gate -- "refused: $(printf '%s' "$req" | tr -cd '[:print:]' | cut -c1-200)"
echo "warden-gate: command not allowed" >&2
exit 126
```

Install it root-owned and not writable by the account:

```sh
sudo install -m 755 -o root -g root warden-gate /usr/local/bin/warden-gate
```

For the `sudo -n /usr/bin/docker compose …` lines, the matching sudoers
entries are, for example:

```
warden-deploy ALL=(root) NOPASSWD: /usr/bin/docker compose ps, \
    /usr/bin/docker compose pull, /usr/bin/docker compose up -d
```

## The matching preset

The preset allows the same commands, so `mcp-warden` refuses (and audits)
everything else before it connects, and the gate refuses it again on the
server:

```toml
[[preset]]
name = "deploy"
type = "ssh"
description = "Production deploy host"
host = "deploy.example.com"
user = "warden-deploy"
secret = "deploy_key"
allowed_commands = [
  "uptime",
  "docker compose (ps|pull|up -d)",
  "journalctl -u app -n [1-9][0-9]{0,2}",
]
approval = "prompt"
timeout_seconds = 300
```

Try it:

```sh
mcp-warden preset test deploy --command "docker compose ps"   # ALLOWED
mcp-warden preset test deploy --command "docker compose down" # REFUSED, nothing sent
```

And from your own terminal with the key file still at hand, before you delete
it — the gate is the only thing between these requests and the shell:

```sh
ssh -i ./warden-deploy warden-deploy@deploy.example.com 'docker compose ps'  # runs
ssh -i ./warden-deploy warden-deploy@deploy.example.com 'id'                 # refused, exit 126
ssh -i ./warden-deploy -t warden-deploy@deploy.example.com                   # no PTY, refused
rm ./warden-deploy                                                          # done testing
```

## 4. SFTP needs its own key

`sftp_transfer` uses the SFTP subsystem. A forced command replaces that too,
so a preset with `allow_sftp = true` can't use the gated key. Give file
transfers a second account, confined to one directory:

```
# /etc/ssh/sshd_config.d/warden.conf
Match User warden-files
    ForceCommand internal-sftp -d /files
    ChrootDirectory /srv/warden-files
    AuthenticationMethods publickey
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
```

`ChrootDirectory` and every directory above it must be owned by root and not
writable by anyone else; the account writes inside it:

```sh
sudo useradd --create-home --shell /bin/sh warden-files && sudo passwd --lock warden-files
sudo install -d -m 755 -o root -g root /srv/warden-files
sudo install -d -m 750 -o warden-files -g warden-files /srv/warden-files/files
```

Inside the chroot the remote paths start at `/files`:

```toml
[[preset]]
name = "deploy-files"
type = "ssh"
description = "Upload and fetch build artefacts"
host = "deploy.example.com"
user = "warden-files"
secret = "files_key"
allow_sftp = true
sftp_allowed_paths = ["/files/"]
approval = "prompt"
```

With no `allowed_commands`, `ssh_exec` on this preset refuses everything, and
`internal-sftp` would not run a command anyway.

## What this does not cover

- **What the allowed commands themselves can do.** `docker compose up -d`
  runs whatever the compose file says; whoever can change that file controls
  the deploy.
- **The audit trail on the server.** The gate logs refusals to syslog
  (`journalctl -t warden-gate`); `mcp-warden audit` has the agent's side,
  including calls refused before they reached the server.
- **Output.** `ssh_exec` returns stdout and stderr to the agent unscrubbed
  (threat model N3), so keep secrets out of what the allowed commands print.
