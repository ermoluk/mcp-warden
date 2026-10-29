#!/usr/bin/env node
// Runs the mcp-warden binary for this platform, which npm installed from one
// of the optional @mcp-warden/<platform>-<arch> packages. Nothing is
// downloaded, at install time or at run time, and there is no install
// script: the binary ships inside that package.
//
// stdout belongs to the binary — under `mcp-warden mcp` it is the MCP
// protocol channel — so this wrapper only ever writes to stderr.
"use strict";

const { spawn } = require("child_process");
const path = require("path");

const PACKAGES = {
  "darwin-arm64": "@mcp-warden/darwin-arm64",
  "darwin-x64": "@mcp-warden/darwin-x64",
  "linux-arm64": "@mcp-warden/linux-arm64",
  "linux-x64": "@mcp-warden/linux-x64",
  "win32-x64": "@mcp-warden/win32-x64",
};

function fail(message) {
  process.stderr.write(`mcp-warden (npm): ${message}\n`);
  process.exit(1);
}

function binaryPath() {
  const platform = `${process.platform}-${process.arch}`;
  const pkg = PACKAGES[platform];
  if (!pkg) {
    fail(
      `there is no prebuilt binary for ${platform}. ` +
        "Build it from source instead: cargo install --locked mcp-warden",
    );
  }
  const exe = process.platform === "win32" ? "mcp-warden.exe" : "mcp-warden";
  try {
    return path.join(path.dirname(require.resolve(`${pkg}/package.json`)), "bin", exe);
  } catch (e) {
    fail(
      `${pkg} is not installed, so there is no binary to run. ` +
        "It is an optional dependency: reinstall without --no-optional / --omit=optional.",
    );
  }
}

const child = spawn(binaryPath(), process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: true,
});

const forwarded = ["SIGINT", "SIGTERM", "SIGHUP"];
for (const signal of forwarded) {
  process.on(signal, () => {
    if (child.exitCode === null && child.signalCode === null) child.kill(signal);
  });
}

child.on("error", (e) => fail(`could not start ${child.spawnfile}: ${e.message}`));
child.on("exit", (code, signal) => {
  if (signal) {
    // Die the same way the binary did.
    for (const s of forwarded) process.removeAllListeners(s);
    process.kill(process.pid, signal);
  } else {
    process.exit(code === null ? 1 : code);
  }
});
