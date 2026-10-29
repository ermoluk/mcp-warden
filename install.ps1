# Install mcp-warden from a GitHub release on Windows.
#
#   irm https://github.com/ermoluk/mcp-warden/releases/latest/download/install.ps1 | iex
#
# Downloads the zip and the release's SHA256SUMS, refuses to install unless
# the checksum matches, and copies mcp-warden.exe into a directory you own.
# No administrator rights, no changes to PATH or anything else, and nothing
# that runs again later: to update, run it again.
#
# Environment:
#   MCP_WARDEN_VERSION       release to install, e.g. 0.5.3 (default: the latest)
#   MCP_WARDEN_INSTALL_DIR   where the binary goes
#                            (default: %LOCALAPPDATA%\Programs\mcp-warden\bin)
#   MCP_WARDEN_DOWNLOAD_URL  base URL of the release assets, for mirrors and
#                            tests (default: GitHub releases)

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    # Windows PowerShell 5.1 may not offer TLS 1.2 by default.
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'https://github.com/ermoluk/mcp-warden'
    $dir = $env:MCP_WARDEN_INSTALL_DIR
    if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'Programs\mcp-warden\bin' }
    if ($env:MCP_WARDEN_DOWNLOAD_URL) {
        $base = $env:MCP_WARDEN_DOWNLOAD_URL.TrimEnd('/')
    } elseif ($env:MCP_WARDEN_VERSION) {
        $base = "$repo/releases/download/v$($env:MCP_WARDEN_VERSION.TrimStart('v'))"
    } else {
        $base = "$repo/releases/latest/download"
    }

    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if ($arch -ne 'X64' -and $arch -ne 'Arm64') {
        throw "mcp-warden install: unsupported architecture $arch"
    }
    # Windows on Arm runs the x64 build under emulation.
    $archive = 'mcp-warden-x86_64-pc-windows-msvc.zip'

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('mcp-warden-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "mcp-warden install: downloading $archive from $base"
        $zip = Join-Path $tmp $archive
        $sums = Join-Path $tmp 'SHA256SUMS'
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$archive" -OutFile $zip
        Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums

        $want = Get-Content $sums | ForEach-Object {
            $fields = $_ -split '\s+'
            if ($fields.Count -ge 2 -and ($fields[1] -eq $archive -or $fields[1] -eq "*$archive")) { $fields[0] }
        } | Select-Object -First 1
        if (-not $want) { throw "mcp-warden install: SHA256SUMS has no entry for $archive" }
        $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
        if ($got -ne $want.ToLowerInvariant()) {
            throw "mcp-warden install: checksum mismatch for ${archive}: expected $want, got $got"
        }
        Write-Host 'mcp-warden install: checksum ok'

        $unpacked = Join-Path $tmp 'unpacked'
        Expand-Archive -Path $zip -DestinationPath $unpacked
        $exe = Join-Path $unpacked 'mcp-warden.exe'
        if (-not (Test-Path $exe)) { throw "mcp-warden install: $archive has no mcp-warden.exe" }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $target = Join-Path $dir 'mcp-warden.exe'
        Copy-Item -Force -Path $exe -Destination $target
        $installed = & $target --version
        Write-Host "mcp-warden install: installed $installed to $target"

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not (($userPath -split ';') -contains $dir)) {
            Write-Host "mcp-warden install: $dir is not on your PATH. To add it for your user, run:"
            Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"$dir;`" + [Environment]::GetEnvironmentVariable('Path', 'User'), 'User')"
        }
    } finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }
}
