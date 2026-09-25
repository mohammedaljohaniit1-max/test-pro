# SysPulse

A native **Windows system diagnostics and observability suite** in Go. It builds to one self-contained `syspulse.exe` with an embedded dark-theme dashboard at **http://localhost:9099**, which receives live telemetry over WebSocket.

It reads the machine and does not change it. The one exception is the software upgrade button, which you trigger yourself and which calls `winget upgrade` for a package winget has already reported.

| Module | What it shows | Native source |
|---|---|---|
| **Network** | Every TCP/UDP socket (IPv4 and IPv6) with PID, process name and path, local and remote endpoint, and state. New, closed and changed connections are pushed live. | `iphlpapi!GetExtendedTcpTable` / `GetExtendedUdpTable` (`*_OWNER_PID`) |
| **Processes** | CPU %, working set (RSS), private bytes, threads, start time, image path. Sampled by a pool of worker goroutines. | Toolhelp32 snapshot, `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `GetProcessTimes`, `QueryFullProcessImageNameW`, `psapi!GetProcessMemoryInfo` |
| **System** | CPU % and RAM history charts, commit charge, uptime, capacity of every logical drive | `GetSystemTimes`, `GlobalMemoryStatusEx`, `GetPerformanceInfo`, `GetDiskFreeSpaceExW`, `GetTickCount64` |
| **Event log** | System and Application channels, classified as service crash, app fault, unexpected shutdown, driver, disk, Windows Update, power or other. Includes a 7-day stacked timeline. | `wevtapi!EvtQuery` / `EvtNext` / `EvtRender` / `EvtFormatMessage` |
| **Software** | Installed programs from the registry Uninstall keys (HKLM 64-bit, HKLM 32-bit, HKCU), merged with `winget upgrade` results. Upgradable packages get a one-click **Upgrade** button. | `x/sys/windows/registry`, `winget.exe` |

## Directory structure

```
.
├── build.bat                     # Windows build script → dist\syspulse.exe
├── Makefile                      # cross-compile / test from Linux or macOS
├── go.mod / go.sum               # only dependency: golang.org/x/sys
├── cmd/
│   ├── syspulse/                 # the real Windows entry point (//go:build windows)
│   │   ├── main.go               # flags, wiring, elevation check, browser launch, banner
│   │   └── util.go               # loopback-address guard
│   └── syspulse-demo/            # the same dashboard fed by synthetic data (any OS)
└── internal/
    ├── model/                    # JSON DTOs shared by all layers
    ├── netmon/                   # socket table parsing (pure Go) + tracker/diff + Windows source
    ├── procmon/                  # CPU delta sampler with worker pool + Windows reader
    ├── sysmon/                   # CPU / memory / disk sampler with history + Windows platform
    ├── eventlog/                 # XML parsing, classification, timeline + wevtapi reader
    ├── software/                 # registry inventory filter, winget parser/merger + Windows backend
    ├── ws/                       # dependency-free RFC 6455 WebSocket server
    ├── hub/                      # collector scheduler and WebSocket fan-out
    └── server/                   # HTTP API, security, go:embed of web/
        └── web/                  # index.html, assets/app.js, assets/app.css, favicon.svg
```

Every package has platform-neutral logic (parsing, diffing, CPU maths, classification, winget table parsing) that is unit-tested on any OS. Only the thin `*_windows.go` files call Win32.

## Build

On **Windows**, with Go 1.23+ installed:

```bat
build.bat               :: vet + test + build dist\syspulse.exe (v1.0.0, amd64)
build.bat 1.2.0 arm64   :: custom version / architecture
set SKIP_TESTS=1 && build.bat
```

To **cross-compile** from Linux or macOS:

```sh
make windows            # dist/syspulse.exe
make windows-arm64      # dist/syspulse-arm64.exe
make test vet
```

The binary is statically linked (`CGO_ENABLED=0`) and needs no installer or runtime.

## Run

```bat
syspulse.exe                    :: opens http://127.0.0.1:9099 in the default browser
syspulse.exe -no-browser -addr 127.0.0.1:9100
```

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `127.0.0.1:9099` | Listen address. It must be loopback; anything else is refused. |
| `-no-browser` | `false` | Don't open the dashboard automatically. |
| `-interval` | `1s` | Sampling period for system, process and network data. |
| `-events-window` | `168h` | How far back the event log is read at start-up. |
| `-events-max` | `2000` | Events kept per channel. |
| `-v` | `false` | Debug logging. |
| `-version` | | Print the version and exit. |

**Run as administrator for full visibility.** Without elevation, protected processes (e.g. `lsass.exe`, `csrss.exe`, AV engines) still appear with their names and socket ownership. Their path, memory and CPU show as "restricted".

### Try the UI without Windows

```sh
go run ./cmd/syspulse-demo            # http://127.0.0.1:9099 with simulated telemetry
```

The demo uses the real hub, server and embedded UI. Only the OS collectors are replaced. `-preview 0.0.0.0:8080` adds a reverse proxy for review behind an HTTPS gateway. This flag exists only in the demo binary.

## Security model

SysPulse shows sensitive host data and can start `winget`, so the HTTP surface is locked down:

- **Loopback only.** The listener binds to `127.0.0.1`, and non-loopback `-addr` values are rejected at start-up.
- **DNS-rebinding defence.** Requests whose `Host` header is not a loopback name or IP get `403`.
- **Session token.** Each launch generates a random 128-bit token and embeds it in the served page. Mutating endpoints require it in `X-SysPulse-Token`, and the WebSocket requires it in `?token=`.
- **Same-origin.** The WebSocket upgrade and every `POST` must carry `Origin: http://<host>`.
- **No argument injection.** Package IDs must match `^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$`, and winget runs through `exec.Command` with discrete arguments, never a shell. Only packages from the last `winget upgrade` listing may be upgraded, and only one upgrade runs at a time.
- **Strict CSP.** `script-src 'self'; style-src 'self'`. There are no inline scripts or styles and no CDNs; charts are drawn on `<canvas>`. Other headers: `X-Frame-Options: DENY`, `nosniff`, `no-referrer`.
- The Security event log is **not** read.

## HTTP / WebSocket API

| Method | Path | Description |
|---|---|---|
| GET | `/` | Dashboard (token injected) |
| GET | `/ws?token=` | Live stream (see below) |
| GET | `/api/health` | `{status, version, clients}` |
| GET | `/api/snapshot` | Latest metrics, history, processes, net stats and event summary |
| GET | `/api/connections` | Current sockets |
| GET | `/api/processes` | Current processes |
| GET | `/api/events?level=&category=&q=&limit=` | Filtered events (level: `critical`/`error`/`warning`/`info`) |
| GET | `/api/software` | Inventory merged with upgrades, winget status |
| POST | `/api/software/refresh` | Re-run `winget upgrade` (token + origin) |
| POST | `/api/software/upgrade` `{"id":"Vendor.App"}` | Upgrade one package (token + origin) |

WebSocket messages are `{"type": ..., "data": ...}`, where `type` is one of `snapshot`, `metrics`, `processes`, `netdiff` (`added`/`removed`/`changed`), `netstats`, `events`, `eventsummary` or `software`. Each client has a bounded queue, and a slow client is disconnected so it cannot stall the collectors.

## Implementation notes

- **Socket tables.** Calls are retried while they return `ERROR_INSUFFICIENT_BUFFER`. Ports are converted from network byte order. The row layouts (TCP4 24 B, TCP6 56 B, UDP4 12 B, UDP6 28 B) are parsed with bounds checks.
- **CPU %.** Per process: Δ(kernel+user) / Δwall / cores. Samples are keyed by (PID, creation time), so a reused PID never inherits another process's counters. For the whole system, busy = (kernel + user − idle) / (kernel + user) from `GetSystemTimes`.
- **Event log.** Reads are incremental: after the first window query, polls use `EventRecordID > last`. Publisher metadata handles are cached for `EvtFormatMessage`, and when rendering fails the message is rebuilt from `EventData`.
- **winget parsing.** Columns are located from the header row using rune offsets, since winget pads with display width. Rows where a long name spills into the next column are re-split. Footer lines and progress spinners are discarded. Parsing works for any UI language whose table has an `Id` column.

## Limitations

- Requires Windows 10 1809+ or Windows Server 2019+. Windows 11 is detected from the build number.
- The software upgrade features need **winget** (App Installer). Without it the inventory still works and the UI says winget is missing.
- Some installers only upgrade in an elevated session or show their own UI despite `--silent`.
- Process CPU is sampled at `-interval`, so processes that live for less than one interval may not appear.

## Testing

```sh
go test -race ./...          # all platform-neutral logic, HTTP/WS integration
GOOS=windows go vet ./...    # type-checks the Win32 layer
```
