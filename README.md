# SysPulse 2.0

> **Windows Observability & System Reliability Cockpit** — bilingual (English / العربية with full RTL), with a multi-port connection-sweep radar, one-click event-log diagnostics, an Alerts & Incidents centre and an integrated user guide.

A native **Windows system diagnostics and observability suite** in Go. It builds to one self-contained `syspulse.exe` with an embedded dark-theme dashboard at **http://localhost:9099**, which receives live telemetry over WebSocket.

It reads the machine and does not change it. The one exception is the software upgrade button, which you trigger yourself and which calls `winget upgrade` for a package winget has already reported.

| Module | What it shows | Native source |
|---|---|---|
| **Network** | Every TCP/UDP socket (IPv4 and IPv6) with PID, process name and path, local and remote endpoint, and state. New, closed and changed connections are pushed live. | `iphlpapi!GetExtendedTcpTable` / `GetExtendedUdpTable` (`*_OWNER_PID`) |
| **Processes** | CPU %, working set (RSS), private bytes, threads, start time, image path. Sampled by a pool of worker goroutines. | Toolhelp32 snapshot, `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `GetProcessTimes`, `QueryFullProcessImageNameW`, `psapi!GetProcessMemoryInfo` |
| **System** | CPU % and RAM history charts, commit charge, uptime, capacity of every logical drive | `GetSystemTimes`, `GlobalMemoryStatusEx`, `GetPerformanceInfo`, `GetDiskFreeSpaceExW`, `GetTickCount64` |
| **Event log** | System and Application channels, classified as service crash, app fault, unexpected shutdown, driver, disk, Windows Update, power or other. Includes a 7-day stacked timeline. | `wevtapi!EvtQuery` / `EvtNext` / `EvtRender` / `EvtFormatMessage` |
| **Anomaly Radar** *(2.0)* | Per-remote-IP inbound connection frequency and distinct-port breadth. **Rule: >10 distinct ports within 5 s ⇒ "High-Frequency Connection Sweep (Traffic Anomaly)"**. Red banner + audio chime with remote IP, MAC, interface, port range and timestamp. | Raw `SOCK_RAW` + `SIO_RCVALL` SYN sensor (admin), `GetExtendedTcpTable` sensor, `GetIpNetTable`, `GetBestRoute`, `SendARP`, `GetAdaptersAddresses` |
| **Diagnostics** *(2.0)* | **Audit Authentication & Access Logs** (4625 failed logons, brute force, password spraying, 4740 lockouts, 4672 privilege assignments) and **Audit System Reliability & Faults** (7034/7031 service crashes, 1000 app faults, 1002 hangs, bugchecks with decoded stop codes, 41/6008 unexpected shutdowns). Every finding has a *Plain-Language Diagnosis* and *Recommended Fix* column in both languages; JSON/CSV export. | `wevtapi!EvtQuery` with ID-filtered XPath over Security / System / Application |
| **Alerts & Incidents** *(2.0)* | Critical / Warning / Informational badges, de-duplication with counts, quick filters, search, acknowledgement, one-click JSON/CSV export (UTF-8 BOM, formula-injection safe). Fed by the radar, the event log, the audits and resource thresholds. | all modules |
| **User Guide / دليل الاستخدام** *(2.0)* | Metric and feature comparison tables, sensor explanations, flags, troubleshooting and a step-by-step **Verification Guide** for safely testing sweep detection on your own LAN. | embedded |
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
    ├── radar/                    # sweep detector, ARP/raw-packet parsing, SIO_RCVALL sensor (Windows)
    ├── alerts/                   # alert store, filters, JSON/CSV export
    ├── audit/                    # auth + reliability analysis with bilingual diagnosis/fix
    ├── hub/                      # collector scheduler and WebSocket fan-out
    └── server/                   # HTTP API, security, go:embed of web/
        └── web/                  # index.html, assets/{app,i18n,guide}.js, assets/app.css, favicon.svg
```

Every package has platform-neutral logic (parsing, diffing, CPU maths, classification, winget table parsing) that is unit-tested on any OS. Only the thin `*_windows.go` files call Win32.

## Build

On **Windows**, with Go 1.23+ installed:

```bat
build.bat               :: vet + test + build dist\syspulse.exe (v2.0.0, amd64)
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
| `-radar-window` | `5s` | Sweep detection window. |
| `-radar-threshold` | `10` | Flag a remote IP that touches more than N distinct ports within the window. |
| `-radar-cooldown` | `60s` | Quiet time after which a sweep incident closes. |
| `-radar-allow` | | Comma-separated IPs never flagged (authorised scanners). |
| `-no-raw-capture` | `false` | Disable the raw SYN sensor and use the TCP table only. |
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
- The Security event log is read **only** when you press *Audit Authentication & Access Logs*.
- The raw sensor uses `RCVALL_IPLEVEL` (no promiscuous NIC mode) and parses only IP/TCP headers.
- Report downloads require the session token; CSV cells starting with `= + - @` are neutralised.

## Verifying sweep detection

1. **Radar → Run safe self-test**: a synthetic sweep from `198.51.100.77` triggers the banner, chime and a critical alert without sending any packets.
2. On a second machine you own, on the same LAN: `nmap -sS -p 1-100 -T4 <this-PC-IP>` or the PowerShell loop in the in-app guide. Within a second the banner shows that machine's IP and MAC (compare with `ipconfig /all`).

Only scan machines you own or are authorised to test.

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
| GET | `/api/radar?limit=` | Radar state: rule, sensors, per-IP stats, incidents, 60 s series |
| GET | `/api/radar/neighbors` | Cached ARP table |
| POST | `/api/radar/selftest` `{"ports":24}` | Inject a synthetic sweep from 198.51.100.77 (token + origin) |
| GET | `/api/alerts?severity=&category=&q=&unacked=&since=&limit=` | Filtered alerts + counts |
| GET | `/api/alerts/export?format=json\|csv&lang=en\|ar&…&token=` | Download the filtered alert report |
| POST | `/api/alerts/ack` `{"ids":[]}` · `/api/alerts/clear` | Acknowledge (empty = all) / clear (token + origin) |
| GET | `/api/audit` | Last report per audit, running audits |
| POST | `/api/audit/auth` · `/api/audit/reliability` `{"hours":168}` | Run a diagnostic audit (token + origin) |
| GET | `/api/audit/{kind}/export?format=json\|csv&lang=&token=` | Download the audit report |

WebSocket messages are `{"type": ..., "data": ...}`, where `type` is one of `snapshot`, `metrics`, `processes`, `netdiff` (`added`/`removed`/`changed`), `netstats`, `events`, `eventsummary`, `software`, `radar`, `sweep`, `alert`, `alertcounts`, `alertsreset`, `audit` or `auditstate`. Each client has a bounded queue, and a slow client is disconnected so it cannot stall the collectors.

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
