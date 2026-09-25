# Tempora — High-Throughput Temporal Correlation Engine

Tempora is an in-memory event streaming and **temporal correlation engine**, written in Go. It takes in telemetry events over HTTP or raw TCP. It then evaluates them against rules written in a small, compiled DSL. Rules come in two kinds: **ordered event patterns** ("5 failed logins, then a success, with no password reset in between, within 2 minutes") and **sliding-window aggregates** ("p99 latency above 750 ms over 30 s"). Matches are sent to stdout, files, webhooks, a query API and a live Server-Sent-Events stream.

It is built for the event-time problems real telemetry has: out-of-order delivery, late data, *absence* detection (something that should have happened but did not), bounded memory under hostile key cardinality, crash recovery, and rule changes without restarts.

| Property | Value (measured, see [Benchmarks](#12-benchmarks--performance)) |
|---|---|
| End-to-end throughput (2 vCPU, 7 rules, 200 ms disorder) | **~650 000 – 775 000 events/s** in process |
| Throughput with in-order input | **~1.1 M events/s** |
| Per-event evaluation latency | **p50 ≈ 1.5 µs, p99 ≈ 6.5 µs, p99.9 ≈ 15 µs** |
| Allocations on the hot path | **0.05 allocs/event**; 0 GC cycles during a 1 M-event run |
| Detection recall on injected attack scenarios | **120 / 120** (100 %), 0 false positives on background keys |
| External dependencies | **None** — Go standard library only |
| Test suite | 104 tests + 2 fuzzers, race-detector clean, 78–94 % coverage per package |

---

## Table of contents

1. [What problem Tempora solves](#1-what-problem-tempora-solves)
2. [Quick start (5 minutes)](#2-quick-start-5-minutes)
3. [System architecture](#3-system-architecture)
4. [Concurrency model](#4-concurrency-model)
5. [Event-time semantics: watermarks, lateness, ordering](#5-event-time-semantics-watermarks-lateness-ordering)
6. [The event model and wire formats](#6-the-event-model-and-wire-formats)
7. [Tempora Correlation Language (TCL) — full reference](#7-tempora-correlation-language-tcl--full-reference)
8. [How rules are evaluated (NFA and window internals)](#8-how-rules-are-evaluated-nfa-and-window-internals)
9. [Bundled rule pack](#9-bundled-rule-pack)
10. [Durability: the write-ahead log and crash recovery](#10-durability-the-write-ahead-log-and-crash-recovery)
11. [Alert delivery (sinks)](#11-alert-delivery-sinks)
12. [Benchmarks & performance](#12-benchmarks--performance)
13. [Memory profile and bounded state](#13-memory-profile-and-bounded-state)
14. [HTTP & TCP API reference](#14-http--tcp-api-reference)
15. [Configuration reference](#15-configuration-reference)
16. [Observability: metrics, logs, profiling](#16-observability-metrics-logs-profiling)
17. [Deployment](#17-deployment)
18. [Operations runbook](#18-operations-runbook)
19. [Testing strategy](#19-testing-strategy)
20. [Project structure — every file explained](#20-project-structure--every-file-explained)
21. [Design decisions and trade-offs](#21-design-decisions-and-trade-offs)
22. [Security considerations](#22-security-considerations)
23. [Limitations and roadmap](#23-limitations-and-roadmap)
24. [Development workflow & contributing](#24-development-workflow--contributing)
25. [Glossary](#25-glossary)

---

## 1. What problem Tempora solves

Single-event alerting ("status == 500") is easy. The incidents that matter usually show up only as **relationships between events over time**:

| Pattern type | Example | Why it is hard |
|---|---|---|
| Ordered sequence | 5+ auth failures → success, same IP, within 2 min | Needs per-key state machines, time bounds and cross-event predicates (`ok.user == fail.user`) |
| Sequence with negation | …and **no** password reset in between | Must *invalidate* partial matches |
| Absence | Service started and sent **no** heartbeat for 30 s | Fires on the *lack* of events, so it needs timers in event time, including when no traffic arrives |
| Sliding aggregate | p99 latency > 750 ms over the last 30 s, per service | Needs windowed quantiles and cardinalities in fixed memory |
| Grouped aggregate | 5xx ratio > 20 % per `path` | Nested grouping inside a partition key, with a cap on group count |

Doing this correctly also means handling:

* **Out-of-order data.** Producers, networks and batching reorder events, so the engine must evaluate in *event time*, not arrival time.
* **Late data.** There must be a clear policy for events that arrive after their window has closed.
* **Unbounded key spaces.** An attacker controls source IPs, so per-key state must be strictly bounded.
* **Crashes.** Partial matches, e.g. 4 of 5 failures, must survive a restart without re-sending old alerts.
* **Change.** Rules must be hot-reloadable without losing state for unchanged rules.

Tempora handles all of these in one small, dependency-free binary.

---

## 2. Quick start (5 minutes)

### 2.1 Prerequisites

* **Go 1.23+** to build from source. No third-party modules are needed.
* *Optional:* Docker 24+ with Compose v2 for the containerised stack.
* *Optional:* `gcc` for `make test-race` (the race detector needs cgo).

### 2.2 Build, validate rules, run

```bash
git clone https://github.com/mohammedaljohaniit1-max/test-pro.git tempora
cd tempora

make build            # -> bin/tempora, bin/tempora-bench (static, CGO_ENABLED=0)
make check            # compiles every rules/*.tcl and prints one line per rule
make run              # starts the server: HTTP :8080, TCP :9090, WAL in ./data/wal
```

`make check` output:

```
ok  latency_slo_breach           aggregate high     65abc95cef55fb7e
ok  error_burst                  aggregate medium   f7dd88c3c326d76f
ok  missing_heartbeat            sequence  high     ca0a7701a5cf0b41
ok  crash_loop                   sequence  high     67adbd7aea0063bc
ok  brute_force_then_success     sequence  critical 1311c53f4d937ccf
ok  port_scan                    aggregate high     38e143f2f50e9275
ok  webshell_chain               sequence  critical 33b8c0abfa5b384c
```

The last column is the rule **fingerprint**: the first 8 bytes of the SHA-256 of the rule's source text. It is used during hot reload (see §8.6).

### 2.3 Send a brute-force attack and see the alert

```bash
T=$(date -u +%s)
for i in 0 1 2 3 4; do
  echo "{\"type\":\"auth.failure\",\"key\":\"203.0.113.9\",\"ts\":$((T+i)),\"attrs\":{\"user\":\"root\",\"method\":\"password\"}}"
done > attack.ndjson
echo "{\"type\":\"auth.success\",\"key\":\"203.0.113.9\",\"ts\":$((T+6)),\"attrs\":{\"user\":\"root\",\"method\":\"password\"}}" >> attack.ndjson

curl -s -XPOST localhost:8080/v1/events \
     -H 'Content-Type: application/x-ndjson' --data-binary @attack.ndjson
# {"accepted":6,"invalid":0,"rejected":0}
```

With the default `TEMPORA_ALLOWED_LATENESS=2s`, the alert is emitted once the watermark passes the success event. That happens when newer traffic arrives, or after `TEMPORA_IDLE_ADVANCE=5s` of idleness. The alert appears on stdout (one JSON object per line) and in the API:

```bash
curl -s 'localhost:8080/v1/alerts?limit=1' | python3 -m json.tool
```

```json
{
  "id": "brute_force_then_success-6-dlnz772uo3k0",
  "rule": "brute_force_then_success",
  "kind": "sequence",
  "severity": "critical",
  "description": "5+ authentication failures followed by a success from the same source",
  "tags": ["mitre:T1110", "auth"],
  "key": "203.0.113.9",
  "event_time": "2026-09-25T00:37:39Z",
  "detected_at": "2026-09-25T00:37:41.016846639Z",
  "fields": { "user": "root", "failures": 5, "method": "password",
              "elapsed_ms": 6000, "duration_ms": 6000 },
  "evidence": [ { "seq": 1, "type": "auth.failure", "ts": "2026-09-25T00:37:33Z", "...": "..." },
                "... 6 contributing events in total ..." ],
  "fingerprint": "1311c53f4d937ccf",
  "shard": 1
}
```

### 2.4 Watch alerts live

```bash
curl -N localhost:8080/v1/alerts/stream                 # all rules
curl -N 'localhost:8080/v1/alerts/stream?rule=port_scan'
```

### 2.5 Load test it

```bash
make bench-e2e                                           # in-process: 1M events
bin/tempora-bench -target 127.0.0.1:9090 -rate 50000 -duration 30s   # over TCP
```

### 2.6 Full containerised stack

```bash
make compose-up        # tempora (8080/9090) + Prometheus (9091) with operational alert rules
make compose-load      # optional: 20k ev/s synthetic load over TCP for 10 minutes
make compose-down
```

---

## 3. System architecture

### 3.1 Component diagram

```
                        ┌───────────────────────────────────────────────────────────────┐
  HTTP POST /v1/events  │                         tempora process                        │
  (JSON / array / NDJSON)│                                                               │
 ──────────────────────▶│  ┌─────────────┐   validate    ┌──────────────┐                │
  TCP :9090 (NDJSON)    │  │ HTTP server │──────────────▶│   Ingestor   │                │
 ──────────────────────▶│  │ TCP server  │  event.Parse  │ seq assign   │──AppendBatch──▶ WAL
                        │  └─────────────┘               │ + journal    │   (group commit, CRC32C,
                        │                                └──────┬───────┘    segmented, fsync policy)
                        │                         hash(key) % N │ SubmitBatch
                        │              ┌────────────────────────┼────────────────────────┐
                        │              ▼                        ▼                        ▼
                        │     ┌────────────────┐      ┌────────────────┐      ┌────────────────┐
                        │     │ lock-free MPMC │      │ lock-free MPMC │ ...  │ lock-free MPMC │
                        │     │ ring (shard 0) │      │ ring (shard 1) │      │ ring (shard N) │
                        │     └───────┬────────┘      └───────┬────────┘      └───────┬────────┘
                        │             ▼ PopBatch               ▼                       ▼
                        │   ┌──────────────────────────────────────────────────────────────┐
                        │   │ shard goroutine (sole owner of its state — no locks)          │
                        │   │  reorder heap ─▶ watermark ─▶ interleave with timer heap      │
                        │   │        │                                  │                    │
                        │   │        ▼                                  ▼                    │
                        │   │  relevance index ─▶ per-key state (LRU + TTL)                 │
                        │   │        ├─ sequence rules: NFA runs (quantifiers, guards)      │
                        │   │        └─ aggregate rules: pane rings + HLL + DDSketch        │
                        │   │  suppression ─▶ Alert                                          │
                        │   └──────────────────────────────┬───────────────────────────────┘
                        │                                  ▼ alerts channel
                        │                        ┌────────────────────┐
                        │                        │     Dispatcher     │ per-sink bounded queue + worker
                        │                        └──┬──────┬──────┬───┘
                        │                           ▼      ▼      ▼
                        │                        stdout  file  webhook(retry+breaker)  Hub ─▶ /v1/alerts
                        │                                                                  └─▶ SSE stream
                        │  /metrics (Prometheus) · /v1/stats · /v1/rules · /healthz · /readyz │
                        └───────────────────────────────────────────────────────────────┘
```

### 3.2 Life of an event

1. **Parse and validate** (`internal/event/codec.go`). JSON is decoded with `UseNumber` so integers stay exact. The event is then normalised: attributes are sorted and limits enforced (§6.3). Invalid events are counted and reported per line, and never reach the engine.
2. **Journal** (`internal/server/ingest.go`, `internal/wal`). If the WAL is enabled, the ingestor takes one mutex per *batch*. It assigns monotonically increasing sequence numbers, appends the whole batch as CRC-protected records, and hands the events to the shards. Journaling and hand-off share one critical section, so WAL order equals per-shard arrival order. That makes replay deterministic.
3. **Route** (`engine.ShardFor`). `wyhash-style 64-bit hash(key) mod N`. Every event with the same key goes to the same shard, which gives single-writer state per key.
4. **Hand-off** (`internal/ring`). A lock-free bounded MPMC ring push: one CAS in the common case. When the ring is full, the producer spins, then yields, then parks (blocking backpressure). With `DropOnFull`, it fails fast with HTTP 429 instead.
5. **Order** (`internal/engine/shard.go`). The shard drains up to `BatchSize` items, pushes each event into a 4-ary min-heap ordered by `(time, seq)`, and raises the watermark to `max_event_time − AllowedLateness`.
6. **Release**. Events and timers at or below the watermark are released in strict event-time order. At equal time, events go before timers.
7. **Evaluate**. A per-shard cache maps `event.Type` to the indexes of rules that can react to it. For each relevant rule, the shard advances the NFA runs (sequence rules) or updates the pane ring (aggregate rules).
8. **Emit**. On a match, suppression is checked, emit expressions are evaluated, and up to 32 evidence events are attached. The `Alert` is pushed on the alert channel.
9. **Deliver** (`internal/sink`). The dispatcher copies each alert into every sink's own bounded queue. A slow sink drops only its own overflow, which is counted, and never blocks the engine.

### 3.3 Startup and shutdown sequence

```
start ─▶ load config (env ◀ flags) ─▶ compile rules ─▶ start engine (MUTED)
      ─▶ replay WAL into engine ─▶ Flush (release reorder buffers while muted)
      ─▶ UNMUTE ─▶ open WAL for append (truncate torn tail) ─▶ start sinks
      ─▶ start HTTP + TCP listeners ─▶ /readyz = 200
SIGHUP ─▶ recompile rules from disk ─▶ atomic swap (state of unchanged rules preserved)
SIGTERM/SIGINT ─▶ /readyz = 503 ─▶ HTTP graceful shutdown (in-flight requests finish)
      ─▶ close TCP ─▶ engine.Close (drains shard queues) ─▶ dispatcher drains sinks
      ─▶ WAL flush + fsync + close ─▶ exit
```

---

## 4. Concurrency model

| Component | Goroutines | Synchronisation |
|---|---|---|
| HTTP handlers | 1 per request (net/http) | none on the hot path; `Ingestor` mutex only when the WAL is on |
| TCP connections | 1 reader per connection | batches up to `BatchSize` lines per `Admit` |
| Shards | exactly `Shards` (default `GOMAXPROCS`) | **none**: each shard owns its state exclusively |
| Shard input | — | Vyukov bounded MPMC ring: per-cell sequence numbers + CAS on head/tail, cache-line padded |
| Parking | — | "doorbell" channel (cap 1) only signalled when a consumer has announced it is parked, so producers pay no channel cost while shards are busy |
| Control messages | — | `Sync`, `Advance`, `Flush` are items in the same ring, so they are ordered with events; each carries a `done` channel |
| Rule swap | — | `atomic.Pointer[Ruleset]`; each shard migrates at its next loop iteration |
| Alerts | 1 dispatcher + 1 worker per sink | buffered channels |
| WAL | callers + 1 fsync ticker (interval mode) | one mutex per batch (group commit) |
| Metrics | scrape-time | atomics; registry mutex only on registration and scrape |

**Why shard-per-core instead of a shared concurrent map?**
All per-key state (NFA runs, windows, timers, suppression) is touched by exactly one goroutine. That removes lock contention and cache-line ping-pong on the hot path, makes the per-key processing order deterministic, and lets the timer heap, reorder heap and LRU list be plain data structures. The cost is possible load imbalance when one key is extremely hot. §21 covers that trade-off.

**Ring algorithm.** Each cell stores `seq`. A producer at position `p` may write when `cell.seq == p`. It CASes `tail` from `p` to `p+1`, writes the value, and publishes with `seq = p+1`. A consumer may read when `cell.seq == p+1`. It CASes `head`, reads, clears the slot so the GC can reclaim it, and releases with `seq = p + capacity`. `PopBatch` drains many cells per wake-up, which amortises signalling. The stress test in `ring_test.go` checks exactly-once delivery and per-producer FIFO order with 4 producers and 4 consumers.

---

## 5. Event-time semantics: watermarks, lateness, ordering

### 5.1 Definitions

* **Event time**: the `ts` carried by the event (Unix ns internally).
* **Watermark** (per shard): `W = max(event time seen) − AllowedLateness`. It is the shard's promise that no event older than `W` will be evaluated from now on.
* **Late event**: one with `ts < W` on arrival. It is dropped and counted in `tempora_events_late_total`.

### 5.2 Guarantees

1. **Deterministic ordering.** Released events are processed in `(ts, seq)` order. Timers (sequence deadlines, absence deadlines, window reclamation) fire in deadline order, interleaved with events.
2. **Events before timers at equal time.** An event at time `t` is processed before any timer with deadline ≥ `t`. So a heartbeat *exactly* at an absence deadline still cancels the alert (`TestAbsenceHeartbeatExactlyAtDeadline`).
3. **Reorder invariance.** Delivering the same set of events in any order whose disorder stays within `AllowedLateness` produces **identical alerts** (`TestDeterminismUnderReordering`: 4 000 events, 3 shards, 3 random bounded permutations).
4. **Fast path.** With `AllowedLateness = 0` the reorder heap is skipped completely. Events are processed on arrival, and events with equal timestamps are *not* late.

### 5.3 Advancing time without traffic

Absence rules need time to move forward even when nothing arrives. Three mechanisms do this:

* **Idle advance** (`TEMPORA_IDLE_ADVANCE`, default 5 s). If a shard has received nothing for that long, its watermark follows the wall clock (`now − lateness`).
* **Explicit punctuation**: `POST /v1/advance {"ts": ...}` or `{"now": true}`. Use this when replaying historical data or when producers send their own heartbeats.
* **Reorder overflow.** If a shard buffers more than `MaxReorder` (65 536) events, the oldest is force-released and `tempora_reorder_forced_total` is incremented. This bounds memory when one producer's clock runs far ahead.

### 5.4 Choosing `AllowedLateness`

| Value | Effect |
|---|---|
| `0` | Lowest latency and no buffering, but any regression in time is dropped. Use for single ordered producers. |
| `500ms – 2s` (default 2 s) | Absorbs typical batching and network jitter. Alerts are delayed by at most the lateness. |
| `> 10s` | Tolerates badly skewed producers, but alert latency and buffered memory grow proportionally. |

Monitor `tempora_events_late_total / tempora_events_processed_total`. A sustained rate above 1 % means lateness is too small or producer clocks are wrong (§18).

---

## 6. The event model and wire formats

### 6.1 Wire format (JSON)

```json
{
  "type":   "auth.failure",           // required, ≤128 bytes; dotted names by convention
  "key":    "203.0.113.9",            // partition key (IP, host, service, user…); ≤512 bytes
  "ts":     "2026-01-02T15:04:05.25Z",// optional; RFC3339(Nano) string OR integer epoch
  "source": "sshd",                   // optional producer id
  "attrs":  { "user": "root", "port": 22, "ratio": 0.5, "ok": false, "note": null }
}
```

* **`key` is the correlation scope.** Rules only correlate events that share a key. Pick the entity whose behaviour you are modelling. For the same underlying data you might use the source IP for brute force, the service name for latency SLOs, or the host for process chains.
* **Timestamps.** Strings must be RFC3339. An integer epoch is interpreted by magnitude: `< 1e11` seconds, `< 1e14` milliseconds, `< 1e17` microseconds, otherwise nanoseconds. A missing `ts` is stamped with the ingest wall clock.
* **Attribute values** must be scalars: string, integer, float, boolean or null. Nested objects and arrays are rejected with a per-event error.

### 6.2 Internal representation

```go
type Event struct {
    Seq      uint64  // assigned at admission; total order tie-breaker; WAL position
    Time     int64   // Unix ns
    Type, Key, Source string
    Attrs    []Attr  // sorted by name → O(log n) lookup, canonical encoding
    Ingested int64   // wall clock at admission (process-local, for latency metrics)
}
type Value struct { S string; N uint64; K Kind } // 32-byte tagged union
```

Numbers and booleans share one 64-bit word. Floats are stored as IEEE-754 bits. Once admitted, an event is **immutable**, so shards share `*Event` pointers between NFA runs, evidence lists and alerts without copying.

Reserved pseudo-fields usable in rules: `type`, `key`, `source`, `ts`.

### 6.3 Admission limits

| Limit | Value | Error |
|---|---|---|
| attributes per event | 64 | `too many attributes` |
| attribute name length | 128 | `invalid attribute name` |
| string attribute length | 4 096 | `attribute string too long` |
| type length | 128 | `type too long` |
| key length | 512 | `key too long` |
| encoded line (TCP / NDJSON) | 64 KiB | line discarded, counted invalid |
| HTTP body | `TEMPORA_MAX_BODY_BYTES` (8 MiB) | `413 Request Entity Too Large` |

Duplicate attribute names are rejected. Attributes are sorted during normalisation.

### 6.4 Binary codec (WAL records)

```
version:u8=1 | seq:uvarint | time:zigzag-varint | type | key | source | nattrs:uvarint |
  { name | kind:u8 | payload }*
strings = uvarint length + bytes; int = zigzag varint; float = 8 bytes LE; bool = u8 (0|1)
```

The decoder is **canonical**. It rejects overlong varints, booleans other than 0 or 1, unsorted or duplicate attribute names, and trailing bytes. So every accepted byte string maps to exactly one event, and re-encoding yields identical bytes. The fuzzer (`FuzzDecodeBinary`) enforces this and found the overlong-varint case during development; the input is kept as a regression seed in `internal/event/testdata/fuzz/`.

---

## 7. Tempora Correlation Language (TCL) — full reference

Rules live in `*.tcl` files. Every file in the rules directory is compiled, in lexical order, into one immutable `Ruleset`. Each file is also compiled on its own first, so error messages name the file and position: `rules/x.tcl:4:23: invalid regex: ...`.

### 7.1 Lexical elements

| Element | Syntax |
|---|---|
| Comments | `# …`, `// …`, `/* … */` |
| Identifiers | `[A-Za-z_][A-Za-z0-9_]*` |
| Strings | `"…"` or `'…'`, escapes `\n \t \r \\ \" \'` (unknown escapes kept verbatim, useful in regexes) |
| Integers / floats | `42`, `1_000_000`, `3.25`, `1e-3` |
| Durations | `500ms`, `1.5s`, `2m`, `1h`, `1d`, `10us`, `100ns` |
| Inside expressions, a duration literal evaluates to **milliseconds** (`500ms` → `500.0`) |

### 7.2 Rule structure

```tcl
rule <name> {
  severity    info | low | medium | high | critical      # default medium
  description "free text"
  tags        ["mitre:T1110", "auth"]
  suppress    <duration>        # re-alert suppression per (rule, key[, group])
  # --- exactly one of the two bodies below ---
  # (a) sequence rule
  within      <duration>        # required: max span from first to last event
  max_runs    <int>             # partial matches kept per key (default 64, max 4096)
  sequence { <step> <step> ... }
  # (b) aggregate rule
  aggregate over <duration> [step <duration>]
  from   <types>
  where  <expr>                 # optional pre-filter (no aggregates)
  by     <expr>                 # optional sub-grouping inside the key
  having <expr>                 # required, must reference ≥1 aggregate
  # --- both kinds ---
  emit { name = <expr>, name = <expr> ... }   # alert payload fields (≤32)
}
```

Each clause may appear at most once. Unknown clauses, duplicate clauses, mixed sequence/aggregate clauses, and duplicate rule names are all compile errors.

### 7.3 Sequence steps

```tcl
sequence {
  alias: <types> [quantifier] [where <expr>]     # positive step
  !alias: <types> [where <expr>]                 # negated step (also: not alias: ...)
}
```

**Types**

| Form | Matches |
|---|---|
| `auth.failure` | exactly that type |
| `auth.*` | any type starting with `auth.` |
| `"proc.exec"` / `"net.*"` | quoted forms of the above |
| `(auth.failure \| auth.lockout)` | any of the alternatives (`\|` or `,`) |
| `*` | every type |

**Quantifiers** (positive steps only)

| Syntax | Meaning |
|---|---|
| *(none)* | exactly 1 |
| `+` | 1 or more |
| `[n]` | exactly n (sliding: the most recent n are kept) |
| `[n:]` | at least n |
| `[n:m]` | between n and m |

The minimum must be ≥ 1. For "zero occurrences", use a negated step.

**Negated steps** (guards) must not be the first step. A guard applies *after* the preceding positive step is satisfied and *before* the next positive step matches. If a matching event arrives in that interval, the partial match is killed. A rule whose **last** step is negated is an **absence rule**: it completes when `within` elapses after the start and no guard event has arrived.

**Cross-step references.** In a step's `where`, you may reference earlier (already bound) positive aliases: `ok: auth.success where user == fail.user`. `alias.field` resolves to the field of the **last** event bound to that step. Referencing a later alias, a negated alias, or a bare alias used as a value is a compile error.

### 7.4 Expressions

Precedence, lowest to highest:

| Level | Operators |
|---|---|
| or | `\|\|`, `or` |
| and | `&&`, `and` |
| not | `!x`, `not x` |
| comparison | `== != < <= > >=`, `in [..]`, `not in [..]` (non-associative: `a < b < c` is an error) |
| additive | `+ -` (`+` concatenates when either side is a string) |
| multiplicative | `* / %` |
| unary | `-x` |
| primary | literal, field, `alias.field`, `fn(args)`, `( expr )`, `[list]` (only after `in`) |

**Semantics**

* Missing fields evaluate to `null`. Comparing `null` with `<`/`>` is `false`, `null == null` is `true`, and arithmetic on `null` yields `null`. A rule therefore never crashes on a missing attribute.
* Integers and floats compare and add with numeric promotion. `int / int` produces a float, and division or modulo by zero yields `null`.
* Truthiness: `null`, `false`, `0`, `0.0`, `NaN` and `""` are false.
* Constant subexpressions are folded at compile time. `in` over a list of literals compiles to a hash-set lookup.

**Field names:** `status`, `latency_ms`, the pseudo-fields `type`/`key`/`source`/`ts`, dotted attribute names (`http.method`, when the prefix is not a step alias), and, in aggregate `emit`/`having`, `group`, `window_start` and `window_end`.

**Scalar functions**

| Function | Description |
|---|---|
| `lower(s)`, `upper(s)`, `trim(s)` | string case / whitespace |
| `len(s)` | string length in bytes (null for non-strings) |
| `contains(s, sub)`, `starts_with(s, p)`, `ends_with(s, p)` | substring tests |
| `matches(s, "regex")` | RE2 regular expression; the pattern must be a literal and is compiled once at rule compile time |
| `cidr(ip, "10.0.0.0/8")` | IPv4/IPv6 prefix membership (literal prefix, parsed once) |
| `str(x)`, `int(x)`, `float(x)` | conversions (`int("42")` → 42) |
| `abs(x)`, `floor(x)`, `ceil(x)` | numeric |
| `min(a, b, ...)`, `max(a, b, ...)` | scalar min/max (≥ 2 args) |
| `coalesce(a, b, ...)` | first non-null |
| `if(cond, a, b)` | conditional |
| `exists(x)`, `is_null(x)` | presence tests |
| `count(alias)` | *(sequence rules)* number of events bound to a step |
| `elapsed_ms()` | *(sequence rules)* current event time − run start |

**Aggregate functions** (only in `having` and `emit` of aggregate rules)

| Function | Implementation | Accuracy |
|---|---|---|
| `count()` | exact counter per pane | exact |
| `rate()` | `count() / over` in events/second | exact |
| `sum(x)`, `avg(x)`, `min(x)`, `max(x)` | per-pane running sums / extremes | exact |
| `distinct(x)` | HyperLogLog, p = 10 (1 KiB per pane) | ~3.25 % std. error |
| `p50(x)`, `p90(x)`, `p95(x)`, `p99(x)`, `p999(x)`, `quantile(x, q)` | DDSketch, α = 1 %, ≤ 512 buckets | ≤ 1 % *relative* error |

Identical aggregate calls are de-duplicated: `p99(latency)` used in both `having` and `emit` is computed once. Aggregates are evaluated **lazily** and memoised per evaluation, so `count() >= 20 and p99(x) > 750` skips the quantile merge whenever the count check fails.

### 7.5 Examples

**Brute force with negation and a cross-step predicate:**

```tcl
rule brute_force_then_success {
  severity critical
  within 2m
  suppress 10m
  max_runs 8
  sequence {
    fail: auth.failure[5:]
    !reset: auth.password_reset
    ok: auth.success where user == fail.user
  }
  emit { user = ok.user, failures = count(fail), elapsed_ms = elapsed_ms() }
}
```

**Absence:**

```tcl
rule missing_heartbeat {
  within 30s
  sequence { start: service.start  !hb: service.heartbeat }
  emit { version = start.version }
}
```

**Grouped aggregate with a computed ratio:**

```tcl
rule error_burst {
  aggregate over 1m step 5s
  from http.request
  by path
  having count() >= 50 and sum(if(status >= 500, 1, 0)) / count() > 0.2
  emit { requests = count(), errors = sum(if(status >= 500, 1, 0)), path = group }
}
```

**Multi-stage intrusion chain:**

```tcl
rule webshell_chain {
  within 30s
  sequence {
    req:  http.request  where starts_with(path, "/admin") or contains(path, "..")
    proc: process.start where parent in ["nginx", "httpd", "php-fpm"] and name in ["sh", "bash", "dash"]
    conn: net.connect   where not cidr(dst_ip, "10.0.0.0/8") and not cidr(dst_ip, "192.168.0.0/16")
  }
  emit { shell = proc.name, dst = conn.dst_ip, path = req.path }
}
```

### 7.6 Compile-time validation (what the compiler rejects)

Validation rejects a rule before it can misbehave at runtime. It checks for:

* a missing `within` in a sequence rule (unbounded state), or a missing `from`/`having` in an aggregate rule
* a `having` that references no aggregate, or an aggregate used in `where`, in a sequence rule, or nested inside another aggregate
* a leading negated step, quantifiers on negated steps, `[0:]`, or `[5:2]`
* references to a later, negated or unknown alias, or an alias used as a value
* invalid regexes or CIDR prefixes, or non-literal regex/CIDR/quantile arguments
* `quantile(x, q)` with q ∉ [0, 1]
* `step > over`, or more than 1 024 window panes; more than 16 steps; `max_runs` ∉ [1, 4096]
* unknown functions, wrong arity, chained comparisons, duplicate emit fields, unknown severity

Errors carry `line:column`. `POST /v1/rules/validate` and `tempora check` expose the same compiler.

---

## 8. How rules are evaluated (NFA and window internals)

### 8.1 Compilation

`lexer → parser (AST) → validation → closure compilation`. Every expression compiles into a tree of Go closures, `func(*Ctx) event.Value`. Evaluation involves no interpretation loop, no reflection and no allocation for field access, comparison, or numeric arithmetic. A three-clause predicate with a list lookup and a CIDR test evaluates in **~129 ns with 0 allocations** (`BenchmarkPredicate`).

A sequence rule compiles to a plan:

* `Positives[]`: the positive steps in order.
* `Guards[i]`: the negated steps active while a run sits at positive stage *i*.
* `IsAbsence()`: true when the last positive stage has guards after it.

### 8.2 NFA runs (sequence rules)

Each **run** is one partial match for one key: `(stage, count, bound[], counts[], start, deadline, evidence)`. For every relevant event, per run:

1. If the event is past `run.deadline`, ignore it; the deadline timer will reap the run.
2. If the event matches a **guard** of the current stage, the **run is killed**. Negation takes precedence.
3. If the current stage is satisfied (`count ≥ Min`) and the event matches the **next** stage, advance.
4. Otherwise, if the event matches the **current** stage and `count < Max`, absorb it.
5. If the last stage is satisfied and the rule is not an absence rule, **complete**.

A new run is started only if no existing run *absorbed the event into stage 0*. This is **skip-till-next-match** semantics:

* `A A B` with pattern `a: A b: B` gives 2 matches (each `A` starts its own run).
* `F F F F F S` with `fail: F[5:] ok: S` gives 1 match with `count(fail) = 5`, not 5 overlapping matches.

**Sliding stage 0.** When stage 0 has a quantifier, the run keeps a ring of stage-0 timestamps. When the run's deadline passes while it is still in stage 0, the run does not die. It *slides*: the oldest failure is dropped and the deadline is recomputed from the new oldest one. This gives exact "N events within T" semantics over a sliding window with a single run, not one run per event. `TestSequenceSlidingWindowKeepsRecentFailures` pins this behaviour.

**Absence.** A run that reaches its final positive stage in an absence rule is kept until its deadline timer fires. If no guard event killed it by then, it emits `kind: "absence"`, with `event_time = deadline`.

**Bounds.** At most `max_runs` runs per (key, rule); when the cap is hit the oldest run is evicted (`tempora_run_evictions_total`). Evidence is capped at 32 events per alert. The stage-0 timestamp ring is capped at `max(64, 4·Min)` and never exceeds 100 000.

### 8.3 Timers

Each shard has **one indexed 4-ary min-heap** of `(deadline, payload)` with a map from timer id to heap index. That gives O(log n) `Schedule`, `Cancel` and `Reset`, and FIFO order among equal deadlines. Timers are used for run deadlines and aggregate-group reclamation. A timing wheel was rejected because event time can jump arbitrarily (replay, `Advance`), and a wheel would cost O(gap) on such jumps.

### 8.4 Sliding windows (aggregate rules)

Each (key, rule, group) owns a ring of `NumBuckets = ceil(over / step)` **panes**. Pane *i* covers `[i·step, (i+1)·step)`. Each pane stores, per aggregate spec: `count`, `n`, `sum`, `min`, `max`, plus a lazily allocated HLL (for `distinct`) or DDSketch (for quantiles).

* **Ingest** is O(#aggregates). When a pane's epoch changes, it is reset in place and its sketches reused, so there is no allocation in the steady state.
* **Evaluate** on every event (continuous evaluation). The window is the `NumBuckets` panes ending at the current pane. Aggregates are computed lazily by merging those panes into per-shard scratch sketches.
* **Default step** = `over / 12`, with a minimum of 1 ms.
* **Default suppression** for aggregate rules = one window length, so a sustained breach produces one alert per window rather than one per event.
* **Group cap**: 1 024 groups per (key, rule). Beyond that, the group idle the longest is evicted.
* **Reclamation**: once a group's newest pane has left every future window, its timer drops the group.

### 8.5 Sketch algorithms

* **DDSketch** (Masson, Rim & Lee, VLDB 2019). A value *x* maps to bucket `ceil(log_γ x)` with `γ = (1+α)/(1−α)`. Returning the bucket's relative midpoint guarantees relative error ≤ α for every quantile. Tempora uses dense offset-indexed stores for positive and negative values plus a zero bucket, with **lowest-bucket collapsing** when the 512-bucket budget is exceeded, which preserves the high quantiles that alerting cares about. Merge is a single-pass range widen plus a dense add. That optimisation took end-to-end throughput from ~197 k to ~900 k events/s on the latency-heavy rule mix (§12.3).
* **HyperLogLog**, dense, with `2^p` one-byte registers, the standard α_m bias constant, and linear counting in the small range. It merges by register-wise max.
* **Hash**: a wyhash-style multiply-mix over 8-byte lanes with a MurmurHash3 finaliser. It is used for sharding and HLL registers. A χ² test in `sketch_test.go` guards its distribution.

### 8.6 Hot reload and state migration

`PUT /v1/rules`, `POST /v1/rules/reload`, and `SIGHUP` all compile a new `Ruleset` and publish it through an atomic pointer. Each shard notices on its next iteration and migrates key state by matching on **(name, fingerprint)**:

* **Unchanged rule** (same name, same source text): runs, windows and timers are **kept**, re-indexed to the new position.
* **Modified or removed rule**: its state is dropped and its timers cancelled.
* **New rule**: starts empty.

A compile error leaves the running ruleset untouched. The API returns `422` with a positioned message; SIGHUP logs an error.

### 8.7 Suppression

`suppress <d>` stores `until = at + d` per (rule, group) in the key's state. Matches before `until` are counted in `tempora_alerts_suppressed_total` and not emitted. The suppression map is pruned opportunistically, so it cannot grow without bound.

---

## 9. Bundled rule pack

| File | Rule | Kind | Detects |
|---|---|---|---|
| `rules/security.tcl` | `brute_force_then_success` | sequence | ≥ 5 auth failures then a success for the same user and source within 2 min, with no password reset in between (MITRE T1110) |
| | `port_scan` | aggregate | one external source touching ≥ 25 distinct TCP ports in 10 s (T1046); `where not cidr(key, "10.0.0.0/8")` excludes internal scanners |
| | `webshell_chain` | sequence | admin-path/traversal request → shell spawned by a web server → outbound connection to a non-RFC1918 address within 30 s (T1505.003) |
| `rules/reliability.tcl` | `latency_slo_breach` | aggregate | per-service p99 latency > 750 ms over 30 s with ≥ 20 requests |
| | `error_burst` | aggregate (by `path`) | 5xx ratio > 20 % over 1 min with ≥ 50 requests |
| | `missing_heartbeat` | absence | `service.start` with no `service.heartbeat` for 30 s |
| | `crash_loop` | sequence | ≥ 3 restarts in 5 min |

The generator in `internal/loadgen` injects four scenario families with ground truth. `TestDetectionRecall` asserts that each is detected exactly once per injected key, and that background keys never trigger the security rules.

---

## 10. Durability: the write-ahead log and crash recovery

### 10.1 On-disk layout

```
<wal-dir>/
  00000000000000000001.wal     # name = first sequence number the segment may contain
  00000000000004194305.wal
  ...
record := length:u32le | crc32c(payload):u32le | payload (event binary codec)
```

* **Group commit.** One mutex acquisition per ingest batch. Records are written through a 256 KiB buffered writer and flushed per batch. Measured: **512 MB/s, 0 allocs/op** for 256-event batches (`BenchmarkAppendBatch`).
* **Rotation** at `TEMPORA_WAL_SEGMENT_BYTES` (64 MiB). The old segment is fsynced before the new one is created, and the directory is fsynced after creation.
* **Retention.** At most `TEMPORA_WAL_RETAIN` closed segments are kept (default 16 ≈ 1 GiB). `TruncateBefore(seq)` is available to embedders.

### 10.2 Sync modes

| `TEMPORA_WAL_SYNC` | Guarantee | Cost |
|---|---|---|
| `none` | survives process crash (data is in the page cache), not power loss | fastest |
| `interval` (default) | loses at most `TEMPORA_WAL_SYNC_EVERY` (200 ms) on power loss | one fsync per interval |
| `always` | every acknowledged batch is on stable storage | one fsync per batch |

### 10.3 Recovery procedure

1. **Scan** every segment in order. Each record's length and CRC32C are verified. The first incomplete or corrupt record ends that segment; this can only be a torn write from a crash.
2. **Replay** every valid event into the engine while it is **muted**. Alerts are re-derived, which rebuilds suppression state, but they are counted in `muted` and not delivered.
3. **Flush** shard reorder buffers while still muted. The last replayed events would otherwise sit in the reorder heap and fire *after* unmuting, re-delivering a pre-crash alert. `TestReplayDoesNotRedeliverBufferedAlerts` reproduces that bug: it fails without `Flush`.
4. **Unmute**, then `Open` the WAL for appends. `Open` **truncates the torn tail**, so new records never follow garbage, and the sequence counter continues from the last valid record.

`TestTornTailRecovery` cuts the final record at every seventh byte offset and checks that replay returns exactly the complete records and that later appends stay readable. `TestCrashRecoveryFromWAL` confirms end to end that a partial brute-force sequence survives a restart and completes with one post-restart event.

**Semantics:** detection state is *exactly* reconstructed from the retained log. Alert delivery is **at-least-once** across a crash that lands between a match and a sink write; the engine does not store sink acknowledgements. Alert `id`s are deterministic (`rule-seq-eventtime`), so downstream systems can de-duplicate.

---

## 11. Alert delivery (sinks)

| Sink | Enabled by | Behaviour |
|---|---|---|
| **stdout** JSON lines | `TEMPORA_ALERT_LOG=stdout` (default) | one object per line; logs go to **stderr**, so stdout is a clean alert stream |
| **file** JSON lines | `TEMPORA_ALERT_LOG=/path/alerts.jsonl` | append mode; parent directories created |
| **webhook** | `TEMPORA_WEBHOOK_URL` | POST JSON; see below |
| **hub** | always | ring buffer of the last `TEMPORA_HUB_SIZE` alerts for `/v1/alerts`; fan-out to SSE subscribers (slow subscribers lose alerts rather than slowing the hub) |

**Isolation.** Every sink has its own bounded queue (`TEMPORA_SINK_QUEUE`) and worker goroutine. When a queue is full, *that sink* drops the alert (`tempora_sink_dropped_total{sink=...}`). The engine and the other sinks are unaffected (`TestDispatcherIsolatesSlowSinks`).

**Webhook details**

* Headers: `Content-Type: application/json`, `X-Tempora-Rule`, `X-Tempora-Alert-Id`, `X-Tempora-Timestamp`, and, when a secret is set, `X-Tempora-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>`.
* Retries: up to 4, exponential backoff with **full jitter** (base 200 ms, cap 10 s). Only transport errors, `429`, and `5xx` are retried; other `4xx` codes are not.
* **Circuit breaker**: opens after 5 consecutive failed deliveries, stays open for 30 s, then allows one half-open probe.

Verifying a signature (Python):

```python
import hmac, hashlib
def verify(secret: bytes, ts: str, body: bytes, header: str) -> bool:
    mac = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + mac, header)
```

Reject requests whose `X-Tempora-Timestamp` is more than a few minutes old to prevent replay.

**Alert schema**

| Field | Description |
|---|---|
| `id` | deterministic id `rule-<seq base36>-<eventtime base36>` |
| `rule`, `fingerprint`, `kind` | `kind` ∈ `sequence`, `absence`, `aggregate` |
| `severity`, `description`, `tags` | copied from the rule |
| `key`, `group` | partition key; `by` group value for aggregates |
| `event_time` | when the match was established in event time (trigger event, absence deadline, or current event for aggregates) |
| `detected_at` | wall clock of detection |
| `window.start/end` | aggregate window |
| `fields` | `emit` values, plus `duration_ms` (sequence) or `window_count` (aggregate) |
| `evidence` | up to 32 (sequence) / 8 (aggregate) contributing events |
| `latency_us` | wall-clock latency from ingest of the trigger event to detection (includes the time spent waiting for the watermark) |
| `shard` | shard that produced the alert |

---

## 12. Benchmarks & performance

All numbers were measured on the development sandbox: **2 vCPU Intel Xeon @ 2.50 GHz, ~1 GB RAM, Go 1.23.4, linux/amd64**. They are a lower bound; throughput scales roughly with cores because shards share nothing. Reproduce them with `make bench` and `make bench-e2e`.

### 12.1 End-to-end engine benchmark (`tempora-bench`)

Workload: the 7 bundled rules, 50 000 background keys, 1 000 136 events. The mix is 55 % HTTP requests (log-normal latency), 20 % auth events, 20 % flows and 5 % heartbeats, with ~0.1 % attack scenarios injected. Allowed lateness is 500 ms and event-time jitter 200 ms. Events are pre-generated, so generation cost is excluded, and partitioned so each producer owns disjoint shards.

| Configuration | Throughput | Eval p50 | Eval p99 | Eval p99.9 | Allocs/event | GC cycles | Alerts / injected |
|---|---|---|---|---|---|---|---|
| 2 producers, 2 shards | **653 852 ev/s** | 1.58 µs | 7.87 µs | 22.2 µs | 0.05 | 0 | 120 / 120 |
| 2 producers, 2 shards (rerun) | 710 947 ev/s | 1.53 µs | 6.56 µs | 15.6 µs | 0.05 | 0 | 120 / 120 |
| 1 producer, 2 shards | **774 710 ev/s** | 1.52 µs | 6.46 µs | 14.5 µs | — | — | 120 / 120 |
| in-order input (`-lateness 0 -jitter 0`) | **1 120 177 ev/s** | 1.26 µs | 6.45 µs | 14.9 µs | — | — | 123 / 123 |

* **Eval latency** is the time for a shard to evaluate one released event against every relevant rule, sampled 1-in-64.
* **Ingest→alert latency** in the in-process benchmark is dominated by the configured watermark delay and the queueing of a pre-loaded burst of 1 M events. It is *not* evaluation cost. In steady state it is ≈ `AllowedLateness` plus microseconds.
* 2 producers is not faster than 1 on 2 vCPUs because producers and shards compete for the same two cores.

### 12.2 Micro-benchmarks (`make bench`)

| Benchmark | ns/op | allocs/op | What it measures |
|---|---|---|---|
| `HLLAdd` | 5.6 | 0 | HyperLogLog insert (pre-hashed) |
| `DDSketchAdd` | 29.3 | 0 | quantile sketch insert |
| `AttrLookup` | 40.4 | 0 | binary-search attribute access (12 attrs) |
| `DDSketchMerge` | 59.4 | 0 | merge of a 1 000-sample sketch (window evaluation) |
| `PushPopMPMC` | 64.0 | 0 | ring push, parallel producers |
| `PushPopSPSC` | 78.6 | 0 | ring push + batched pop, 1:1 |
| `BinaryEncode` | 125.8 | 0 | WAL record encode |
| `Predicate` | 129.4 | 0 | 3-clause compiled predicate (`>=`, `in`, `cidr`) |
| `HistogramObserve` | 142.4 | 0 | lock-free metric histogram, parallel |
| `TimersScheduleCancel` | 519 | 0 | indexed timer heap with 1 024 live timers |
| `AppendBatch` | 38 498 (256 events) | 0 | WAL group commit, **512 MB/s** |

### 12.3 Profiling-driven optimisations (development log)

1. **Initial profile.** `DDSketch.Merge` accounted for 50 % of CPU because it re-inserted buckets one by one through `add()`, and `add()` regrew the slice for each index below the offset. Replacing it with a single range widen plus a dense add (`store.mergeFrom` / `reshape`) raised throughput from **196 709 to 902 232 ev/s (4.6×)**. p99.9 eval latency fell from 476 µs to 15 µs, and GC cycles during the run fell from 6 to 0.
2. **Lazy, memoised aggregates.** `having count() >= 20 and p99(x) > 750` no longer merges sketches for windows that fail the cheap count check.
3. **Allocation-free aggregate context.** The lazy aggregate callback is a pre-bound method value on the shard, not a per-event closure.
4. **Relevance index.** A per-shard cache from type to rule indexes means irrelevant events cost one map lookup. Events that are relevant but cannot *start* a run (e.g. `auth.success` with no pending failures) allocate no key state (`TestIrrelevantEventsAllocateNoState`).

### 12.4 How to benchmark your own workload

```bash
bin/tempora-bench -events 5000000 -producers 4 -shards 8 -keys 200000 \
                  -lateness 1s -jitter 300ms -inject 0.002 -rules ./rules
bin/tempora-bench ... -json > result.json                # machine-readable
bin/tempora-bench ... -cpuprofile cpu.prof -memprofile mem.prof
go tool pprof -http :7070 bin/tempora-bench cpu.prof
```

| Flag | Default | Meaning |
|---|---|---|
| `-events` | 1 000 000 | events to generate (in-process mode) |
| `-producers` | GOMAXPROCS | concurrent submitters (or TCP connections in network mode) |
| `-shards` | 0 (= GOMAXPROCS) | engine shards |
| `-keys` | 50 000 | background key cardinality |
| `-rules` | `rules` | rule file or directory |
| `-lateness` / `-jitter` | 500 ms / 200 ms | engine lateness / generator disorder |
| `-inject` | 0.001 | fraction of scenario events |
| `-batch` | 256 | submit batch size |
| `-target`, `-rate`, `-duration` | — | network mode against a running server |
| `-json`, `-cpuprofile`, `-memprofile` | — | output / profiling |

---

## 13. Memory profile and bounded state

### 13.1 Per-object costs (approximate, 64-bit)

| Object | Size |
|---|---|
| `Value` | 32 B |
| `Event` | ~90 B header + 48 B per attribute + string bytes |
| Key state | ~120 B + per-rule slots + suppression map |
| Sequence run | ~150 B + 8 B × steps × 2 + 8 B × stage-0 ring (≤ 64 by default) |
| Aggregate group | `NumBuckets` × (per-aggregate cell 48 B + HLL 1 KiB when `distinct` is used + DDSketch ≤ 4 KiB when quantiles are used) |
| Timer | ~48 B heap slot + map entry |

In the 1 M-event benchmark, live heap was **296 MiB**. The retained engine state averaged **~3.7 KB per live key**, dominated by 30-pane latency windows holding DDSketches. Most of the heap figure is the 1 M pre-generated input events kept alive by the benchmark harness itself.

### 13.2 Every structure is bounded

| Resource | Bound | Overflow behaviour | Metric |
|---|---|---|---|
| Keys per shard | `MaxKeysPerShard` (262 144) | LRU eviction | `tempora_key_evictions_total` |
| Idle keys | `KeyTTL` (10 min event time, auto-raised to 2 × longest rule horizon) | reclaimed by an incremental sweep (≤ 1 024 keys per iteration) | `tempora_key_expired_total` |
| Runs per key per rule | `max_runs` (64) | oldest evicted | `tempora_run_evictions_total` |
| Groups per key per rule | 1 024 | idlest evicted | `tempora_run_evictions_total` |
| Panes per window | 1 024 (compile time) | compile error | — |
| DDSketch buckets | 512 per sign | lowest collapsed | — |
| Reorder buffer | 65 536 per shard | oldest force-released | `tempora_reorder_forced_total` |
| Shard queue | `RingSize` (16 384) | block or 429 | `tempora_events_blocked_total`, `tempora_events_backpressure_total` |
| Sink queue | `SinkQueue` (8 192) | drop for that sink | `tempora_sink_dropped_total` |
| Evidence | 32 / 8 events | oldest dropped | — |
| Relevance cache | 4 096 types | uncached lookups beyond | — |

Sizing rule of thumb: `memory ≈ live_keys × (Σ over rules of per-key state) + Shards × RingSize × 16 B + in-flight events`. With the bundled rules, 1 M live keys need roughly 4 GiB. Raise `MaxKeysPerShard` only with matching memory limits.

---

## 14. HTTP & TCP API reference

Base URL `http://<host>:8080`. All responses are JSON unless noted. When `TEMPORA_AUTH_TOKEN` is set, endpoints marked 🔒 require `Authorization: Bearer <token>`, compared in constant time. Read-only endpoints remain open; put them behind a network policy if necessary.

### `POST /v1/events` 🔒 — ingest

The body may be a single object, a JSON array, or NDJSON (one object per line; set `Content-Type: application/x-ndjson` or just send multiple lines).

| Status | Meaning |
|---|---|
| `202` | `{"accepted":N,"invalid":M,"rejected":0, "errors":[...first 20...]}`; partial success is still 202 |
| `400` | empty body, malformed JSON array, or every event invalid |
| `413` | body exceeds `TEMPORA_MAX_BODY_BYTES` |
| `429` | shard queue full with `DROP_ON_FULL=true`; `Retry-After: 1` |
| `503` | engine shutting down or WAL write failed |

### `POST /v1/advance` 🔒 — event-time punctuation

`{"ts":"2026-01-01T00:05:00Z"}`, `{"ts":1767225900}`, or `{"now":true}`. Raises every shard's watermark, releases buffered events, and fires due timers (absence rules). Returns `{"watermark": "..."}`.

### `GET /v1/alerts?limit=100&rule=<name>&key=<key>`

Newest first from the in-memory hub. `limit` must be in [1, 10000]. Returns `{"count":N,"alerts":[...]}`.

### `GET /v1/alerts/stream?rule=<name>` — Server-Sent Events

```
: connected

id: brute_force_then_success-6-dlnz772uo3k0
event: alert
data: {"id":"...","rule":"brute_force_then_success",...}

: heartbeat            (every 15 s)
```

`X-Accel-Buffering: no` is set, so it works behind nginx.

### `GET /v1/rules`

Returns the version, load time, and per rule: name, kind, severity, fingerprint, `within`/`over`, pane count, steps, the absence flag, the match count, and the full source text.

### `PUT /v1/rules` 🔒

Body: TCL source. Compiles and atomically replaces the **entire** ruleset. `200 {"version":V,"rules":N}` or `422 {"error":"compile failed","detail":"3:14: ..."}`.

### `POST /v1/rules/reload` 🔒

Recompiles from `TEMPORA_RULES` on disk. It is equivalent to `SIGHUP`, but returns the result.

### `POST /v1/rules/validate`

Compiles without applying. `200 {"valid":true,"rules":[...]}` or `422`. Use it in CI.

### `GET /v1/stats`

A full JSON snapshot: engine totals, per-shard stats (queue depth, processed, late, keys, runs, groups, timers, watermark…), ingest counters, per-rule match counts, memory and GC statistics, latency quantiles (`null` until sampled), sink stats, WAL stats, and TCP connection count.

### `GET /metrics`

Prometheus text exposition format 0.0.4 (§16).

### `GET /healthz`, `GET /readyz`

`healthz` returns 200 whenever the process serves HTTP. `readyz` returns 200 only after WAL replay has completed, and 503 during startup replay and during shutdown. Use `readyz` for load-balancer membership.

### `GET /debug/pprof/*`

Only exposed when `TEMPORA_PPROF=true`.

### TCP ingest (`:9090`)

Newline-delimited JSON with the same event format, one event per line. Fire-and-forget: there are no per-event responses. Invalid and overlong (> 64 KiB) lines are counted and skipped without closing the connection. Blank lines are ignored. Backpressure is TCP flow control: the reader stops reading while shards are saturated. Idle connections close after 5 minutes, and at most 4 096 concurrent connections are accepted.

```bash
cat events.ndjson | nc 127.0.0.1 9090
```

---

## 15. Configuration reference

Precedence: **defaults < environment (`TEMPORA_*`) < command-line flags**. All values are validated at startup, and invalid values abort with a combined error message. `.env.example` lists every variable.

| Environment variable | Flag | Default | Description |
|---|---|---|---|
| `TEMPORA_HTTP_ADDR` | `-http` | `:8080` | HTTP listen address |
| `TEMPORA_TCP_ADDR` | `-tcp` | `:9090` | TCP NDJSON ingest address (empty disables) |
| `TEMPORA_RULES` | `-rules` | `rules` | rule file or directory of `*.tcl` |
| `TEMPORA_SHARDS` | `-shards` | `0` (= GOMAXPROCS) | shard goroutines, 0–1024 |
| `TEMPORA_RING_SIZE` | `-ring-size` | `16384` | per-shard queue capacity (rounded up to a power of 2) |
| `TEMPORA_BATCH_SIZE` | `-batch-size` | `256` | shard drain batch and TCP ingest batch |
| `TEMPORA_ALLOWED_LATENESS` | `-lateness` | `2s` | out-of-order tolerance |
| `TEMPORA_IDLE_ADVANCE` | `-idle-advance` | `5s` | idle time before the watermark follows the wall clock (0 disables) |
| `TEMPORA_MAX_KEYS_PER_SHARD` | `-max-keys` | `262144` | LRU cap |
| `TEMPORA_KEY_TTL` | `-key-ttl` | `10m` | idle key reclamation (event time) |
| `TEMPORA_DROP_ON_FULL` | `-drop-on-full` | `false` | 429 instead of blocking when queues are full |
| `TEMPORA_WAL_DIR` | `-wal-dir` | *(empty = disabled)* | write-ahead log directory |
| `TEMPORA_WAL_SYNC` | `-wal-sync` | `interval` | `none` \| `interval` \| `always` |
| `TEMPORA_WAL_SYNC_EVERY` | `-wal-sync-every` | `200ms` | fsync period for `interval` |
| `TEMPORA_WAL_SEGMENT_BYTES` | `-wal-segment-bytes` | `67108864` | segment size (≥ 64 KiB) |
| `TEMPORA_WAL_RETAIN` | `-wal-retain` | `16` | closed segments kept (0 = unlimited) |
| `TEMPORA_REPLAY` | `-replay` | `true` | replay the WAL on startup |
| `TEMPORA_ALERT_LOG` | `-alert-log` | `stdout` | `stdout` \| file path \| empty |
| `TEMPORA_WEBHOOK_URL` | `-webhook` | — | alert webhook |
| `TEMPORA_WEBHOOK_SECRET` | `-webhook-secret` | — | HMAC signing secret |
| `TEMPORA_HUB_SIZE` | `-hub-size` | `2000` | alerts kept for `/v1/alerts` |
| `TEMPORA_SINK_QUEUE` | `-sink-queue` | `8192` | per-sink queue |
| `TEMPORA_MAX_BODY_BYTES` | `-max-body` | `8388608` | HTTP ingest body limit |
| `TEMPORA_AUTH_TOKEN` | `-auth-token` | — | bearer token for mutating endpoints |
| `TEMPORA_LOG_LEVEL` | `-log-level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `TEMPORA_LOG_FORMAT` | `-log-format` | `json` | `json` \| `text` (logs go to stderr) |
| `TEMPORA_SHUTDOWN_GRACE` | `-shutdown-grace` | `15s` | graceful shutdown timeout |
| `TEMPORA_PPROF` | `-pprof` | `false` | expose `/debug/pprof` |

**CLI subcommands**

```
tempora [flags]                 run the server
tempora check [paths...]        compile rule files/dirs, print rules; exit 1 on error (CI / pre-commit)
tempora probe [url]             HTTP readiness probe (default http://127.0.0.1:8080/readyz), for distroless health checks
tempora version                 print the build version (set via -ldflags)
```

---

## 16. Observability: metrics, logs, profiling

### 16.1 Prometheus metrics

| Metric | Type | Meaning |
|---|---|---|
| `tempora_events_processed_total` | counter | events evaluated by shards |
| `tempora_events_late_total` | counter | dropped behind the watermark |
| `tempora_events_backpressure_total` | counter | rejected (queue full, drop mode) |
| `tempora_events_blocked_total` | counter | submissions that waited for queue space |
| `tempora_ingest_accepted_total` / `_invalid_total` / `_rejected_total` | counter | ingest outcomes |
| `tempora_alerts_total` | counter | alerts produced (including muted during replay) |
| `tempora_alerts_suppressed_total` | counter | matches suppressed |
| `tempora_keys`, `tempora_runs`, `tempora_groups`, `tempora_timers` | gauge | live state |
| `tempora_reorder_buffered` | gauge | events awaiting the watermark |
| `tempora_reorder_forced_total` | counter | forced watermark advances |
| `tempora_key_evictions_total`, `tempora_key_expired_total`, `tempora_run_evictions_total` | counter | bounded-state pressure |
| `tempora_watermark_lag_seconds` | gauge | wall clock − minimum shard watermark |
| `tempora_rule_version` | gauge | active ruleset version |
| `tempora_shard_queue_depth{shard}`, `tempora_shard_processed_total{shard}` | gauge / counter | per-shard load (use to spot hot keys) |
| `tempora_eval_latency_seconds{quantile}` | gauge | sampled per-event evaluation latency |
| `tempora_alert_latency_seconds{quantile}` | gauge | ingest → alert latency |
| `tempora_wal_bytes`, `tempora_wal_segments`, `tempora_wal_records_total`, `tempora_wal_fsyncs_total` | mixed | WAL |
| `tempora_sink_delivered_total{sink}`, `_failed_total{sink}`, `_dropped_total{sink}` | counter | alert delivery |
| `tempora_go_goroutines`, `tempora_go_heap_inuse_bytes`, `tempora_uptime_seconds` | gauge | runtime |

`deploy/alerts.yml` ships operational alerting rules: backpressure, late-event ratio > 1 %, watermark stalled > 5 min, sink dropping, key evictions, and eval p99 > 1 ms.

### 16.2 Logs

`log/slog` structured logs go to **stderr** (JSON by default). Lifecycle events are logged: rules compiled, WAL replayed (records, segments, torn bytes, duration), WAL opened, ready, rule reloads, delivery failures, and shutdown totals.

### 16.3 Profiling

```bash
TEMPORA_PPROF=true bin/tempora ...
go tool pprof -http :7070 http://localhost:8080/debug/pprof/profile?seconds=30
go tool pprof http://localhost:8080/debug/pprof/heap
make profile        # profile the in-process benchmark instead
```

---

## 17. Deployment

### 17.1 Docker image

The multi-stage `Dockerfile` has three stages:

1. **`build`** (`golang:1.23-alpine`): static `CGO_ENABLED=0`, `-trimpath`, stripped binaries, with BuildKit caches for modules and the build cache. Rules are validated with `tempora check` *during the build*, so an image with broken rules cannot be produced.
2. **`test`**: `go vet` + `go test` inside the build image (`make docker-test`).
3. **`runtime`** (`gcr.io/distroless/static-debian12:nonroot`): no shell, no package manager, runs as a **non-root** user. It contains only the two binaries and the rules. The WAL lives in the `/data` volume.

```bash
make docker                                   # tempora:<git-describe> and tempora:latest
docker run --rm -p 8080:8080 -p 9090:9090 -v tempora-data:/data tempora:latest
docker run --rm -v $PWD/rules:/app/rules:ro tempora:latest check /app/rules
```

### 17.2 Docker Compose

`docker-compose.yml` provides:

* **`tempora`**: config from `.env.example`, a named volume for the WAL, a read-only bind mount of `./rules` (edit the rules, then `docker kill -s HUP` to hot reload), a health check through `tempora probe`, `stop_grace_period: 20s`, CPU/memory limits, and a raised `nofile` limit.
* **`prometheus`** (host port 9091), scraping `tempora:8080/metrics` every 5 s with `deploy/alerts.yml` loaded.
* **`loadgen`** (profile `load`): `tempora-bench` in network mode at 20 000 ev/s.

### 17.3 Kubernetes guidance

* Run a `StatefulSet` when the WAL is enabled (one PVC per replica), or a `Deployment` with `TEMPORA_WAL_DIR` empty for stateless detection.
* `readinessProbe: httpGet /readyz`, `livenessProbe: httpGet /healthz`, `terminationGracePeriodSeconds ≥ TEMPORA_SHUTDOWN_GRACE + 5`.
* Mount rules from a ConfigMap and reload with `POST /v1/rules/reload` after the ConfigMap updates.
* Set `GOMAXPROCS` to the CPU limit (or use `automaxprocs` in a fork), because shards default to `GOMAXPROCS`.
* Set `GOMEMLIMIT` to about 90 % of the memory limit, so the GC tightens before the OOM killer acts.
* **Horizontal scaling.** Each instance correlates only the keys it receives. Partition upstream by `key`, for example with Kafka keyed partitions or consistent-hash load balancing on the key, so every event for a key reaches the same replica.

### 17.4 Bare metal / systemd

```ini
[Unit]
Description=Tempora correlation engine
After=network-online.target

[Service]
ExecStart=/usr/local/bin/tempora -rules /etc/tempora/rules -wal-dir /var/lib/tempora/wal
ExecReload=/bin/kill -HUP $MAINPID
EnvironmentFile=-/etc/tempora/tempora.env
User=tempora
Restart=on-failure
LimitNOFILE=65536
TimeoutStopSec=30
StandardOutput=append:/var/log/tempora/alerts.jsonl

[Install]
WantedBy=multi-user.target
```

---

## 18. Operations runbook

| Symptom | Likely cause | Action |
|---|---|---|
| `tempora_events_late_total` rising | lateness too small, or producer clock skew | raise `TEMPORA_ALLOWED_LATENESS`; check NTP on producers; send `ts` from the true event source |
| Absence alerts delayed or not firing | watermark not advancing (no traffic, idle advance disabled) | check `tempora_watermark_lag_seconds`; keep `IDLE_ADVANCE` > 0 or send `POST /v1/advance` |
| `events_blocked_total` / 429s | shards saturated | add CPU / shards; inspect `tempora_shard_queue_depth{shard}` for a hot shard (hot key); reduce expensive rules |
| One shard's queue much deeper than the others | a single very hot key | re-key upstream (e.g. `service+path`), or split the rule |
| `key_evictions_total` rising | more live keys than `MAX_KEYS_PER_SHARD × shards` | raise the cap with more memory, shorten `KEY_TTL`, or narrow rule `from`/`where` so irrelevant keys create no state |
| `run_evictions_total` rising | `max_runs` too small for the pattern's fan-out | raise `max_runs` in the rule, or make stage 0 more selective |
| `sink_dropped_total{sink="webhook:..."}` | webhook slow or down (circuit open) | fix the endpoint; raise `TEMPORA_SINK_QUEUE`; alerts remain in stdout/file sinks and in the hub |
| Duplicate alert after a crash | expected at-least-once edge case (§10.3) | de-duplicate downstream on the deterministic `id` |
| `readyz` stays 503 at startup | long WAL replay | normal for large WALs (replay logs its duration); reduce `WAL_RETAIN` |
| Rule reload rejected | compile error | `curl -XPOST --data-binary @rules/x.tcl :8080/v1/rules/validate` shows `line:col` |
| High memory | aggregate rules with many groups × panes × sketches | lower `over/step` pane count, use `by` sparingly, check `tempora_groups` |

**Safe rule rollout:** validate (`tempora check` in CI) → `POST /v1/rules/validate` against production → `PUT /v1/rules` or edit on disk plus `SIGHUP` → watch `tempora_rule_version` and per-rule `matches` in `/v1/rules`.

---

## 19. Testing strategy

```bash
make test        # all tests
make test-race   # with the race detector (CGO)
make cover       # coverage.out + coverage.html
make fuzz        # FUZZTIME=30s by default
make ci          # lint + race tests + rule check
```

**104 tests + 2 fuzzers. All pass under `-race`.**

| Package | Coverage | Highlights |
|---|---|---|
| `config` | 94.4 % | env/flag precedence, validation of every invalid value class |
| `ring` | 94.0 % | 4×4 MPMC stress (exactly-once, per-producer FIFO), wrap-around, blocking push with cancellation, close semantics, wake-up latency |
| `loadgen` | 93.8 % | determinism, bounded disorder, **detection recall = 100 %** with zero false positives on background keys |
| `pq` | 93.0 % | randomised heap vs. sorted reference; 5 000 random schedule/cancel/reset ops vs. a reference map; FIFO on ties |
| `sketch` | 92.4 % | DDSketch relative-error bound on 4 distributions × 6 quantiles; merge equivalence; collapse keeps p99; HLL error at 5 cardinalities; hash χ² |
| `metrics` | 92.1 % | concurrent counters, histogram quantiles, exposition format escaping, type conflicts |
| `engine` | 86.6 % | 30+ semantic tests: quantifiers, negation, cross-step predicates, sliding stage 0, bounded quantifiers, overlapping runs, `max_runs`, absence (incl. exactly-at-deadline), idle advance, reordering, late drops, suppression, sliding windows, `by`/`where`, `distinct`, group reclamation, TTL + LRU, hot reload migration, muted replay, backpressure, **determinism under reordering**, concurrent producers |
| `sink` | 82.2 % | HMAC signature, retry on 5xx, no retry on 4xx, circuit breaker open→half-open→closed, hub filters, slow-sink isolation |
| `server` | 82.0 % | HTTP NDJSON/array/partial-invalid/body limit, auth, advance→absence, rules API (validate/put/reload), metrics & probes, SSE, TCP (garbage, blank, overlong lines), **crash recovery from WAL**, **no re-delivery of buffered alerts after replay** |
| `wal` | 80.0 % | round trip with rotation, segment skipping, reopen, **torn tail at every offset**, mid-segment corruption, retention/truncation, concurrent appenders |
| `rules` | 79.9 % | lexer, 30 expression semantics, 30 distinct compile-error classes, error positions, constant folding, type matchers, bundled rules compile, **`FuzzCompile`** |
| `event` | 78.1 % | value semantics, limits, binary round trip (5 000 random events), truncation at every byte, JSON parsing and epoch disambiguation, **`FuzzDecodeBinary`** |

Fuzzing is part of the process, not a checkbox: `FuzzDecodeBinary` found a non-canonical decoding case (overlong varints, and bool bytes other than 0/1) that is now rejected. 2.87 M executions ran clean after the fix, and the crashing input is kept as a permanent regression seed.

---

## 20. Project structure — every file explained

```
.
├── cmd/
│   ├── tempora/main.go            # server binary: config, WAL replay (muted) + Flush, sinks, HTTP/TCP,
│   │                              #   readiness, SIGHUP reload, graceful shutdown; `check`, `probe`, `version`
│   └── tempora-bench/main.go      # benchmark: in-process (pre-generated, shard-partitioned producers,
│                                  #   Advance barrier, memory/GC/alloc stats, pprof) and TCP network mode
├── internal/
│   ├── event/
│   │   ├── value.go               # 32-byte tagged union Value; equality/ordering with numeric promotion
│   │   ├── event.go               # Event, sorted Attrs, binary-search Get, pseudo-fields, admission limits
│   │   ├── codec.go               # canonical binary codec (WAL); JSON wire format; epoch disambiguation
│   │   ├── event_test.go          # semantics, limits, round trip, corruption, JSON, FuzzDecodeBinary
│   │   └── testdata/fuzz/…        # fuzz regression corpus
│   ├── ring/
│   │   ├── ring.go                # Vyukov bounded MPMC ring, batched pop, doorbell parking, backpressure
│   │   └── ring_test.go           # MPMC stress, FIFO, blocking, close, benchmarks
│   ├── pq/
│   │   ├── heap.go                # generic 4-ary min-heap (reorder buffer)
│   │   ├── timers.go              # indexed 4-ary timer heap: Schedule/Cancel/Reset O(log n), FIFO ties
│   │   └── pq_test.go
│   ├── sketch/
│   │   ├── hash.go                # wyhash-style 64-bit string hash + Murmur finaliser
│   │   ├── hll.go                 # HyperLogLog (dense, linear-counting correction), merge
│   │   ├── ddsketch.go            # DDSketch: log buckets, pos/neg/zero stores, collapsing, one-pass merge
│   │   └── sketch_test.go         # accuracy vs. exact on 4 distributions, merge equivalence, χ², benchmarks
│   ├── metrics/
│   │   ├── metrics.go             # lock-free counters/gauges/histograms; Prometheus text exposition
│   │   └── metrics_test.go
│   ├── rules/                     # Tempora Correlation Language
│   │   ├── lexer.go               # tokens, durations, comments, string escapes, positions
│   │   ├── ast.go                 # expression nodes, TypeMatcher, StepAST, RuleAST
│   │   ├── parser.go              # recursive-descent parser for rules, steps, quantifiers, expressions
│   │   ├── expr.go                # closure compiler: operators, `in` hash sets, 25 functions, aggregates
│   │   │                          #   (lazy AggEval), alias scoping, constant folding
│   │   ├── compile.go             # rule validation, sequence plan (positives + guards), window plan,
│   │   │                          #   fingerprints, CompileFiles
│   │   └── rules_test.go          # lexer, expressions, 30 error classes, bundled rules, FuzzCompile
│   ├── engine/
│   │   ├── engine.go              # Engine API: New, Submit(Batch), Sync, Advance, Flush, SetRules,
│   │   │                          #   SetMuted, Close, Stats/Totals, config defaults
│   │   ├── shard.go               # shard loop: batching, watermark, reorder heap, event/timer interleave,
│   │   │                          #   relevance cache, key LRU + TTL sweep, rule migration, suppression
│   │   ├── sequence.go            # NFA runs: guards, quantifiers, sliding stage 0, absence completion
│   │   ├── aggregate.go           # pane rings, per-pane sketches, lazy memoised window aggregates,
│   │   │                          #   group caps and reclamation
│   │   ├── alert.go               # Alert type and JSON rendering
│   │   └── engine_test.go         # semantics suite incl. determinism-under-reordering
│   ├── wal/
│   │   ├── wal.go                 # segmented CRC32C log, group commit, sync modes, rotation, retention,
│   │   │                          #   torn-tail truncation on open, Replay with segment skipping
│   │   └── wal_test.go            # torn tail at every offset, corruption, retention, concurrency
│   ├── sink/
│   │   ├── sink.go                # Sink interface; Dispatcher with per-sink queues and workers
│   │   ├── logsink.go             # JSON-lines to stdout or file
│   │   ├── webhook.go             # HMAC-signed webhook, full-jitter retries, circuit breaker
│   │   ├── hub.go                 # recent-alert ring buffer + live subscriber fan-out (SSE)
│   │   └── sink_test.go
│   ├── server/
│   │   ├── ingest.go              # Ingestor: seq assignment + WAL journaling + shard hand-off
│   │   ├── http.go                # routes, auth, ingest (object/array/NDJSON), advance, alerts, SSE,
│   │   │                          #   rules API, stats, metrics registration, panic recovery
│   │   ├── tcp.go                 # NDJSON TCP listener: batching, bounded lines, conn limits, idle timeout
│   │   └── server_test.go         # end-to-end HTTP/TCP/SSE/auth/rules/metrics/crash recovery
│   ├── config/
│   │   ├── config.go              # defaults ← TEMPORA_* env ← flags; validation
│   │   └── config_test.go
│   └── loadgen/
│       ├── loadgen.go             # deterministic synthetic telemetry + injected attack/fault scenarios
│       └── loadgen_test.go        # determinism, bounded disorder, detection recall
├── rules/
│   ├── security.tcl               # brute force, port scan, webshell chain
│   └── reliability.tcl            # latency SLO, error burst, missing heartbeat, crash loop
├── deploy/
│   ├── prometheus.yml             # scrape config for the compose stack
│   └── alerts.yml                 # operational Prometheus alerts for Tempora itself
├── Dockerfile                     # build → test → distroless non-root runtime
├── docker-compose.yml             # tempora + prometheus (+ loadgen profile)
├── .dockerignore
├── .env.example                   # every configuration variable, documented
├── Makefile                       # build, run, check, lint, test(-race), cover, bench(-e2e), fuzz,
│                                  #   profile, docker, compose-*, ci, clean   (`make help`)
├── go.mod                         # module; no third-party dependencies
├── .gitignore
└── README.md
```

**Code size:** ~9 250 lines of production Go and ~3 200 lines of tests (Go standard library only).

**Package dependency graph** (arrows = imports; no cycles):

```
cmd/tempora ─▶ config, engine, event, metrics, rules, server, sink, wal
server ─▶ engine, event, metrics, rules, sink, wal
sink ─▶ engine
engine ─▶ event, metrics, pq, ring, rules, sketch
wal ─▶ event          rules ─▶ event          loadgen ─▶ event, pq
config ─▶ wal         event, ring, pq, sketch, metrics ─▶ (stdlib only)
```

---

## 21. Design decisions and trade-offs

| Decision | Chosen | Alternatives considered | Rationale / cost |
|---|---|---|---|
| Parallelism | shard-per-core, key-hash partitioning | shared `sync.Map` + per-key mutex; actor per key | no locks or contention on the hot path; deterministic per-key order; **cost:** a single extremely hot key is limited to one core |
| Queue | Vyukov MPMC ring + doorbell | Go channels; LMAX disruptor | batch drain with no allocations, explicit backpressure, producers skip the channel when consumers are busy; **cost:** more code than a channel |
| Time model | event time + bounded lateness | processing time; per-key watermarks | correct and reproducible under disorder; **cost:** alert delay ≤ lateness, late events dropped (counted) |
| Watermark scope | per shard | global min across shards | no cross-shard coordination; **cost:** a skewed producer affects only the shards its keys land on, which is also the benefit |
| Timers | indexed 4-ary heap | hierarchical timing wheel | O(log n) under arbitrary event-time jumps (replay, `/advance`); cancel/reset without tombstones |
| Pattern semantics | skip-till-next-match with sliding stage 0 | strict contiguity; skip-till-any-match (all combinations) | matches analyst intent; avoids combinatorial explosion; bounded by `max_runs` |
| Rule execution | closure compilation | tree-walking interpreter; bytecode VM; codegen | about as fast as a VM and much simpler; no reflection, 0 allocations |
| Aggregates | pane rings + mergeable sketches | exact per-event buffers; tumbling-only windows | fixed memory per group, sliding semantics, quantiles/cardinalities; **cost:** ≤ 1 % / ~3 % approximation error, pane granularity |
| Aggregate evaluation | continuous, lazy, memoised | on pane close only | lowest detection latency; laziness keeps it cheap |
| Durability | input WAL + deterministic replay | periodic state snapshots | simple and exact; **cost:** replay time grows with retention, bounded by `WAL_RETAIN` |
| Alert delivery | at-least-once, deterministic ids | exactly-once via sink ack log | far simpler; downstream de-duplication is trivial |
| Dependencies | stdlib only | Prometheus client, zap, Kafka client | minimal supply-chain risk, tiny static binary (7 MB) |

---

## 22. Security considerations

* **Input hardening.** Size limits on bodies, lines, attributes, strings, keys and types. The JSON decoder uses `UseNumber`. Nested values are rejected, and malformed lines never kill a TCP connection.
* **State exhaustion** by adversarial key or group cardinality is bounded by the LRU, TTL, `max_runs`, the group cap and the reorder cap (§13.2). All of these are observable in metrics.
* **Rule safety.** Regexes are RE2 (linear time, no catastrophic backtracking) and compiled once. Every sequence must have a `within`, and pane counts and step counts are bounded at compile time.
* **Authentication.** Optional bearer token on mutating endpoints, compared in constant time. Use TLS termination (ingress / sidecar) in front of Tempora; the binary does not terminate TLS itself.
* **Webhook integrity.** HMAC-SHA256 over timestamp + body. Receivers should verify the signature and the timestamp freshness.
* **Container.** Distroless, non-root, no shell, read-only rules mount.
* **Panics** in handlers are recovered and logged with a stack trace, and return 500.
* **pprof** is off by default.

---

## 23. Limitations and roadmap

**Current limitations (by design or scope):**

* Single-node correlation. Scale out by partitioning keys upstream (§17.3); there is no built-in cluster membership or state rebalancing.
* Correlation is scoped to a single `key`. Cross-key joins (e.g. user ↔ IP graphs) require choosing a composite key upstream.
* Aggregates use pane granularity: a window slides by `step`, not per event.
* Alert delivery is at-least-once across crashes.
* WAL replay time is proportional to retained segments; there are no state snapshots yet.
* `distinct` and quantiles are approximate (bounds documented in §7.4).

**Roadmap:**

1. State snapshots (per shard) + WAL truncation up to the snapshot sequence.
2. Kafka / NATS consumers with partition-aligned sharding and committed offsets.
3. Clustered mode: consistent-hash ring with key-range handoff.
4. Per-key watermarks as an option for multi-tenant producers with different skews.
5. Rule unit-test fixtures (`*.tcl.test`) executed by `tempora check`.
6. OTLP logs ingestion.

---

## 24. Development workflow & contributing

```bash
make help            # list all targets
make fmt lint        # gofmt -s, go vet (+ staticcheck when installed)
make test-race       # race detector
make fuzz FUZZTIME=2m
make bench bench-e2e
make ci              # what CI must pass
```

Conventions:

* Conventional commits (`feat(engine): …`, `fix(wal): …`, `test(rules): …`).
* No third-party dependencies without a strong justification.
* Every behavioural change to engine semantics needs a test in `engine_test.go`. Every new TCL construct needs parser, compiler-error and evaluation tests. Performance changes need before/after `tempora-bench` numbers in the PR description.
* Keep the hot path allocation-free: check `allocs_per_event` in `tempora-bench -json` and `-benchmem`.

Adding a scalar TCL function: implement it in `compileCall` in `internal/rules/expr.go`, add arity validation, add rows to `TestExpressions` and `TestExpressionCompileErrors`, and document it in §7.4.

Adding a sink: implement `sink.Sink` (`Name`, `Deliver`, `Close`), wire it up in `cmd/tempora/main.go`, add metrics labels automatically through the dispatcher, and add an isolation test.

---

## 25. Glossary

| Term | Meaning |
|---|---|
| **Key** | partition/correlation scope of an event; all state is per key |
| **Shard** | a goroutine owning a hash-partition of keys and all their state |
| **Event time** | the time an event happened (`ts`), as opposed to arrival time |
| **Watermark** | per-shard threshold below which no further events will be evaluated |
| **Lateness** | tolerated disorder; events more than this far behind the newest are late |
| **Run** | one partial match (NFA thread) of a sequence rule for one key |
| **Guard** | a negated step; an event matching it kills the run |
| **Absence rule** | a sequence ending in a guard; fires when the guard did *not* occur within `within` |
| **Pane** | a tumbling sub-window of width `step`; a sliding window is `over/step` panes |
| **Group** | a sub-partition of an aggregate rule inside a key, from `by` |
| **Suppression** | a per (rule, key, group) quiet period after an alert |
| **Fingerprint** | truncated SHA-256 of a rule's source; used to preserve state across reloads |
| **Muted** | engine mode during WAL replay: alerts are counted but not delivered |
| **Torn tail** | a partially written final WAL record left by a crash; truncated on open |
| **DDSketch / HLL** | mergeable sketches for relative-error quantiles / cardinality |
