# pathdiff

`pathdiff` persists cDOT FPolicy change events in Pebble and exposes daemon control and query commands.

## Objectives

- Capture changed file paths and operations emitted by cDOT FPolicy.
- Keep a durable, locally queryable history optimized for time and path lookups.
- Provide daemon lifecycle, audit, backup, and live-monitoring workflows from one CLI.

## Usage

Build the binary with `xc build`, then register and start the per-user systemd service:

```sh
bin/pathdiff service start --db pathdiff_data --listen :9911
bin/pathdiff service status
bin/pathdiff service monitor --path /vol/finance/ --interval 2s
bin/pathdiff service stop
```

On first start, `pathdiff` writes `~/.config/systemd/user/pathdiff.service`, reloads the user systemd manager, and starts it. Later `service start` calls start the registered unit without replacing its configuration. Add `--verbose` (or `-v`) to the first start to log sender connection, protocol, negotiation, keep-alive, and accepted-event state changes. While verbose mode is enabled, the daemon reports per-sender accepted-event throughput every 10 seconds.

`service status` renders the systemd state, active FPolicy connection count, and registered event count. The internal `daemon run` entrypoint handles SIGINT and SIGTERM by stopping listeners, closing active sockets, waiting for workers, then closing Pebble.

When diagnosing an incompatible FPolicy session, add `--record-dir captures` to write the raw bytes from every event connection. Each capture has a timestamped `.in` file for bytes received from ONTAP and a matching `.out` file for bytes sent by `pathdiff`. Captures may contain file paths and user or client identifiers; protect and remove them appropriately.

The event listener accepts one JSON object per line. `timestamp` is RFC3339 and optional; omitted timestamps are assigned when the event is stored.

```json
{"path":"/vol/finance/report.csv","operation":"modify","timestamp":"2026-08-29T10:30:00Z"}
```

Query the running daemon from another shell:

```sh
bin/pathdiff events --path /vol/finance/ --start 2026-08-29T00:00:00Z --end 2026-08-30T00:00:00Z
bin/pathdiff events firefox --start 10d --max 250
bin/pathdiff events --path /vol/finance/ --start 10d
bin/pathdiff events --path /vol/finance/ --start 1M4d --end 2026-08-28
bin/pathdiff path list firefox --start 10d
bin/pathdiff path parent --path /vol/finance/ --sort timestamp --max 250
bin/pathdiff db event reset
```

`monitor` prints newly observed events as JSON lines until interrupted. Add `--since RFC3339` to replay changes from a particular timestamp. The default control socket is `/tmp/pathdiff.sock`; set `--control` on both daemon and client to use another socket. The daemon commits both time and path indexes atomically to Pebble. Configure the FPolicy receiver or a protocol adapter to emit the line-delimited JSON above.

`events --start` and `--end` accept RFC3339 timestamps, dates such as `2026-08-28`, or relative expressions: `10d`, `1m`, `5h10m`, and `1M4d` mean ten days, one minute, five hours ten minutes, and one month four days ago. Use uppercase `M` for calendar months; lowercase `m` always means minutes. Omit `--start` for the last 24 hours or `--end` for now.

`events` renders matches as a table. Its optional first argument is a case-insensitive path search: `firefox` matches any path containing `firefox`. Include `*` or `?` for an explicit wildcard, where `*` matches across directories and `?` matches one character. `--max` defaults to `100`; when more matches exist, it prints the count instead of a partial table. Increase `--max` or tighten the wildcard, `--path`, or time range.

`path list` accepts the same optional path search and `--path`, `--start`, `--end`, `--max`, and `--control` flags as `events`. It coalesces repeated changes to each volume/path pair and renders `Last Change`, `Volume`, and `Path`.

`path parent` accepts the same flags but coalesces changed paths by volume and parent directory, rendering `Last Change`, `Volume`, `CNT`, and `Parent`. `CNT` is the number of distinct changed child paths beneath that parent. Both views sort by volume then path by default; pass `--sort timestamp` to list newest changes first.

`db event reset` removes all stored event records through the running daemon. It preserves configured volume MSID-to-name mappings.

## Implementation

The daemon accepts one JSON event per TCP line, validates that each event contains a path, and writes it through a single Pebble batch. Each event is indexed twice: a timestamp-first key supports ordered monitoring queries, while a path-first key supports prefix and time-window audit queries. The local Unix control socket keeps database ownership in the daemon; all client commands query or control it through a compact JSON request/response protocol.

The receiver accepts JSON lines from adapters, raw XML notifications, and native ONTAP XML transport. Native ONTAP XML uses a `0x22` message-type byte, a 4-byte big-endian length, an XML header/body payload separated by a blank line, and a trailing NUL byte. It sends `NEGO_REQ`; `pathdiff` replies with the reference-compatible `NEGO_RESP` layout: `HandshakeResp` containing the request's `VsUUID`, `PolicyName`, `SessionId`, and scalar protocol version `1.2`. Header-only native messages such as `KEEP_ALIVE` have `ContentLen` `0` and no separator; `pathdiff` accepts and ignores them while keeping the session open.

XML notifications extract path, operation, and timestamp fields. Unknown connection prefixes are rejected rather than guessed as another protocol.

Native synchronous `SCREEN_REQ` messages are also stored as audit events using their request type, generation time, and UNIX access path. `pathdiff` does not issue access allow/deny decisions for screen requests.

`SCREEN_REQ` payloads also include the numeric `VolMsid`. Persisted query results retain it as `volume_msid`; configure a human-readable name through the daemon with:

```sh
bin/pathdiff volume set --msid 2163258291 --name asic_user
```

Subsequent query and monitor output resolves that ID as `volume_name` without rewriting historic event records.

## Tasks

### build

Build a CGO-free binary for the current platform.

```sh
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o bin/pathdiff ./cmd/pathdiff
```

### build-all

Build CGO-free binaries for common cDOT deployment and operator platforms.

```sh
mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/pathdiff-linux-amd64 ./cmd/pathdiff
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/pathdiff-linux-arm64 ./cmd/pathdiff
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o bin/pathdiff-darwin-arm64 ./cmd/pathdiff
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o bin/pathdiff-windows-amd64.exe ./cmd/pathdiff
```

### test

Run the test suite and static analysis.

```sh
go test ./...
go vet ./...
```

### clean

Remove locally built binaries.

```sh
rm -rf bin
```