# pathdiff

`pathdiff` persists cDOT FPolicy change events in Pebble and exposes daemon control and query commands.

## Objectives

- Capture changed inode paths emitted by a cDOT FPolicy bridge.
- Keep a durable, locally queryable history optimized for time and path lookups.
- Provide daemon lifecycle, audit, backup, and live-monitoring workflows from one CLI.

## Usage

Build the binary with `xc build`, then start the daemon with a TCP listener that the FPolicy bridge can reach:

```sh
bin/pathdiff daemon --db pathdiff_data --listen :9911
```

Add `--verbose` (or `-v`) to log sender connection, protocol, negotiation, keep-alive, and accepted-event state changes. While verbose mode is enabled, the daemon reports per-sender accepted-event throughput every 10 seconds.

Press `Ctrl+C` to stop the daemon. It stops accepting new connections, closes active sender and control sockets, waits for their workers to finish, then closes Pebble.

When diagnosing an incompatible FPolicy session, add `--record-dir captures` to write the raw bytes from every event connection. Each capture has a timestamped `.in` file for bytes received from ONTAP and a matching `.out` file for bytes sent by `pathdiff`. Captures may contain file paths and user or client identifiers; protect and remove them appropriately.

The event listener accepts one JSON object per line. `timestamp` is RFC3339 and optional; omitted timestamps are assigned when the event is stored.

```json
{"inode":12345,"path":"/vol/finance/report.csv","operation":"modify","timestamp":"2026-08-29T10:30:00Z"}
```

Query the running daemon from another shell:

```sh
bin/pathdiff inodes --since 2026-08-29T00:00:00Z
bin/pathdiff events --path /vol/finance/ --start 2026-08-29T00:00:00Z --end 2026-08-30T00:00:00Z
bin/pathdiff monitor --path /vol/finance/ --interval 2s
bin/pathdiff status
bin/pathdiff stop
```

`monitor` prints newly observed events as JSON lines until interrupted. Add `--since RFC3339` to replay changes from a particular timestamp. The default control socket is `/tmp/pathdiff.sock`; set `--control` on both daemon and client to use another socket. The daemon commits both time and path indexes atomically to Pebble. Configure the FPolicy receiver or a protocol adapter to emit the line-delimited JSON above.

## Implementation

The daemon accepts one JSON event per TCP line, validates that each event contains a path, and writes it through a single Pebble batch. Each event is indexed twice: a timestamp-first key supports ordered inode and monitoring queries, while a path-first key supports prefix and time-window audit queries. The local Unix control socket keeps database ownership in the daemon; all client commands query or control it through a compact JSON request/response protocol.

The receiver accepts JSON lines from adapters, raw XML notifications, and native ONTAP XML transport. Native ONTAP XML uses a `0x22` message-type byte, a 4-byte big-endian length, an XML header/body payload separated by a blank line, and a trailing NUL byte. It sends `NEGO_REQ`; `pathdiff` replies with the reference-compatible `NEGO_RESP` layout: `HandshakeResp` containing the request's `VsUUID`, `PolicyName`, `SessionId`, and scalar protocol version `1.2`. Header-only native messages such as `KEEP_ALIVE` have `ContentLen` `0` and no separator; `pathdiff` accepts and ignores them while keeping the session open.

XML notifications extract inode, path, operation, timestamp, Vserver, and volume UUID fields. Unknown connection prefixes are rejected rather than guessed as another protocol.

Native synchronous `SCREEN_REQ` messages are also stored as audit events. Their captured NFS payloads provide `ReqId`, `ReqType`, `GenerationTime`, a UNIX access path, and `VolMsid`, but no file inode; these events retain `inode` as `0` and include `request_id` and `volume_msid` in their JSON payload. `pathdiff` does not issue access allow/deny decisions for screen requests.

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