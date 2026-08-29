# pathdiff

`pathdiff` persists cDOT FPolicy change events in Pebble and exposes daemon control and query commands.

## Objectives

- Capture changed inode paths emitted by a cDOT FPolicy bridge.
- Keep a durable, locally queryable history optimized for time and path lookups.
- Provide daemon lifecycle, audit, backup, and live-monitoring workflows from one CLI.

## Usage

Build the binary with `xc build`, then start the daemon with a TCP listener that the FPolicy bridge can reach:

```sh
bin/pathdiff daemon --db ./pathdiff.db --listen :9911
```

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

The receiver expects a cDOT FPolicy protocol adapter to convert native FPolicy notifications into the documented JSON input. This keeps NetApp-specific wire handling separate from the durable event store and CLI.

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