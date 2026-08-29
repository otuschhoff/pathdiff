# pathdiff

`pathdiff` persists cDOT FPolicy change events in Pebble and exposes daemon control and query commands.

## Run

Start the daemon, choosing a TCP listener that your FPolicy event bridge can reach:

```sh
go run ./cmd/pathdiff daemon --db ./pathdiff.db --listen :9911
```

The event listener accepts one JSON object per line. `timestamp` is RFC3339 and optional; omitted timestamps are assigned when the event is stored.

```json
{"inode":12345,"path":"/vol/finance/report.csv","operation":"modify","timestamp":"2026-08-29T10:30:00Z"}
```

Query the running daemon from another shell:

```sh
go run ./cmd/pathdiff inodes --since 2026-08-29T00:00:00Z
go run ./cmd/pathdiff events --path /vol/finance/ --start 2026-08-29T00:00:00Z --end 2026-08-30T00:00:00Z
go run ./cmd/pathdiff monitor --path /vol/finance/ --interval 2s
go run ./cmd/pathdiff status
go run ./cmd/pathdiff stop
```

`monitor` prints newly observed events as JSON lines until interrupted. Add `--since RFC3339` to replay changes from a particular timestamp. The default control socket is `/tmp/pathdiff.sock`; set `--control` on both daemon and client to use another socket. The daemon commits both time and path indexes atomically to Pebble. Configure the FPolicy receiver or a protocol adapter to emit the line-delimited JSON above.