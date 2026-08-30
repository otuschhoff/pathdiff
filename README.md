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
bin/pathdiff service restart
bin/pathdiff service refresh
bin/pathdiff service list-ports
bin/pathdiff service monitor --path /vol/finance/ --show-node --show-lif
bin/pathdiff service stop
bin/pathdiff engine list
bin/pathdiff cdot node list
bin/pathdiff cdot lif list
bin/pathdiff cdot fpolicy list
bin/pathdiff cdot fpolicy scope list
bin/pathdiff cdot fpolicy create ncl1-1-vs-70
bin/pathdiff cdot fpolicy start ncl1-1-vs-50
bin/pathdiff cdot fpolicy stop ncl1-1-vs-50
bin/pathdiff cdot pubkey generate
bin/pathdiff cdot pubkey show
bin/pathdiff cdot set-cluster cluster.example.test
bin/pathdiff cdot check --host cluster.example.test
```

On first start, `pathdiff` writes `~/.config/systemd/user/pathdiff.service`, reloads the user systemd manager, and starts it. The default listener range is `:9911-9999`, allowing each FPolicy SVM to use a distinct TCP destination port. Later `service start` calls start the registered unit without replacing custom configuration; a legacy default `:9911` unit is upgraded automatically to the default range. `service restart` re-executes the unit's configured binary, picking up a replacement at that path. Add `--verbose` (or `-v`) to the first start to log sender connection, protocol, negotiation, keep-alive, and accepted-event state changes. While verbose mode is enabled, the daemon reports per-sender accepted-event throughput every 10 seconds.

`service status` renders the systemd state, active FPolicy connection count, registered event count, and average accepted FPolicy requests per second since daemon start. The daemon discovers cDOT external engines that target its local IPv4 addresses, listens only on their configured ports, and accepts each port only from LIF IPv4s on the policy's SVM. It refreshes that configuration every minute, adds newly configured senders, attempts to enable their policies, and removes ports that are no longer configured. Run `service refresh` to request the same cDOT reconciliation immediately; `service list-ports` shows the currently active ports and their allowed LIF IPv4 addresses. Before `cdot fpolicy start` enables and connects policies, it requests this refresh so their target ports are listening first. The internal `daemon run` entrypoint handles SIGINT and SIGTERM by stopping listeners, closing active sockets, waiting for workers, then closing Pebble.

`cdot node list` and `cdot lif list` render live ONTAP inventory over SSH. `engine list` uses that inventory to resolve each active sender's node and SVM names, hides raw LIF IPv4 by default, and renders connection time, human-readable time since the last accepted event, total events, average event rate, FPolicy connection status when ONTAP permits the status query, hostname, and local listener port.

`cdot fpolicy list [<svmWildcardSearchTerm>]` lists the SVM, external engine, target addresses, port, SSL option, engine type and format, policy class, and event class for FPolicy external-engine configurations. It shows `pathdiff*` policy or engine names by default; use `--all` (or `-a`) for every configured policy. `cdot fpolicy scope list` applies the same filter and lists policy scopes. `cdot fpolicy create [<svmWildcardSearch>]` prints paste-ready setup commands for matching data SVMs that do not yet have a `pathdiff*` policy or engine. It resolves the receiver IPv4 and port from the managed pathdiff service, reads configured policies to choose the next sequence number, and does not change cDOT. `cdot fpolicy start [<svmWildcardSearchTerm> [<policyClass>]]` refreshes receiver listeners, verifies every operational `data-fpolicy-client` LIF can reach each receiver target with `network ping`, then disables and enables matching policy classes, connects their engines, and waits up to 30 seconds for ONTAP to confirm all engine connections before reporting success. `cdot fpolicy stop` disables policies using the same arguments and filtering. Both select the `pathdiff*` policy or engine by default, accept an explicit policy-class filter as their second argument, and use `--all` to operate on every matching policy.

`cdot pubkey generate` creates a non-interactive Ed25519 keypair at `$XDG_DATA_HOME/pathdiff/cdot_ed25519`, or `~/.local/share/pathdiff/cdot_ed25519` when `XDG_DATA_HOME` is unset. It uses Go cryptography and SSH libraries rather than external SSH commands, prints the public-key path, and will not overwrite an existing key. Use `cdot pubkey show` to print the public key for adding to ONTAP. Future cDOT SSH operations default to user `pathdiff`; pass `cdot --user <user>` to override it.

`cdot set-cluster <clusterFQDN>` writes the default cDOT cluster to `$XDG_CONFIG_HOME/pathdiff/cdot.json`, or `~/.config/pathdiff/cdot.json` when unset. `cdot check` uses this default unless `--host <cluster>` overrides it. The check connects to ONTAP using the generated key and user `pathdiff` by default, then runs `vserver fpolicy policy show` and `vserver fpolicy policy external-engine show` to verify policy visibility and whether a configured external-engine endpoint matches this host's addresses. It verifies cluster host keys using `$XDG_CONFIG_HOME/pathdiff/known_hosts`, or `~/.config/pathdiff/known_hosts` when unset. For the first connection, use `--accept-new-host-key` to save the presented host key; subsequent checks verify it strictly. Add `--debug-ssh-exec` to print each SSH command and its returned output. Use `--known-hosts` or `--key` to override either path.

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
bin/pathdiff db status
bin/pathdiff db event reset
bin/pathdiff cdot volume list
bin/pathdiff cdot svm list
```

`monitor` prints newly observed events as tables until interrupted. It shows timestamp, SVM, volume, and path by default, coalescing each batch to the newest event for every path. Add `--show-op`, `--show-node`, or `--show-lif` for operation and sender metadata; use `--hide-timestamp`, `--hide-svm`, or `--hide-volume` to suppress individual default columns. Use `--json` for resolved JSON-line events instead of tables. Add `--since RFC3339` to replay changes from a particular timestamp. The default control socket is `/tmp/pathdiff.sock`; set `--control` on both daemon and client to use another socket. The daemon commits both time and path indexes atomically to Pebble. Configure the FPolicy receiver or a protocol adapter to emit the line-delimited JSON above.

`events --start` and `--end` accept RFC3339 timestamps, dates such as `2026-08-28`, or relative expressions: `10d`, `1m`, `5h10m`, and `1M4d` mean ten days, one minute, five hours ten minutes, and one month four days ago. Use uppercase `M` for calendar months; lowercase `m` always means minutes. Omit `--start` for the last 24 hours or `--end` for now.

`events` renders matches as a table. Its optional first argument is a case-insensitive path search: `firefox` matches any path containing `firefox`. Include `*` or `?` for an explicit wildcard, where `*` matches across directories and `?` matches one character. `--max` defaults to `100`; when more matches exist, it prints the count instead of a partial table. Increase `--max` or tighten the wildcard, `--path`, or time range.

`path list` accepts the same optional path search and `--path`, `--start`, `--end`, `--max`, and `--control` flags as `events`. It coalesces repeated changes to each volume/path pair and renders `Last Change`, `Volume`, and `Path`.

`path parent` accepts the same flags but coalesces changed paths by volume and parent directory, rendering `Last Change`, `Volume`, `CNT`, and `Parent`. `CNT` is the number of distinct changed child paths beneath that parent. Both views sort by volume then path by default; pass `--sort timestamp` to list newest changes first.

`db event reset` removes all stored event records through the running daemon. It preserves configured volume MSID-to-name mappings.

`db status` renders the live Pebble database path and its on-disk size through the daemon control socket.

## Implementation

The daemon accepts one JSON event per TCP line, validates that each event contains a path, and writes it through a single Pebble batch. Each event is indexed twice: a timestamp-first key supports ordered monitoring queries, while a path-first key supports prefix and time-window audit queries. The local Unix control socket keeps database ownership in the daemon; all client commands query or control it through a compact JSON request/response protocol.

The receiver accepts JSON lines from adapters, raw XML notifications, and native ONTAP XML transport. Native ONTAP XML uses a `0x22` message-type byte, a 4-byte big-endian length, an XML header/body payload separated by a blank line, and a trailing NUL byte. It sends `NEGO_REQ`; `pathdiff` replies with the reference-compatible `NEGO_RESP` layout: `HandshakeResp` containing the request's `VsUUID`, `PolicyName`, `SessionId`, and scalar protocol version `1.2`. Header-only native messages such as `KEEP_ALIVE` have `ContentLen` `0` and no separator; `pathdiff` accepts and ignores them while keeping the session open.

XML notifications extract path, operation, and timestamp fields. Unknown connection prefixes are rejected rather than guessed as another protocol.

Native synchronous `SCREEN_REQ` messages are also stored as audit events using their request type, generation time, and UNIX access path. `pathdiff` does not issue access allow/deny decisions for screen requests.

`SCREEN_REQ` payloads also include the numeric `VolMsid`. Persisted query results retain it as `volume_msid`.

`cdot volume list` and `cdot svm list` query current ONTAP data directly over SSH. Each table includes the live name and ID plus whether its SVM has an FPolicy policy configured. Local `set` mapping commands are not used.

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