# OPC-UA Recon

A pre-authentication and light active-recon tool for OPC-UA servers: enumerate
endpoint security configuration, test whether anonymous or credentialed access
actually works, and scan for tags that are writeable by the authenticated session.

**Only use against systems you own or are explicitly authorised to test.**

![demo](demo.gif)

## Features
- Enumerate endpoint security settings (security mode, policy, advertised auth methods)
- Confirm whether anonymous access works
- Confirm whether supplied credentials work
- Scan for writeable tags (advertised `UserAccessLevel`, not confirmed by writing)
- Export writeable-tag findings to CSV
- Mass-scan a list of targets from a file

## Requirements
- Go 1.21
- `go mod tidy` to fetch `github.com/gopcua/opcua` and `github.com/fatih/color`

## Limitations
- Write-tag scanning currently only runs against `SecurityMode: None` endpoints
- Credential probing does not yet support client-certificate authentication (see TODO)

## Usage

| Flag | Description |
|---|---|
| `-endpoint` | Full OPC-UA endpoint URL, e.g. `opc.tcp://10.0.0.10:4840` |
| `-ip` | Server IP (combine with `-port`) |
| `-port` | Server port (default `4840`) |
| `-ip-file` | Newline-delimited file of targets for mass scanning. Each line may include a port (`10.0.0.10:18889`); if omitted, `-port` is used |
| `-probe-anon` | Actively attempt an anonymous session to confirm it really works |
| `-probe-creds` | Attempt authentication with `-user`/`-pass` |
| `-user` | Username for credentialed auth |
| `-pass` | Password for credentialed auth |
| `-probe-write` | Scan for tags writeable by the current session (anonymous or credentialed) |
| `-batch-size` | Nodes read per batch during the write-tag scan (default `50`; `1` streams one at a time) |
| `-rewrite-host` | Replace a server's advertised endpoint host (often an internal/NAT address) with the host you actually dialled |
| `-output-file` | Append writeable-tag findings to this CSV file |
| `-verbose` | Enable diagnostic output |

### CSV output format
When `-output-file` is set, each writeable tag found is appended as a row:

`Endpoint, SecurityMode, SecurityPolicy, AuthMethod, NodeID, BrowseName, AccessLevel, Value`

### IP file format
One target per line; port optional, otherwise defaults to `-port`:
```
10.0.0.10
10.0.0.11:99009
172.16.3.4
```

## Build
```bash
go install github.com/chrisdinozzi/opcua-recon@latest
```

Then run examples below with `./opcua_recon` instead of `go run opcua_recon.go`.

## Examples

Scan an OPC-UA Server by Endpoint

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840"`

Scan an OPC-UA Server by IP and non-standard port

`go run opcua_recon.go -ip "10.0.0.10" -port 18889`

Scan an OPC-UA Server by IP and check if anonymous access works

`go run opcua_recon.go -ip "10.0.0.10" -probe-anon`

Scan an OPC-UA Server by Endpoint and check if credentials access works

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840" -probe-creds -user "user" -pass "password"`

Scan an OPC-UA Server by Endpoint and check if anonymous access works, and look for anonymous writeable tags, output to file

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840" -probe-anon -probe-write -output-file out.csv`

Scan an OPC-UA Server by Endpoint and check if credentials access works, and look for writeable tags for said credentials

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840" -probe-creds -user "user" -pass "password" -probe-write`

Scan an OPC-UA Server by Endpoint that is behind NAT/Firewall, or has a hostname different from the user provided

`go run opcua_recon.go -endpoint "opc.tcp://123.45.67.89:4840" -rewrite-host`

Specify a scanning batch size for writeable tag scan. useful for slow servers (slower the server, lower the batch count)

`go run opcua_recon.go -endpoint "opc.tcp://123.45.67.89:4840" -rewrite-host -probe-anon -probe-write -batch-size 10`
