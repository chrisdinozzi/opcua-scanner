# OPC-UA Recon
Features:
- Gather information on the security of OPC-UA Servers
- Check if Anonymous access works
- Check if Credentials work
- Scan for writeable tags
- Output writeable tags to CSV

## TODO
- Add certificate authentication support

## Usage
``` bash
-endpoint       OPC-UA Endpoint
-ip             OPC-UA Server IP
-ports          OPC-UA Server Port
-ip_file        new line deliminated file of IPs. Can also specify ports. See examples for more
-probe-anon     attempt to connect with Anonymous credentials to confirm if access really works
-probe-creds    attempt to connect with provided credentials to check if they work (requires username and password to be specified)
-username   
-password
-probe-write    scan the endpoint for writeable tags
-rewrite-host   if the server is behind NAT/Firewall, use this to replace the local address with the advertised one
-batch-szie     specify the probe write batch size (default 50)
```

### Examples

Scan an OPC-UA Server by endpoint

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840"`

Scan an OPC-UA Server by IP

`go run opcua_recon.go -ip "10.0.0.10"`

Scan an OPC-UA Server by IP and non-standard port

`go run opcua_recon.go -ip "10.0.0.10" -port 18889`

Scan an OPC-UA Server by Endpoint and check if anonymous access works

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840" -probe-anon`

Scan an OPC-UA Server by Endpoint and check if credentials  access works

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840" -probe-creds -user "user" -password "password"`

Scan an OPC-UA Server by Endpoint and check if anonymous access works, and look for anonymous writeable tags

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840" -probe-anon -probe-write`

Scan an OPC-UA Server by Endpoint and check if credentials access works, and look for writeable tags for said credentials

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840" -probe-creds -user "user" -probe-write`

Scan an OPC-UA Server by Endpoint that is behind NAT/Firewall, or has a hostname different from the user provided

`go run opcua_recon.go -endpoint "opc.tcp://123.45.67.89:4840" -rewrite-host`