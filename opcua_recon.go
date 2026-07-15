package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
)

var verbose bool

type endpointDetails struct {
	ref             int
	url             string
	security_mode   string
	security_policy string
	security_level  int
	offers_anon     bool
	offers_creds    bool
	methods         []string
}

type tag struct {
	NodeID      *ua.NodeID
	NodeClass   ua.NodeClass
	BrowseName  string
	Description string
	AccessLevel ua.AccessLevelType
	Path        string
	DataType    string
	Writable    bool
	Value       interface{}
}

const maxDepth = 100

const banner = `
                                                                                
  ####  #####   ####        #    #   ##      #####  ######  ####   ####  #    # 
 #    # #    # #    #       #    #  #  #     #    # #      #    # #    # ##   # 
 #    # #    # #      ##### #    # #    #    #    # #####  #      #    # # #  # 
 #    # #####  #            #    # ######    #####  #      #      #    # #  # # 
 #    # #      #    #       #    # #    #    #   #  #      #    # #    # #   ## 
  ####  #       ####         ####  #    #    #    # ######  ####   ####  #    # 

by cdino
`

func main() {
	fmt.Println(banner)

	endpoint := flag.String("endpoint", "", "OPC-UA endpoint URL")
	ip := flag.String("ip", "", "OPC-UA server IP")
	ip_file := flag.String("ip-file", "", "New line deliminated file of IPs to scan")
	port := flag.Int("port", 4840, "OPC-UA server port. Default 4840")
	probe_anon := flag.Bool("probe-anon", false, "also actively test whether anonymous login truly works")
	user := flag.String("user", "", "Username for authentication")
	pass := flag.String("pass", "", "Password for authentication")
	probe_credentials := flag.Bool("probe-creds", false, "Attempt authentication with credentials")
	probe_write := flag.Bool("probe-write", false, "Scan for writeable tags")
	rewrite_host := flag.Bool("rewrite-host", false, "Rewrite the endpoint host with the provided host. required for scanning servers behind NAT/Firewalls")

	flag.BoolVar(&verbose, "verbose", false, "enable verbose output")
	flag.Parse()

	var mass_scan = false
	if *ip_file != "" {
		mass_scan = true
	}
	if *ip != "" {
		url := fmt.Sprintf("opc.tcp://%s:%d", *ip, *port)
		endpoint = &url
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if mass_scan == true {
		targets := parseIPFile(*ip_file, *port)
		fmt.Println("Targets: ", targets)
		for i, endpoint := range targets {
			fmt.Println(i + 1)
			scanServer(ctx, &endpoint, user, pass, probe_anon, probe_credentials, probe_write, rewrite_host)
		}
	} else {
		fmt.Println("Target: ", *endpoint)
		scanServer(ctx, endpoint, user, pass, probe_anon, probe_credentials, probe_write, rewrite_host)
	}
}

func parseIPFile(file_name string, port int) []string {
	var targets []string
	targets_file, err := os.Open(file_name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "File Read Failed: %v\n", err)
		os.Exit(1)
	}
	defer targets_file.Close()

	scanner := bufio.NewScanner(targets_file)

	for scanner.Scan() {
		//check if a port is appended already to the IP
		target := scanner.Text()
		if !strings.Contains(target, ":") {
			target = target + ":" + strconv.Itoa(port)
		}
		target = "opc.tcp://" + target
		targets = append(targets, target)
	}

	return targets
}

func scanServer(ctx context.Context, endpoint, user, pass *string, probe_anon, probe_credentials, probe_write, rewrite_host *bool) {
	endpoints, err := opcua.GetEndpoints(ctx, *endpoint)

	if err != nil {
		fmt.Fprintf(os.Stderr, "GetEndpoints failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== %s ===\n%d endpoint(s)\n\n", *endpoint, len(endpoints))

	scanned_endpoints := []endpointDetails{}

	for i, ep := range endpoints {
		anyAnonymous := false
		anyCredential := false
		if *rewrite_host {
			dialledURL, err := url.Parse(*endpoint)
			if err != nil {
				fmt.Println("Error parsing endpoint URL.")
				os.Exit(1)
			}
			dialledHost := dialledURL.Hostname()
			rewriteEndpointHost(ep, dialledHost)
		}
		var methods []string

		for _, tok := range ep.UserIdentityTokens {
			// Convert the numeric token-type enum into a readable label.
			name := tokenTypeName(tok.TokenType)

			methods = append(methods, name)

			switch tok.TokenType {
			case ua.UserTokenTypeAnonymous:
				anyAnonymous = true
			case ua.UserTokenTypeUserName,
				ua.UserTokenTypeCertificate,
				ua.UserTokenTypeIssuedToken:
				anyCredential = true
			}
		}

		if len(methods) == 0 {
			methods = []string{"(none advertised)"}
		}

		scanned_endpoints = append(scanned_endpoints, endpointDetails{
			ref:             i,
			url:             ep.EndpointURL,
			security_mode:   ep.SecurityMode.String(),
			security_policy: ep.SecurityPolicyURI,
			security_level:  int(ep.SecurityLevel),
			offers_anon:     anyAnonymous,
			offers_creds:    anyCredential,
			methods:         methods})

		fmt.Printf("[Endpoint %d]\n", scanned_endpoints[i].ref+1)
		fmt.Printf("  URL:             %s\n", scanned_endpoints[i].url)
		fmt.Printf("  Security mode:   %s\n", scanned_endpoints[i].security_mode)
		fmt.Printf("  Security policy: %s\n", scanned_endpoints[i].security_policy)
		fmt.Printf("  Security level:  %d\n", scanned_endpoints[i].security_level)
		fmt.Printf("  Allows Anonymous Login:  %t\n", scanned_endpoints[i].offers_anon)
		fmt.Printf("  Allows Credential Login:  %t\n", scanned_endpoints[i].offers_creds)
		fmt.Printf("  Supported Login Methods:  %v\n", scanned_endpoints[i].methods)
		fmt.Println("***")
		switch {
		case anyAnonymous && anyCredential:
			color.Green("[+] Anonymous Access Available")
			color.Yellow("[+] Credential Accesss Available")
		case anyAnonymous:
			color.Green("[+] Anonymous Access Available")
		case anyCredential:
			color.Yellow("[+] Credential Accesss Available")
		default:
			fmt.Println("[-] No user identity tokens advertised (weird — check manually)")
		}
		if *probe_anon && anyAnonymous {
			color.Green("[*] Checking if Anonymous access works...")
			runAnonymousProbe(ctx, ep, *endpoint)
		}

		if *probe_credentials && anyCredential {
			color.Green("[*] Checking if Credential access works...")
			runCredentialProbe(ctx, ep, *user, *pass)
		}
		if *probe_write && (anyAnonymous || anyCredential) {
			runWriteableProbe(ctx, ep, *user, *pass, anyAnonymous)
		}
		//os.Exit(0)
	}
	fmt.Println("---")

}

func rewriteEndpointHost(ep *ua.EndpointDescription, dialledHost string) {
	u, err := url.Parse(ep.EndpointURL)
	if err != nil {
		return
	}
	advertisedHost := u.Hostname()
	if advertisedHost != dialledHost {
		fmt.Printf("[*]Advertised host (%s) differs from dialled host (%s), replacing advertised with dialed.\n\n", advertisedHost, dialledHost)
		u.Host = dialledHost + ":" + u.Port()
		ep.EndpointURL = u.String()
		fmt.Printf("Advertised: %s\nDialled:%s\nEndpoint URL: %s\n", advertisedHost, dialledHost, ep.EndpointURL)
	}
}

func runAnonymousProbe(ctx context.Context, ep *ua.EndpointDescription, endpoint string) {
	c, err := opcua.NewClient(endpoint, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous), opcua.AuthAnonymous())
	if err != nil {
		fmt.Printf("[-] could not build client: %v\n", err)
		return
	}

	if err := c.Connect(ctx); err != nil {
		color.Red("[-] anonymous login REJECTED (%v)\n", err)
		return
	}

	defer c.Close(ctx)

	color.Green("[+] anonymous login SUCCEEDED")
}

func runCredentialProbe(ctx context.Context, endpoint *ua.EndpointDescription, user, pass string) {

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	fmt.Printf("[*] Attempting login with %s:%s\n", user, pass)

	// sec_policy := shortPolicy(endpoint.SecurityPolicyURI)
	// security_mode := endpoint.SecurityMode.String()

	opts := []opcua.Option{
		// opcua.SecurityPolicy(sec_policy),
		// opcua.SecurityModeString(security_mode),
		opcua.AuthUsername(user, pass),
		opcua.SecurityFromEndpoint(endpoint, ua.UserTokenTypeUserName),
		opcua.ApplicationURI("urn:cdino:opcua-recon"),
	}

	if endpoint.SecurityMode != ua.MessageSecurityModeNone {
		generateCertificate()
		opts = append(opts,
			opcua.CertificateFile("client_cert.pem"),
			opcua.PrivateKeyFile("client_key.pem"),
		)
	}
	c, err := opcua.NewClient(endpoint.EndpointURL, opts...)
	if err != nil {
		fmt.Printf("[-] could not build client: %v\n", err)
		return
	}

	if err := c.Connect(ctx); err != nil {
		color.Red("[-] credential login REJECTED (%v)\n", err)
		return
	}

	defer c.Close(ctx)

	color.Green("[+] credential login SUCCEEDED")
}

func runWriteableProbe(ctx context.Context, endpoint *ua.EndpointDescription, user string, pass string, isAnon bool) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var c *opcua.Client
	var err error
	if isAnon { //anon auth
		fmt.Printf("[*] Attempting to find writeable tags on %s with Anonymous credentials\n", endpoint.EndpointURL)

		c, err = opcua.NewClient(endpoint.EndpointURL, opcua.SecurityFromEndpoint(endpoint, ua.UserTokenTypeAnonymous), opcua.AuthAnonymous())
		if err != nil {
			fmt.Printf("[-] could not build client: %v\n", err)
			return
		}
		if err := c.Connect(ctx); err != nil {
			color.Red("[-] credential login REJECTED (%v)\n", err)
			return
		}
	} else { //cred auth
		fmt.Printf("[*] Attempting to find writeable tags with %s:%s\n", user, pass)

		opts := []opcua.Option{
			opcua.AuthUsername(user, pass),
			opcua.SecurityFromEndpoint(endpoint, ua.UserTokenTypeUserName),
		}

		if endpoint.SecurityMode != ua.MessageSecurityModeNone {
			generateCertificate()
			opts = append(opts,
				opcua.CertificateFile("client_cert.pem"),
				opcua.PrivateKeyFile("client_key.pem"),
				opcua.ApplicationURI("urn:cdino:opcua-recon"),
			)
		}
		c, err = opcua.NewClient(endpoint.EndpointURL, opts...)
		if err != nil {
			fmt.Printf("[-] could not build client: %v\n", err)
			return
		}
		if err := c.Connect(ctx); err != nil {
			color.Red("[-] credential login REJECTED (%v)\n", err)
			return
		}
	}

	defer c.Close(ctx)

	var nodeID string = "i=85" //TODO: make this programatic or user supplied (or both!)
	id, err := ua.ParseNodeID(nodeID)
	if err != nil {
		fmt.Printf("invalid node id: %s", err)
		return
	}
	visited := make(map[string]bool)
	var nodes []*ua.NodeID
	start := time.Now()
	collectNodes(ctx, c.Node(id), 0, visited, &nodes)
	verboseOutput("collected %d nodes in %s\n", len(nodes), time.Since(start))
	color.Green("[+] collected %d nodes", len(nodes))

	tags := readAllChunked(ctx, c, nodes)
	color.Green("[+] %d writeable tags found", len(tags))
	verboseOutput("found %d writeable tags in %s\n", len(tags), time.Since(start))

	//fmt.Print(prettyPrint(tags))
	os.Exit(1)

}

func browseTags(ctx context.Context, n *opcua.Node, level int, path string, tags *[]tag, visited map[string]bool) (err error) {

	if level > maxDepth || ctx.Err() != nil {
		return nil
	}

	key := n.ID.String()
	if visited[key] {
		return nil
	}
	visited[key] = true
	if key == "i=2253" { // skip server meta data tags
		return nil
	}

	attrs, err := n.Attributes(ctx,
		ua.AttributeIDNodeClass,       //0
		ua.AttributeIDUserAccessLevel, //1
		ua.AttributeIDBrowseName,      //2
		ua.AttributeIDDescription,     //3
		ua.AttributeIDDataType,        //4
		ua.AttributeIDValue,           //5

	)

	if err != nil {
		fmt.Printf("Attr read error: %v\n", err)
		return nil
	}

	node_class := ua.NodeClass(attrs[0].Value.Int())
	browse_name := attrs[2]
	description := attrs[3]
	path = path + "." + browse_name.Value.String()

	if node_class == ua.NodeClassVariable {
		value := attrs[5].Value
		//fmt.Printf("Value: %v\n", value)
		access_level := ua.AccessLevelType(attrs[1].Value.Uint())
		//fmt.Printf("Access Level: %s\n", access_level)
		writable := access_level&ua.AccessLevelTypeCurrentWrite != 0
		if writable {
			color.Green("[+] Found writeable tag: " + n.ID.String())
			tag := tag{
				NodeID:      n.ID,
				BrowseName:  browse_name.Value.String(),
				Description: description.Value.String(),
				Path:        path,
				Value:       value.Value(),
				Writable:    writable,
			}
			*tags = append(*tags, tag)
		}

	}

	nodes, err := n.ReferencedNodes(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)

	if err != nil {
		fmt.Printf("Couldn't get referenced nodes: %v", err)
		return nil
	}
	for _, node := range nodes {
		browseTags(ctx, node, level+1, path, tags, visited)
	}

	return nil
}

func collectNodes(ctx context.Context, n *opcua.Node, level int, visited map[string]bool, out *[]*ua.NodeID) {
	if level > maxDepth || ctx.Err() != nil {
		return
	}
	key := n.ID.String()
	if visited[key] {
		return
	}
	visited[key] = true
	if key == "i=2253" { // skip server diagnostics subtree
		return
	}

	*out = append(*out, n.ID)

	nodes, err := n.ReferencedNodes(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	if err != nil {
		verboseOutput("browse failed at %s: %v\n", key, err)
		return
	}
	for _, child := range nodes {
		collectNodes(ctx, child, level+1, visited, out)
	}
}

const attrsPerNode = 4 // NodeClass, UserAccessLevel, BrowseName, Value — order matters
func readNodeChunk(ctx context.Context, c *opcua.Client, ids []*ua.NodeID) ([]tag, error) {
	attsToRead := make([]*ua.ReadValueID, 0, len(ids)*attrsPerNode)
	for _, nodeId := range ids {
		attsToRead = append(attsToRead,
			&ua.ReadValueID{NodeID: nodeId, AttributeID: ua.AttributeIDNodeClass},
			&ua.ReadValueID{NodeID: nodeId, AttributeID: ua.AttributeIDUserAccessLevel},
			&ua.ReadValueID{NodeID: nodeId, AttributeID: ua.AttributeIDBrowseName},
			&ua.ReadValueID{NodeID: nodeId, AttributeID: ua.AttributeIDValue},
		)
	}
	resp, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: attsToRead})
	if err != nil {
		return nil, err
	}

	var writeable []tag
	for i, nodeId := range ids {
		base := i * attrsPerNode // results[base .. base+attrsPerNode) belong to ids[i]
		nodeClass := resp.Results[base+0]
		accessLevel := resp.Results[base+1]
		browseName := resp.Results[base+2]
		val := resp.Results[base+3]

		if nodeClass.Status != ua.StatusOK || ua.NodeClass(nodeClass.Value.Int()) != ua.NodeClassVariable {
			continue // not a variable, or couldn't read class
		}
		if accessLevel.Status != ua.StatusOK {
			continue
		}
		access := ua.AccessLevelType(accessLevel.Value.Uint())
		if access&ua.AccessLevelTypeCurrentWrite == 0 {
			continue // not writeable
		}

		tag := tag{
			NodeID:      nodeId,
			AccessLevel: access,
			Writable:    true,
		}
		if browseName.Status == ua.StatusOK && browseName.Value != nil {
			tag.BrowseName = browseName.Value.String()
		}
		if val != nil && val.Value != nil {
			tag.Value = val.Value.Value()
		}
		writeable = append(writeable, tag)
	}
	return writeable, nil
}

const chunkSize = 500 // 500 nodes * 4 attrs = 2000 ReadValueIDs per request
func readAllChunked(ctx context.Context, c *opcua.Client, ids []*ua.NodeID) []tag {
	var all []tag
	for start := 0; start < len(ids); start += chunkSize {
		end := start + chunkSize
		if end > len(ids) {
			end = len(ids)
		}
		found, err := readNodeChunk(ctx, c, ids[start:end])
		if err != nil {
			verboseOutput("chunk [%d:%d] read failed: %v\n", start, end, err)
			continue // one bad chunk doesn't abort the rest
		}
		all = append(all, found...)
	}
	return all
}

func generateCertificate() {
	appURI, _ := url.Parse("urn:cdino:opcua-recon")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "opcua-recon-client",
			Organization: []string{"cdino"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0), // valid 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{appURI},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	certOut, _ := os.Create("client_cert.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyOut, _ := os.Create("client_key.pem")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

}

func tokenTypeName(t ua.UserTokenType) string {
	switch t {
	case ua.UserTokenTypeAnonymous:
		return "Anonymous (guest)"
	case ua.UserTokenTypeUserName:
		return "Username/Password"
	case ua.UserTokenTypeCertificate:
		return "X.509 Certificate"
	case ua.UserTokenTypeIssuedToken:
		return "Issued Token"
	default:
		// Sprintf builds a string instead of printing it. %d formats the
		// numeric enum value so unknown types still show something useful.
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

func shortPolicy(uri string) string {
	// Walk backwards from the end of the string looking for '#'.
	// len(uri)-1 is the last index; i-- decrements each iteration.
	for i := len(uri) - 1; i >= 0; i-- {
		// Strings are indexed as bytes; a single-quote literal like '#' is a
		// byte (rune) constant. If this byte is '#', return everything after it.
		if uri[i] == '#' {
			// uri[i+1:] is a "slice expression": from index i+1 to the end.
			return uri[i+1:]
		}
	}
	// If we never found a '#': empty string gets a placeholder, otherwise
	// return the URI unchanged.
	if uri == "" {
		return "(none)"
	}
	return uri
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func verboseOutput(output string, args ...interface{}) {
	if verbose {
		fmt.Printf(output, args...)
	}
}
