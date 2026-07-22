package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
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

type tag struct {
	NodeID      *ua.NodeID
	BrowseName  string
	AccessLevel ua.AccessLevelType
	Writable    bool
	Value       interface{}
}

const maxDepth = 10

const banner = `
                                                                                
                                                                                                               
                                                                                                               
  ██████  ████████   ██████             █████ ████  ██████      ████████   ██████   ██████   ██████  ████████  
 ███░░███░░███░░███ ███░░███ ██████████░░███ ░███  ░░░░░███    ░░███░░███ ███░░███ ███░░███ ███░░███░░███░░███ 
░███ ░███ ░███ ░███░███ ░░░ ░░░░░░░░░░  ░███ ░███   ███████     ░███ ░░░ ░███████ ░███ ░░░ ░███ ░███ ░███ ░███ 
░███ ░███ ░███ ░███░███  ███            ░███ ░███  ███░░███     ░███     ░███░░░  ░███  ███░███ ░███ ░███ ░███ 
░░██████  ░███████ ░░██████             ░░████████░░████████    █████    ░░██████ ░░██████ ░░██████  ████ █████
 ░░░░░░   ░███░░░   ░░░░░░               ░░░░░░░░  ░░░░░░░░    ░░░░░      ░░░░░░   ░░░░░░   ░░░░░░  ░░░░ ░░░░░ 
          ░███                                                                                                 
          █████                                                                                                
         ░░░░░                                                                                                 

v1.0.2

by cdino
`

func main() {
	fmt.Println(banner)
	time.Sleep(500 * time.Millisecond)
	endpoint := flag.String("endpoint", "", "OPC-UA endpoint URL")
	ip := flag.String("ip", "", "OPC-UA server IP")
	ipFile := flag.String("ip-file", "", "New line deliminated file of IPs to scan")
	port := flag.Int("port", 4840, "OPC-UA server port. Default 4840")
	probeAnon := flag.Bool("probe-anon", false, "also actively test whether anonymous login truly works")
	user := flag.String("user", "", "Username for authentication")
	pass := flag.String("pass", "", "Password for authentication")
	probeCreds := flag.Bool("probe-creds", false, "Attempt authentication with credentials")
	probeWrite := flag.Bool("probe-write", false, "Scan for writeable tags")
	batchSize := flag.Int("batch-size", 50, "number of nodes to collect before reading their attributes (1 = stream one at a time, large = collect-all-then-read)")
	rewriteHost := flag.Bool("rewrite-host", false, "Rewrite the endpoint host with the provided host. required for scanning servers behind NAT/Firewalls")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose output")
	outputFile := flag.String("output-file", "", "a .csv output of writeable tags.")
	cleanupCerts := flag.Bool("cleanup-certs", false, "delete generated client certificate/key files when the scan finishes")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	verboseOutput("Flag Values:\n\tEndpoint: %s\n\tIP: %s\n\tIP File:%s\n\tPort: %d\n\tProbe Anon:%t\n\tProbe Creds:%t\n\tUsername: %s\n\tPassword: %s\n\tProbe Write: %t\n\tBatch Size: %d\nOutput File: %s\n", *endpoint, *ip, *ipFile, *port, *probeAnon, *probeCreds, *user, *pass, *probeWrite, *batchSize, *outputFile)

	var massScan = false
	if *ipFile != "" {
		massScan = true
	}
	if *ip != "" {
		url := fmt.Sprintf("opc.tcp://%s:%d", *ip, *port)
		endpoint = &url
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if massScan == true {
		targets := parseIPFile(*ipFile, *port)
		if targets == nil {
			return
		}
		fmt.Println("Targets: ", targets)
		for i, endpoint := range targets {
			fmt.Println(i + 1)
			scanServer(ctx, &endpoint, user, pass, outputFile, *probeAnon, *probeCreds, *probeWrite, *rewriteHost, *batchSize)
		}
	} else {
		fmt.Println("Target: ", *endpoint)
		scanServer(ctx, endpoint, user, pass, outputFile, *probeAnon, *probeCreds, *probeWrite, *rewriteHost, *batchSize)
	}

	if *cleanupCerts {
		os.Remove("client_cert.pem")
		os.Remove("client_key.pem")
	}
}

func parseIPFile(fileName string, port int) []string {
	var targets []string
	targetsFile, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "File Read Failed: %v\n", err)
		return nil
	}
	defer targetsFile.Close()

	scanner := bufio.NewScanner(targetsFile)

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

func scanServer(ctx context.Context, endpoint, user, pass, outputFile *string, probeAnon, probeCreds, probeWrite, rewriteHost bool, batchSize int) {
	endpoints, err := opcua.GetEndpoints(ctx, *endpoint)

	if err != nil {
		fmt.Fprintf(os.Stderr, "GetEndpoints failed: %v\n", err)
		return
	}

	fmt.Printf("=== %s ===\n%d endpoint(s)\n\n", *endpoint, len(endpoints))

	var dialledHost string
	if rewriteHost {
		dialledURL, err := url.Parse(*endpoint)
		if err != nil {
			fmt.Println("[-] Error parsing endpoint URL.")
			return
		}
		dialledHost = dialledURL.Hostname()
	}

	for i, ep := range endpoints {
		anyAnonymous := false
		anyCredential := false

		if rewriteHost {
			rewriteEndpointHost(ep, dialledHost) // just reuse the already-computed value
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

		fmt.Printf("[Endpoint %d]\n", i+1)
		fmt.Printf("  URL:             %s\n", ep.EndpointURL)
		fmt.Printf("  Security mode:   %s\n", ep.SecurityMode.String())
		fmt.Printf("  Security policy: %s\n", ep.SecurityPolicyURI)
		fmt.Printf("  Security level:  %d\n", int(ep.SecurityLevel))
		fmt.Printf("  Allows Anonymous Login:  %t\n", anyAnonymous)
		fmt.Printf("  Allows Credential Login:  %t\n", anyCredential)
		fmt.Printf("  Supported Login Methods:  %v\n", methods)
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

		if (probeAnon || probeCreds || probeWrite) && ep.SecurityMode != ua.MessageSecurityModeNone {
			color.Green("[*] Generating certificates")
			if err := generateCertificateForPolicy(ep.SecurityPolicyURI, "client_cert.pem", "client_key.pem"); err != nil {
				color.Red("[-] could not generate certificate, skipping probes for this endpoint: %v", err)
				continue
			}
		}

		if probeAnon && anyAnonymous {
			color.Green("[*] Checking if Anonymous access works...")
			runAnonymousProbe(ctx, ep, *endpoint)
		}

		if probeCreds && anyCredential {
			color.Green("[*] Checking if Credential access works...")
			runCredentialProbe(ctx, ep, *user, *pass)
		}
		if probeWrite && (anyAnonymous || anyCredential) {
			runWriteableProbe(ctx, ep, *user, *pass, anyAnonymous, anyCredential, batchSize, *outputFile)
		}
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

	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
		opcua.AuthAnonymous(),
	}
	if ep.SecurityMode != ua.MessageSecurityModeNone {
		opts = append(opts,
			opcua.CertificateFile("client_cert.pem"),
			opcua.PrivateKeyFile("client_key.pem"),
			opcua.ApplicationURI("urn:cdino:opcua-recon"),
		)
	}
	c, err := opcua.NewClient(endpoint, opts...)

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

	opts := []opcua.Option{
		opcua.AuthUsername(user, pass),
		opcua.SecurityFromEndpoint(endpoint, ua.UserTokenTypeUserName),
		opcua.ApplicationURI("urn:cdino:opcua-recon"),
	}
	if endpoint.SecurityMode != ua.MessageSecurityModeNone {
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

func runWriteableProbe(ctx context.Context, endpoint *ua.EndpointDescription, user, pass string, isAnon, isCreds bool, batchSize int, outputFile string) {
	ctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()
	var c *opcua.Client
	var err error

	if isAnon && !isCreds { //anon auth
		fmt.Printf("[*] Attempting to find writeable tags on %s with Anonymous credentials\n", endpoint.EndpointURL)

		opts := []opcua.Option{
			opcua.AuthUsername(user, pass),
			opcua.SecurityFromEndpoint(endpoint, ua.UserTokenTypeAnonymous),
		}
		if endpoint.SecurityMode != ua.MessageSecurityModeNone {
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
			color.Red("[-] anonymous login REJECTED (%v)\n", err)
			return
		}
	} else { //cred auth
		fmt.Printf("[*] Attempting to find writeable tags with %s:%s\n", user, pass)

		opts := []opcua.Option{
			opcua.AuthUsername(user, pass),
			opcua.SecurityFromEndpoint(endpoint, ua.UserTokenTypeUserName),
		}
		if endpoint.SecurityMode != ua.MessageSecurityModeNone {
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

	var nodeID string = "i=85"
	startNodeID, err := ua.ParseNodeID(nodeID)
	if err != nil {
		fmt.Printf("invalid node id: %s", err)
		return
	}
	visited := make(map[string]bool)
	var pending []*ua.NodeID
	var tags []tag
	start := time.Now()

	walkAndReport(ctx, c, c.Node(startNodeID), 0, visited, &pending, &tags, batchSize)
	flushBatch(ctx, c, &pending, &tags) // flush whatevers left under batchSize at the end

	color.Green("[+] %d writeable tags found", len(tags))
	verboseOutput("scan took %s, visited %d nodes", time.Since(start), len(visited))

	if outputFile != "" {
		appendCSV(outputFile, endpoint, isAnon, tags)
	}
	verboseOutput(prettyPrint(tags))

}

const attrsPerNode = 4

func readNodeChunk(ctx context.Context, c *opcua.Client, ids []*ua.NodeID) ([]tag, error) {
	attsToRead := make([]*ua.ReadValueID, 0, len(ids)*attrsPerNode)
	for _, nodeID := range ids {
		attsToRead = append(attsToRead,
			&ua.ReadValueID{NodeID: nodeID, AttributeID: ua.AttributeIDNodeClass},
			&ua.ReadValueID{NodeID: nodeID, AttributeID: ua.AttributeIDUserAccessLevel},
			&ua.ReadValueID{NodeID: nodeID, AttributeID: ua.AttributeIDBrowseName},
			&ua.ReadValueID{NodeID: nodeID, AttributeID: ua.AttributeIDValue},
		)
	}
	resp, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: attsToRead})
	if err != nil {
		return nil, err
	}
	verboseOutput("requested %d, got %d results", len(attsToRead), len(resp.Results))
	if len(resp.Results) < len(ids)*attrsPerNode {
		return nil, fmt.Errorf("server returned %d results, expected %d", len(resp.Results), len(ids)*attrsPerNode)
	}
	var writeable []tag
	for i, nodeID := range ids {
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
			NodeID:      nodeID,
			AccessLevel: access,
			Writable:    true,
		}
		if browseName.Status == ua.StatusOK && browseName.Value != nil {
			tag.BrowseName = browseName.Value.String()
		}
		if val != nil && val.Value != nil {
			tag.Value = val.Value.Value()
		}
		//color.Green("[+] Found writeable tag: " + tag.BrowseName)

		writeable = append(writeable, tag)
	}
	return writeable, nil
}

func walkAndReport(ctx context.Context, c *opcua.Client, n *opcua.Node, level int, visited map[string]bool, pending *[]*ua.NodeID, found *[]tag, batchSize int) {
	if level > maxDepth {
		color.Red("[-] Max Depth Exceeded (Level=%d MaxDepth=%d)", level, maxDepth)
		return
	}
	if ctx.Err() != nil {
		color.Red("[-] Context error:%s", ctx.Err())
		return
	}
	key := n.ID.String()
	if visited[key] {
		verboseOutput("[*] Node (%s) already visited, skipping", key)
		return
	}
	visited[key] = true
	if key == "i=2253" { // skip server diagnostics subtree
		verboseOutput("[*] Node (%s) part of server diagnostics, skipping", key)
		return
	}
	*pending = append(*pending, n.ID)
	if len(*pending) >= batchSize {
		flushBatch(ctx, c, pending, found)
	}
	nodes, err := n.ReferencedNodes(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	if err != nil {
		color.Red("browse failed at %s: %v", key, err)
		return
	}
	for _, child := range nodes {
		walkAndReport(ctx, c, child, level+1, visited, pending, found, batchSize)
	}
}

func flushBatch(ctx context.Context, c *opcua.Client, pending *[]*ua.NodeID, found *[]tag) {
	if len(*pending) == 0 {
		return
	}
	results, err := readNodeChunk(ctx, c, *pending)
	if err != nil {
		verboseOutput("batch read failed (%d nodes): %v", len(*pending), err)
		*pending = nil
		return
	}
	for _, t := range results {
		color.Green("[+] Found writeable tag: %s (%s)", t.BrowseName, t.NodeID.String())
	}
	*found = append(*found, results...)
	*pending = nil // reset for the next batch
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
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func verboseOutput(output string, args ...interface{}) {
	if verbose {
		fmt.Printf(output, args...)
		fmt.Println()
	}
}

func appendCSV(path string, endpoint *ua.EndpointDescription, isAnon bool, tags []tag) {
	if len(tags) == 0 {
		return
	}

	authMethod := "Username/Password"
	if isAnon {
		authMethod = "Anonymous"
	}

	// Open in append mode so multiple servers/endpoints all land in one file.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open output file: %v\n", err)
		return
	}
	defer f.Close()

	// Write the header only if the file was empty before this open.
	info, _ := f.Stat()
	w := csv.NewWriter(f)
	defer w.Flush()

	if info.Size() == 0 {
		w.Write([]string{"Endpoint", "SecurityMode", "SecurityPolicy", "AuthMethod", "NodeID", "BrowseName", "AccessLevel", "Value"})
	}

	for _, t := range tags {
		w.Write([]string{
			endpoint.EndpointURL,
			endpoint.SecurityMode.String(),
			endpoint.SecurityPolicyURI,
			authMethod,
			t.NodeID.String(),
			t.BrowseName,
			t.AccessLevel.String(),
			fmt.Sprintf("%v", t.Value),
		})
	}
}

func generateCertificateForPolicy(policyURI, certPath, keyPath string) error {
	policy := policyURI
	if idx := strings.LastIndex(policyURI, "#"); idx != -1 {
		policy = policyURI[idx+1:]
	}

	if policy == "None" {
		return nil
	}

	keySize := 2048
	if policy == "Basic128Rsa15" || policy == "Basic256" {
		keySize = 1024
	}

	if certSatisfiesPolicy(certPath, keySize) {
		return nil // existing cert is adequate, reuse it
	}

	appURI, _ := url.Parse("urn:cdino:opcua-recon")
	priv, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("[-] failed to generate serial number: %s", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "opcua-recon-client", Organization: []string{"cdino"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{appURI},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("writing cert file: %w", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("writing key file: %w", err)
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return nil
}

func certSatisfiesPolicy(certPath string, requiredKeySize int) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false // doesn't exist or unreadable — needs generating
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false // not RSA — regenerate
	}
	return pub.N.BitLen() >= requiredKeySize
}
