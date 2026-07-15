// This line declares which "package" this file belongs to.
// In Go, a program that you can run must have a package called "main".
// (Libraries you import have other names, like "opcua" or "fmt".)
package main

// The import block lists the other packages this file uses.
// Standard-library packages are single words ("fmt", "os").
// Third-party ones are full paths that look like URLs ("github.com/...").
// Go is strict: if you import something and don't use it, it won't compile.
import (
	"bufio"
	"context" // for timeouts/cancellation — passed into network calls
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag" // parses command-line flags like -endpoint
	"fmt"  // formatted printing (Println, Printf, etc.)
	"math/big"
	"net/url"
	"os"     // access to os.Stderr and os.Exit for error handling
	"regexp" // to sort the list of auth methods alphabetically
	"time"   // for time.Second when building the timeout

	// The gopcua library, split into two packages we need:
	"github.com/fatih/color"
	"github.com/gopcua/opcua" // the client + GetEndpoints entry points
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua" // the OPC-UA type definitions (enums, structs)
)

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
`

// "func main()" is the entry point. When you run the program, Go calls this.
// The empty () means it takes no arguments; no return type means it returns nothing.
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
	flag.Parse()
	fmt.Printf("Username: %s\nPassword: %s\n", *user, *pass)

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
			scanServer(ctx, &endpoint, user, pass, probe_anon, probe_credentials, probe_write)
		}
	} else {
		fmt.Println("Target: ", *endpoint)
		scanServer(ctx, endpoint, user, pass, probe_anon, probe_credentials, probe_write)
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
		match, _ := regexp.MatchString(`\d*.\d*.\d*.\d*.:\d*`, target)
		if !match {
			target = target + string(port)
		}
		target = "opc.tcp://" + target
		targets = append(targets, target)
	}

	return targets
}

func scanServer(ctx context.Context, endpoint, user, pass *string, probe_anon, probe_credentials, probe_write *bool) {
	endpoints, err := opcua.GetEndpoints(ctx, *endpoint)

	if err != nil {
		fmt.Fprintf(os.Stderr, "GetEndpoints failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== %s ===\n%d endpoint(s)\n\n", *endpoint, len(endpoints))

	anyAnonymous := false
	anyCredential := false

	seen := make(map[string]bool)
	scanned_endpoints := []endpointDetails{}

	for i, ep := range endpoints {

		var methods []string

		for _, tok := range ep.UserIdentityTokens {
			// Convert the numeric token-type enum into a readable label.
			name := tokenTypeName(tok.TokenType)

			methods = append(methods, name)
			seen[name] = true

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
			runAnonymousProbe(ctx, *endpoint)
		}

		if *probe_credentials && anyCredential {
			color.Green("[*] Checking if Credential access works...")
			runCredentialProbe(ctx, ep, *user, *pass)
		}
		if *probe_write && (anyAnonymous || anyCredential) {
			runWriteableProbe(ctx, ep, *user, *pass, anyAnonymous)
		}
		os.Exit(0)
	}
	fmt.Println("---")

}

func runAnonymousProbe(ctx context.Context, endpoint string) {
	c, err := opcua.NewClient(endpoint, opcua.AuthAnonymous())
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
		fmt.Printf("[*] Attempting to find writeable tags with Anonymous credentials\n")

		c, err = opcua.NewClient(endpoint.EndpointURL, opcua.AuthAnonymous())
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
	var tags []tag
	err = browseTags(ctx, c.Node(id), 0, "", &tags, visited)
	fmt.Printf(prettyPrint(tags))

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

	)

	if err != nil {
		fmt.Printf("Attr read error: %v\n", err)
		return nil // bail out of THIS node, don't index into an empty slice

	}

	node_class := ua.NodeClass(attrs[0].Value.Int())
	browse_name := attrs[2]
	description := attrs[3]
	path = path + "." + browse_name.Value.String()

	if node_class == ua.NodeClassVariable {
		value, _ := n.Value(ctx)
		//fmt.Printf("Value: %v\n", value)
		access_level := ua.AccessLevelType(attrs[1].Value.Uint())
		//fmt.Printf("Access Level: %s\n", access_level)
		writable := access_level&ua.AccessLevelTypeCurrentWrite != 0
		if writable {
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

	//fmt.Printf("Node ID: %s\n", n.ID)
	//fmt.Printf("Browser Name: %s\n", browse_name.Value)
	//fmt.Printf("Description Name: %s\n\n", description.Value)

	nodes, err := n.ReferencedNodes(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)

	if err != nil {
		fmt.Printf("Couldn't get referenced nodes: %v", err)
		return nil
	}
	for _, node := range nodes {
		browseTags(ctx, node, level+1, path, tags, visited)
		if err != nil {
			continue
		}
	}

	return nil
}

// Returns the auth options plus the token type to select on the endpoint.
func authOptions(user, pass string) ([]opcua.Option, ua.UserTokenType) {
	if user == "" {
		return []opcua.Option{opcua.AuthAnonymous()}, ua.UserTokenTypeAnonymous
	}
	return []opcua.Option{opcua.AuthUsername(user, pass)}, ua.UserTokenTypeUserName
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
