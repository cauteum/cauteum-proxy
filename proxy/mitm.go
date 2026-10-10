package proxy

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	maxCachedLeafs = 256
	leafTTL        = 24 * time.Hour
	// Cached leafs are re-issued once they get this close to NotAfter, so a
	// long-running sidecar never presents an expired certificate.
	leafRenewBefore = time.Hour
)

// MitmCA is an ephemeral sandbox CA used for TLS terminate (HTTPS L7).
type MitmCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	tlsCert tls.Certificate
	pem     []byte

	mu       sync.Mutex
	leafs    map[string]*list.Element
	lru      *list.List
	inFlight map[string]*leafCall
}

type cachedLeaf struct {
	host string
	cert *tls.Certificate
}

type leafCall struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

// GenerateMitmCA creates a new ephemeral CA.
func GenerateMitmCA() (*MitmCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"cautem"},
			CommonName:   "cautem Sandbox Proxy CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certificateAuthorityLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &MitmCA{
		cert:     cert,
		key:      key,
		tlsCert:  tlsCert,
		pem:      certPEM,
		leafs:    make(map[string]*list.Element),
		lru:      list.New(),
		inFlight: make(map[string]*leafCall),
	}, nil
}

// CertPEM returns the CA certificate PEM.
func (c *MitmCA) CertPEM() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.pem...)
}

// WritePEM writes the CA certificate to path.
func (c *MitmCA) WritePEM(path string) error {
	if c == nil {
		return fmt.Errorf("mitm: nil ca")
	}
	return os.WriteFile(path, c.pem, 0o644)
}

// WriteBundle writes system CA roots (if found) plus the cautem CA to path.
func (c *MitmCA) WriteBundle(path string) error {
	if c == nil {
		return fmt.Errorf("mitm: nil ca")
	}
	var b []byte
	for _, p := range systemCAPaths() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		b = append(b, data...)
		if len(b) > 0 && b[len(b)-1] != '\n' {
			b = append(b, '\n')
		}
		break
	}
	b = append(b, c.pem...)
	return os.WriteFile(path, b, 0o644)
}

func systemCAPaths() []string {
	return []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/ssl/cert.pem",
	}
}

// Leaf returns a hostname leaf cert signed by this CA (cached).
func (c *MitmCA) Leaf(hostname string) (*tls.Certificate, error) {
	if c == nil {
		return nil, fmt.Errorf("mitm: nil ca")
	}
	host := strings.ToLower(strings.TrimSpace(hostname))
	if host == "" {
		return nil, fmt.Errorf("mitm: empty hostname")
	}
	c.mu.Lock()
	if element, ok := c.leafs[host]; ok {
		leaf := element.Value.(cachedLeaf).cert
		if leaf.Leaf != nil && time.Until(leaf.Leaf.NotAfter) > leafRenewBefore {
			c.lru.MoveToFront(element)
			c.mu.Unlock()
			return leaf, nil
		}
		c.lru.Remove(element)
		delete(c.leafs, host)
	}
	if call := c.inFlight[host]; call != nil {
		c.mu.Unlock()
		<-call.done
		return call.cert, call.err
	}
	call := &leafCall{done: make(chan struct{})}
	c.inFlight[host] = call
	c.mu.Unlock()
	leaf, err := c.generateLeaf(host)
	c.mu.Lock()
	if err == nil {
		if c.lru.Len() >= maxCachedLeafs {
			oldest := c.lru.Back()
			delete(c.leafs, oldest.Value.(cachedLeaf).host)
			c.lru.Remove(oldest)
		}
		c.leafs[host] = c.lru.PushFront(cachedLeaf{host: host, cert: leaf})
	}
	call.cert, call.err = leaf, err
	delete(c.inFlight, host)
	close(call.done)
	c.mu.Unlock()
	return leaf, err
}

func (c *MitmCA) generateLeaf(hostname string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		tmpl.DNSNames = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// Include CA in chain for clients that expect intermediates.
	certPEM = append(certPEM, c.pem...)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if tlsCert.Leaf, err = x509.ParseCertificate(der); err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

// ServerTLSConfig returns a tls.Config that presents a leaf for hostname.
func (c *MitmCA) ServerTLSConfig(hostname string) (*tls.Config, error) {
	leaf, err := c.Leaf(hostname)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ClientTLSConfig returns a tls.Config for dialing the real upstream.
func ClientTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
}

// RootPool returns a cert pool containing only this CA (for tests / clients).
func (c *MitmCA) RootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}
