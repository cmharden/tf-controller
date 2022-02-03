package mtls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
)

const (
	org = "tf-controller"
)

// CertBundle holds the certs and keys for a given certificate bundle
type CertBundle struct {
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// CreateCA generates a self-signed certificate that can be used to sign other certificates.
func CreateCA(name string, ttl time.Duration) (*CertBundle, error) {
	start := time.Now()
	end := start.Add(ttl)

	templ := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{org},
		},
		DNSNames:              []string{name},
		NotBefore:             start,
		NotAfter:              end,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// for a self signed cert the template is passed as the parent
	der, err := x509.CreateCertificate(rand.Reader, templ, templ, key.Public(), key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	certPEM, keyPEM, err := pemEncode(der, key)
	if err != nil {
		return nil, err
	}

	return &CertBundle{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// IssueCert generates a x509 certificate signed by the provided CA
func (ca *CertBundle) IssueCert(name string, ttl time.Duration) (*CertBundle, error) {
	start := time.Now()
	end := start.Add(ttl)
	templ := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{org},
		},
		DNSNames:              []string{org},
		NotBefore:             start,
		NotAfter:              end,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, templ, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	certPEM, keyPEM, err := pemEncode(der, key)
	if err != nil {
		return nil, err
	}

	return &CertBundle{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// GetGRPCClientCredentials returns transport credentials for a client connection
func GetGRPCClientCredentials(c *CertBundle, caCertPEM []byte) (credentials.TransportCredentials, error) {
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to add client CA")
	}

	serverCert, err := tls.X509KeyPair(c.CertPEM, c.KeyPEM)
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		RootCAs:      certPool,
	}

	return credentials.NewTLS(config), nil
}

// pemEncode takes a certificate and encodes it as PEM
func pemEncode(certificateDER []byte, key *rsa.PrivateKey) ([]byte, []byte, error) {
	certBuf := &bytes.Buffer{}
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}); err != nil {
		return nil, nil, errors.Wrap(err, "encoding cert")
	}
	keyBuf := &bytes.Buffer{}
	if err := pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil, nil, errors.Wrap(err, "encoding key")
	}
	return certBuf.Bytes(), keyBuf.Bytes(), nil
}

func ValidCert(caCert, cert, key []byte, dnsName string, at time.Time) (bool, error) {
	if len(caCert) == 0 || len(cert) == 0 || len(key) == 0 {
		return false, errors.New("empty cert")
	}

	pool := x509.NewCertPool()
	caDer, _ := pem.Decode(caCert)
	if caDer == nil {
		return false, errors.New("bad CA cert")
	}
	cac, err := x509.ParseCertificate(caDer.Bytes)
	if err != nil {
		return false, errors.Wrap(err, "parsing CA cert")
	}
	pool.AddCert(cac)

	_, err = tls.X509KeyPair(cert, key)
	if err != nil {
		return false, errors.Wrap(err, "building key pair")
	}

	b, _ := pem.Decode(cert)
	if b == nil {
		return false, errors.New("bad private key")
	}

	crt, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return false, errors.Wrap(err, "parsing cert")
	}
	_, err = crt.Verify(x509.VerifyOptions{
		DNSName:     dnsName,
		Roots:       pool,
		CurrentTime: at,
	})
	if err != nil {
		return false, errors.Wrap(err, "verifying cert")
	}
	return true, nil
}
