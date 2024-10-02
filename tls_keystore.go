package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

var (
	ErrMissingCertificates = fmt.Errorf("no public certificates provided")
)

// TLSCertKeyStore wraps the stdlib tls.Certificate to return its contained key
// and certs.
type TLSCertKeyStore tls.Certificate

// GetKeyPair implements X509KeyStore using the underlying tls.Certificate
func (d TLSCertKeyStore) GetKeyPair() (crypto.PrivateKey, []byte, error) {
	if len(d.Certificate) < 1 {
		return nil, nil, ErrMissingCertificates
	}
	return d.PrivateKey, d.Certificate[0], nil
}

func (d TLSCertKeyStore) PublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	switch d.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return x509.RSA
	case *ecdsa.PrivateKey:
		return x509.ECDSA
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// GetChain impliments X509ChainStore using the underlying tls.Certificate
func (d TLSCertKeyStore) GetChain() ([][]byte, error) {
	return d.Certificate, nil
}
