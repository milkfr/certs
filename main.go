package main

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/tls"
	"time"
	"runtime"
	"math/big"
	"crypto/x509/pkix"
	"net"
	"sort"
	"crypto/sha1"
	"bytes"
	"encoding/pem"
	"crypto/cipher"
	"errors"
	"crypto/sha256"
	"crypto/aes"
	"strings"
	"io/ioutil"
	"log"
	"flag"
)


var SignerVersion = ":version1"

func hashSorted(lst []string) []byte {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha1.New()
	for _, s := range c {
		h.Write([]byte(s + ","))
	}
	return h.Sum(nil)
}

func signHost(ca tls.Certificate, hosts []string) (err error) {
	var x509ca *x509.Certificate

	// Use the provided ca and not the global proxyCa for certificate generation.
	if x509ca, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return
	}

	start := time.Unix(0, 0)
	end, err := time.Parse("2006-01-02", "2049-12-31")
	if err != nil {
		return
	}

	// 生成serial的hash
	hash := hashSorted(append(hosts, SignerVersion, ":"+runtime.Version()))

	serial := new(big.Int)
	serial.SetBytes(hash)

	template := x509.Certificate {
		SerialNumber: serial,
		Issuer: x509ca.Subject,
		Subject: pkix.Name {
			Organization: []string{"milkfr"},
		},
		NotBefore: start,
		NotAfter: end,
		// KeyUsage, ExtKeyUsage, BasicConstraintsValid什么用处
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// IP，DNS参数
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			template.Subject.CommonName = h
		}
	}

	// 生成新Rand，使用和ca.PrivateKey有关的aes算法来随机
	var csprng counterEncryptorRand
	if csprng, err = newCounterEncryptorRandFromKey(ca.PrivateKey, hash); err != nil {
		return
	}

	// 用新Rand的随机算法生成公私钥对
	var certpriv *rsa.PrivateKey
	if certpriv, err = rsa.GenerateKey(&csprng, 2048); err != nil {
		return
	}

	var derBytes []byte
	// 使用根证书签名
	// x509.CreateCertificate(rand.Reader, template, RootCa, &Key.PublicKey, RootKey)
	if derBytes, err = x509.CreateCertificate(&csprng, &template, x509ca, &certpriv.PublicKey, ca.PrivateKey); err != nil {
		return
	}
	certBuffer := bytes.Buffer{}
	pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBuffer := bytes.Buffer{}
	pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certpriv)})

	err = ioutil.WriteFile("ca.crt", certBuffer.Bytes(), 0644)
	if err != nil {
		return
	}
	err = ioutil.WriteFile("ca.key", keyBuffer.Bytes(), 0644)
	if err != nil {
		return
	}

	return nil
}
type counterEncryptorRand struct {
	cipher cipher.Block  // aes
	counter []byte
	rand []byte
	ix int
}

func (c *counterEncryptorRand) Seed(b []byte) {
	if len(b) != len(c.counter) {
		panic("SetCounter: wrong counter size")
	}
	copy(c.counter, b)
}

func (c *counterEncryptorRand) refill() {
	c.cipher.Encrypt(c.rand, c.counter)
	for i := 0; i < len(c.counter); i++ {
		if c.counter[i]++; c.counter[i] != 0 {
			break
		}
	}
	c.ix = 0
}

func (c *counterEncryptorRand) Read(b []byte) (n int, err error) {
	if c.ix == len(c.rand) {
		c.refill()
	}
	if n = len(c.rand) - c.ix; n > len(b) {
		n = len(b)
	}
	copy(b, c.rand[c.ix:c.ix+n])
	c.ix+=n
	return
}

func newCounterEncryptorRandFromKey(key interface{}, seed []byte) (r counterEncryptorRand, err error) {
	var keyBytes []byte
	switch key := key.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	default:
		err = errors.New("only RSA keys supported")
		return
	}
	h := sha256.New()
	if r.cipher, err = aes.NewCipher(h.Sum(keyBytes)[:aes.BlockSize]); err != nil {
		return
	}
	r.counter = make([]byte, r.cipher.BlockSize())
	if seed != nil {
		copy(r.counter, h.Sum(seed)[:r.cipher.BlockSize()])
	}
	r.rand = make([]byte, r.cipher.BlockSize())
	r.ix = len(r.rand)
	return
}

func stripPort(s string) string {
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}

func TLSSignHostFromCA(ca *tls.Certificate, host string) {
	err := signHost(*ca, []string{stripPort(host)})
	if err != nil {
		log.Println(err)
	}
}

func main() {
	var host = flag.String("hostname", "milkfr.github.io", "Specified domain name")
	flag.Parse()

	var err error

	caCert, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		panic("Error read ca.pem" + err.Error())
	}
	caKey, err := ioutil.ReadFile("ca.key.pem")
	if err != nil {
		panic("Error read ca.key.pem" + err.Error())
	}

	var ca, caErr = tls.X509KeyPair(caCert, caKey)
	if caErr != nil {
		panic("Error parsing builtin CA " + caErr.Error())
	}
	if ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}

	TLSSignHostFromCA(&ca, *host)
}

