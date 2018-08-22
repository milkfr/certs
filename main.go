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
	"flag"
	"io/ioutil"
	"log"
)


func init() {
	if CAErr != nil {
		panic("Error parsing builtin CA " + CAErr.Error())
	}
	var err error
	if CA.Leaf, err = x509.ParseCertificate(CA.Certificate[0]); err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}
}

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIIF+jCCA+KgAwIBAgIJAPDundaYfvCsMA0GCSqGSIb3DQEBCwUAMIGRMQswCQYD
VQQGEwJDTjERMA8GA1UECAwIemhlamlhbmcxETAPBgNVBAcMCGhhbmd6aG91MQ8w
DQYDVQQKDAZtaWxrZnIxDzANBgNVBAsMBnNjeXRoZTEZMBcGA1UEAwwQbWlsa2Zy
LmdpdGh1Yi5pbzEfMB0GCSqGSIb3DQEJARYQMjkxNTA5NzIyQHFxLmNvbTAeFw0x
ODA3MTgwMzE1MjlaFw0zODA3MTMwMzE1MjlaMIGRMQswCQYDVQQGEwJDTjERMA8G
A1UECAwIemhlamlhbmcxETAPBgNVBAcMCGhhbmd6aG91MQ8wDQYDVQQKDAZtaWxr
ZnIxDzANBgNVBAsMBnNjeXRoZTEZMBcGA1UEAwwQbWlsa2ZyLmdpdGh1Yi5pbzEf
MB0GCSqGSIb3DQEJARYQMjkxNTA5NzIyQHFxLmNvbTCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBAKpHHZY0Q2wRpkAjIxYTTbNPt+oGs887qy008NYdiZZM
BMU15ODVYXCvISi8g9ESd4iZ7Bz5u77lCKmdXJm4We4UyEQ/a9ZjZC5YhV48HOGb
h415ZKG77ByIJfhCqn51ITGJy/SxidZUVtluV/VFnkyTPOrLRGy0qXoz+cwbYN9j
Ry6KeEJCNAf6Q+h6PnyXX0kFeuSthsPWuDXF7OSgGFFFnn77zXuxanEE+vL+nGre
i1MbG/+HVixjzW9eRGHBvIAS4Rq9Zq+/bRP+j+xK2fOiGWqMdfsr5Eack//Uc1ef
WXFT8ezSsLwRzD42W5JOMEHqOJCLw8xaWrL1qN4nE15HV6lTjMsDhmKlkuF3P8Pj
/CidfiphY3Dwj/Q/YmTcjrNLyBOsPae2+r/VLH90JawApYtveFwABlyeqhK35OGg
K0ed2ePXtY1k06xyhDmqrTHIoJQFHgIhpN/QCct3C0NNDO8QeqCV02SxjSwguISt
g7E4qsb5ea06jc8Bq/UzsVYSTV9NKC+moQkUC54MH73AyQMr7To/k0QYUDVNO0sC
p0rxswUCUXxumbWle8zetglnRLA9ALE825u8H8mF2uLb2ayzaRMVtDsoeUWrmefC
y2BC4VC/O9iFwArBngEZf0o9ZQfdV2tnq9ZnBF7TlMVoLnAQJfUvEIPndjkGP/5j
AgMBAAGjUzBRMB0GA1UdDgQWBBRVeTT6NtMIKnS7vyCHZYp6ctHctDAfBgNVHSME
GDAWgBRVeTT6NtMIKnS7vyCHZYp6ctHctDAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA4ICAQAVjtvkcKcejzlw1xV3FT/7Xdl/0brxo/26wkWEa2DAVdPf
XpRczb0seePr+j6r98+ZYTa9FJbiPKnc/7wwy0Q3ugL4suZAXXfNcKUAUMotj9L4
e4yB699hKTOuCL1N2mLww9NbpF49eTbpCp8lcxkE+fZASXIsVnc+we58Byp7l+VO
MjqpxYertLzx/dZ9cLvnguUTRLWdRLSfHM8QoUQbtkkID0c74PY/sOhcfPKHjgPY
koyabN6l5yTIzJLffqnId/y0+QQC0961bVoQ13Cw/hoEz1CJy6znWcZVh+svVyUk
od6uZ1jon+wXNlY5ue+p6xIHrefCKVt7Xsfa97qRe8WSmDtuWujAOBWT3z4siX3C
r2LyDaDl5YjTLTUD5/YVav9QNMpu3s7WLSSv/jS7JUJhrrHo9WB+5kUg/rpvMZN6
eejgrFlcof+9S+0wjMrFph7eg9U0pgn6Ez0c7hyFgAaML2/Q3bPzNYBQW3Jp+HgG
gMqC57PQ+UIdE0FOsvoHs6+YUYwRBdKZTs3+tbdvvWMhjFxYmfC3Vd6nzoHJXJGA
TIf5UfTzKEl/nFylH+zv9owF7N9jRlcX2RCDw7ruMdzQBTWC+UCSgAl+1KTYfOPI
UqGe0ZmXPBGG/Uq3HrJmYaL/p9KSH2GaKJsENXpyIAW4s72E7lqVzPIsw7qoyQ==
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)

var CA, CAErr = tls.X509KeyPair(CA_CERT, CA_KEY)

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
			Organization: []string{"Proxy"},
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

	err = ioutil.WriteFile("ca.cer", certBuffer.Bytes(), 0644)
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
	TLSSignHostFromCA(&CA, *host)
}

