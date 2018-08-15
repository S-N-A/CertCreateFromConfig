package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

type CertificateTemplate struct {
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizationalUnit"`
	CommonName         string   `json:"commonName"`
	IPAddresses        []string `json:"IP"`
}

func main() {
	var CertTemplate CertificateTemplate

	file, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	byteConfig, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(byteConfig, &CertTemplate)
	if err != nil {
		log.Fatal(err)
	}
	ips := []net.IP{}
	for _, ip := range CertTemplate.IPAddresses {
		ips = append(ips, net.ParseIP(ip))
	}
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)
	subject := pkix.Name{
		Organization:       CertTemplate.Organization,
		OrganizationalUnit: CertTemplate.OrganizationalUnit,
		CommonName:         CertTemplate.CommonName,
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	pk, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey,
		pk)
	if err != nil {
		log.Println("Couldn't create certificate, check template")
		log.Fatal(err)
	}

	certOut, _ := os.Create("cert.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, _ := os.Create("key.pem")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
	keyOut.Close()

}
