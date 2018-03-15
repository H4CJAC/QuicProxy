package genCerts

import (
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"math/big"
	"math/rand"
	"crypto/x509/pkix"
	"time"
	rand2 "crypto/rand"
	"crypto/tls"
	"os"
	"net"
	"GoQuicProxy/constValue"
)

const(
	rootCa = "./certs/ca/ca.cer"
	rootKey = "./certs/ca/cakey.pem"
)

var(
	ca *x509.Certificate
	key *rsa.PrivateKey
)

func LoadRootCA() error {
	//读取根证书文件和私钥文件
	caFile, err := ioutil.ReadFile(rootCa)
	if err != nil {
		return err
	}
	caKey, err := ioutil.ReadFile(rootKey)
	if err != nil {
		return err
	}
	//解析
	caBlock, _ := pem.Decode(caFile)
	ca, err = x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}
	keyBlock, _ := pem.Decode(caKey)
	key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	return nil
}

func GenCert(addr string) (*tls.Certificate, error) {
	//检测是否已存在该证书
	cerFile, keyFile := constValue.CERTOUTS_PATH + addr + "cer.pem", constValue.CERTOUTS_PATH + addr + "key.pem"
	_, ec := os.Stat(cerFile)
	_, ek := os.Stat(keyFile)
	if os.IsNotExist(ec) || os.IsNotExist(ek) {
		if err := createCer(addr, cerFile, keyFile); err != nil {
			return nil, err
		}
	}
	cer, err := tls.LoadX509KeyPair(cerFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &cer, nil
}

func createCer(addr string, cerFile string, keyFile string) error {
	//证书模板
	cerModel := &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()),
		Subject: pkix.Name{
			Country: []string{"CN"},
			Organization: []string{addr},
			OrganizationalUnit: []string{addr},
			Province: []string{"GD"},
			CommonName: addr,
			Locality: []string{"GD"},
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(100, 0, 0),
		BasicConstraintsValid: true,
		IsCA: false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		EmailAddresses: []string{addr},
		IPAddresses: []net.IP{[]byte{127,0,0,1}},
		DNSNames: []string{addr},
	}
	//生成公私钥对
	priKey, err := rsa.GenerateKey(rand2.Reader, 2048)
	if err != nil {
		return err
	}
	cer, err := x509.CreateCertificate(rand2.Reader, cerModel, ca, &priKey.PublicKey, key)
	if err != nil {
		return err
	}
	//编码生成证书和私钥文件
	cerPem := &pem.Block{
		Type: "CERTIFICATE",
		Bytes: cer,
	}
	keyBuf := x509.MarshalPKCS1PrivateKey(priKey)
	keyPem := &pem.Block{
		Type: "PRIVATE KEY",
		Bytes: keyBuf,
	}
	cerFP, err := os.Create(cerFile)
	if err != nil {
		return err
	}
	keyFP, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	err = pem.Encode(cerFP, cerPem)
	if err != nil {
		return err
	}
	err = pem.Encode(keyFP, keyPem)
	if err != nil {
		return err
	}
	return nil
}

