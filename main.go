package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type SshKeyPair struct {
	PublicKey  string
	PrivateKey string
}

func main() {
	 var sshPair SshKeyPair
	if err := MakePubPvtSSHKey(&sshPair); err != nil {
		fmt.Println("ERROR %v", err.Error())
		return
	}
	fmt.Println(sshPair.PublicKey)
	fmt.Println(sshPair.PrivateKey)
}

func MakePubPvtSSHKey(outPair *SshKeyPair) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	outPair.PrivateKey = string(pem.EncodeToMemory(privateKeyPEM))

	// generate public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	outPair.PublicKey = string(ssh.MarshalAuthorizedKey(pub))
	return nil
}
