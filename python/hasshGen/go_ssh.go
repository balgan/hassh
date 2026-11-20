// Minimal golang.org/x/crypto/ssh server and client with library defaults,
// for hasshgen.py. Usage: go_ssh server | go_ssh client HOST:PORT
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == "client" {
		cfg := &ssh.ClientConfig{User: "hassh", HostKeyCallback: ssh.InsecureIgnoreHostKey()}
		if c, err := ssh.Dial("tcp", os.Args[2], cfg); err == nil {
			c.Close()
		}
		return
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		return nil, errors.New("no")
	}}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaSigner, _ := ssh.NewSignerFromKey(rsaKey)
	cfg.AddHostKey(rsaSigner)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSigner, _ := ssh.NewSignerFromKey(ecKey)
	cfg.AddHostKey(ecSigner)
	l, err := net.Listen("tcp", ":22")
	if err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() { ssh.NewServerConn(c, cfg); c.Close() }()
	}
}
