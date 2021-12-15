package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	"github.com/bytedance/Elkeid/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	caPath      = flag.String("ca", "./ca.crt", "")
	certPath    = flag.String("cert", "./client.crt", "")
	privkeyPath = flag.String("privkey", "./client.key", "")
	svrTarget   = flag.String("svr", "", "")
)

func main() {
	flag.Parse()
	ca, err := os.ReadFile(*caPath)
	if err != nil {
		panic(err)
	}
	cert, err := os.ReadFile(*certPath)
	if err != nil {
		panic(err)
	}
	privkey, err := os.ReadFile(*privkeyPath)
	if err != nil {
		panic(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca)
	keyPair, err := tls.X509KeyPair(cert, privkey)
	if err != nil {
		panic(err)
	}
	conn, err := grpc.Dial(*svrTarget, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{keyPair},
		ServerName:   "elkeid.com",
		ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      certPool,
	})))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	client, err := proto.NewTransferClient(conn).Transfer(context.Background())
	if err != nil {
		panic(err)
	}
	client.CloseSend()
	fmt.Printf("validate target %v successfully", svrTarget)
}
