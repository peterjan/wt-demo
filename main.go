package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

const (
	certFile = "certificate.pem"
	keyFile  = "certificate.key"

	defaultCertValidity     = 10 * 24 * time.Hour
	defaultLoadCertFromDisk = true
)

func main() {
	fmt.Println("- - - - - - - - -")
	fmt.Println("WebTransport Demo")
	fmt.Println("- - - - - - - - -")
	fmt.Println()

	tlsCfg, hash, err := buildTLSConfig(defaultLoadCertFromDisk)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Server Certificate Hash")
	fmt.Println(base64.StdEncoding.EncodeToString(hash[:]))
	fmt.Println()

	server := webtransport.Server{
		H3: http3.Server{
			TLSConfig: tlsCfg,
			Addr:      "localhost:4433",
		},
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	defer server.Close()

	http.HandleFunc("/demo", func(w http.ResponseWriter, r *http.Request) {
		log.Println("incoming connection...")

		conn, err := server.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrading failed: %s", err)
			w.WriteHeader(500)
			return
		}
		defer func() {
			_ = conn.CloseWithError(0, "")
		}()

		handleConn(conn)
	})

	log.Println("listening at", server.H3.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func handleConn(sess *webtransport.Session) {
	for {
		log.Println("waiting for stream...")
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		log.Println("accepted stream")

		s, err := io.ReadAll(stream)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("received ", string(s))

		_, err = stream.Write([]byte(s))
		if err != nil {
			log.Fatal(err)
		}

		log.Println("sent ", string(s))
		stream.Close()
	}
}

func buildTLSConfig(loadFromDisk bool) (cfg *tls.Config, hash [32]byte, err error) {
	var cert tls.Certificate

	if loadFromDisk {
		cert, err = loadTLSCertificate()
		if err != nil {
			return
		}
	} else {
		cert, err = generateTLSCertificate()
		if err != nil {
			return
		}
	}

	var x509Cert *x509.Certificate
	x509Cert, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}

	hash = sha256.Sum256(x509Cert.Raw)
	cfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	return
}

func loadTLSCertificate() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func generateTLSCertificate() (tls.Certificate, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return tls.Certificate{}, err
	}

	serial := int64(binary.BigEndian.Uint64(b))
	if serial < 0 {
		serial = -serial
	}
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(defaultCertValidity),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, certTempl, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{ca.Raw},
		PrivateKey:  caPrivateKey,
		Leaf:        ca,
	}, nil
}
