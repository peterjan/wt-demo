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
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/webtransport-go"
)

const (
	alpn = "webtransport-go / quic-go"

	qlogDir = "qlog"

	certFile = "certificate.pem"
	keyFile  = "certificate.key"

	defaultCertValidity     = 10 * 24 * time.Hour
	defaultLoadCertFromDisk = true
)

type (
	client struct {
		d webtransport.Dialer
	}

	server struct {
		s *webtransport.Server
	}
)

func NewClient(tlsCfg *tls.Config) *client {
	x509Cert, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(x509Cert)
	return &client{
		d: webtransport.Dialer{
			RoundTripper: &http3.RoundTripper{
				TLSClientConfig: &tls.Config{
					RootCAs:            certPool,
					InsecureSkipVerify: true,
				},
				// QuicConfig: &quic.Config{Tracer: getQlogger()},
			},
		},
	}
}

func (c *client) Close() error {
	return errors.Join(
		c.d.RoundTripper.Close(),
		c.d.Close(),
	)
}

func NewServer(addr string, tlsCfg *tls.Config) *server {
	return &server{
		s: &webtransport.Server{
			H3: http3.Server{
				TLSConfig: tlsCfg,
				Addr:      addr,
			},
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (s *server) CertificateHash() string {
	x509Cert, err := x509.ParseCertificate(s.s.H3.TLSConfig.Certificates[0].Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	hash := sha256.Sum256(x509Cert.Raw)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (s *server) Close() error {
	return s.s.Close()
}

func (s *server) Run() {
	http.HandleFunc("/webtransport", func(w http.ResponseWriter, r *http.Request) {
		log.Println("incoming connection...")

		conn, err := s.s.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrading failed: %s", err)
			w.WriteHeader(500)
			return
		}
		defer func() {
			err = conn.CloseWithError(0, "")
			if err != nil {
				log.Fatal(err)
			}
		}()

		handleConn(conn)
	})

	log.Println("Server Certificate Hash")
	log.Println(s.CertificateHash())
	log.Println()

	log.Println("listening at", s.s.H3.Addr)
	if err := s.s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	fmt.Println("- - - - - - - - -")
	fmt.Println("WebTransport Demo")
	fmt.Println("- - - - - - - - -")
	fmt.Println()

	tlsCfg, err := buildTLSConfig(defaultLoadCertFromDisk)
	if err != nil {
		log.Fatal(err)
	}

	s := NewServer("localhost:4433", tlsCfg)
	defer s.Close()
	go s.Run()

	runEchoTest(tlsCfg)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	<-signalCh
	log.Println("Shutting down...")
	os.Exit(0)
}

func runEchoTest(tlsCfg *tls.Config) {
	c := NewClient(tlsCfg)
	defer c.Close()

	rsp, sess, err := c.d.Dial(context.Background(), "https://localhost:4433/webtransport", nil)
	if err != nil {
		log.Fatal(err)
	} else if rsp.StatusCode != 200 {
		log.Fatalf("unexpected status code: %d", rsp.StatusCode)
	}

	str, err := sess.OpenStream()
	if err != nil {
		log.Fatal(err)
	}

	err = str.SetDeadline(time.Now().Add(time.Second))
	if err != nil {
		log.Fatal(err)
	}

	n, err := str.Write([]byte("yo"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("sent %d bytes", n)

	err = str.Close()
	if err != nil {
		log.Fatal(err)
	}

	reply, err := io.ReadAll(str)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("received", string(reply))
}

func handleConn(sess *webtransport.Session) {
	for {
		select {
		case <-sess.Context().Done():
			break
		default:
		}

		log.Println("waiting for stream...")
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			// log.Fatal(err) // TODO: handle this gracefully
			break
		}
		log.Println("accepted stream")

		n, err := io.CopyBuffer(stream, stream, make([]byte, 100))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("received %d bytes", n)

		stream.Close()
	}
}

// create a qlog file in QLOGDIR, if that environment variable is set
func getQlogger() func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
	tracer := func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
		if _, err := os.Stat(qlogDir); os.IsNotExist(err) {
			if err := os.MkdirAll(qlogDir, 0755); err != nil {
				log.Fatal(err)
			}
		}

		role := "server"
		if p == logging.PerspectiveClient {
			role = "client"
		}
		filename := fmt.Sprintf("./%s/log_%x_%s.qlog", qlogDir, connID, role)
		log.Println("creating", filename)
		f, err := os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}

		return qlog.NewConnectionTracer(f, p, connID)
	}
	return tracer
}

func buildTLSConfig(loadFromDisk bool) (cfg *tls.Config, err error) {
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

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
	}, nil
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
