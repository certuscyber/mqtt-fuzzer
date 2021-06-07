package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	f "mqttprox/fuzzer"
	"mqttprox/utils"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	u "github.com/dchest/uniuri"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type TLS struct {
	Country    []string
	Org        []string
	CommonName string
}

type Config struct {
	Remotehost     string   `json:"RemoteHost"`
	Localhost      string   `json:"LocalPost"`
	Localport      int      `json:"LocalProxyPort"`
	LocalportFuzz  int      `json:"LocalFuzzPort"`
	FuzzPayloadLen int      `json:"PayloadLength"`
	FuzzingDelay   int      `json:"Delay"`
	TLS            *TLS     `json:"TLS"`
	CACertFile     string   `json:"CACertFile"`
	CAKeyFile      string   `json:"CAKeyFile"`
	ClientCertFile string   `json:"ClientCertFile"` // client cert for mTLS
	ClientKeyFile  string   `json:"ClientKeyFile"`  // client priv key for mTLS
	IPS            []string // IPAddress for the child cert
	Names          []string // DNSNames for the child cert

}

var config Config
var ids = 0

func genCert() ([]byte, *rsa.PrivateKey) {
	s, _ := rand.Prime(rand.Reader, 128)
	ca := &x509.Certificate{
		SerialNumber: s,
		Subject: pkix.Name{
			Country:      config.TLS.Country,
			Organization: config.TLS.Org,
			CommonName:   config.TLS.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		fmt.Println("Failed to create a certificate", err)
	}
	return ca_b, priv
}

func genChildCert(cert tls.Certificate, ips, names []string) []byte {

	parent, err := x509.ParseCertificate(cert.Certificate[0])

	if err != nil {
		fmt.Println("create child cert failed")
		return nil
	}

	s, _ := rand.Prime(rand.Reader, 128)

	template := &x509.Certificate{
		SerialNumber:          s,
		Subject:               pkix.Name{Organization: []string{"Argo Incorporated"}},
		Issuer:                pkix.Name{Organization: []string{"Argo Incorporated"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if ips != nil {
		is := make([]net.IP, 0)
		for _, i := range ips {
			is = append(is, net.ParseIP(i))
		}
		template.IPAddresses = is
	}
	if names != nil {
		template.DNSNames = names
	}

	private := cert.PrivateKey.(*rsa.PrivateKey)

	certP, _ := x509.ParseCertificate(cert.Certificate[0])
	public := certP.PublicKey.(*rsa.PublicKey)

	cab, err := x509.CreateCertificate(rand.Reader, template, parent, public, private)
	if err != nil {
		fmt.Println("create ca failed", err)
		os.Exit(1)
	}

	fmt.Println("[*] Child Certificate files generated")
	return cab
}

//need to handle file size
//to capture fuzz packets
func recordTraffic(r io.Reader, source string, id int, isFuzz bool, fuzzPayloadLen int, fuzzingDelay int, requestID string) {
	if isFuzz {

		inputSource := source
		requests, err := os.OpenFile("./logs/requests.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}
		defer requests.Close()

		responses, err := os.OpenFile("./logs/responses.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}
		defer responses.Close()

		requestsLogger := log.New(requests, "", log.LstdFlags)
		responsesLogger := log.New(responses, "", log.LstdFlags)

		requestsLogger.SetOutput(&lumberjack.Logger{
			Filename:   "./logs/requests.log",
			MaxSize:    500,
			MaxBackups: 4,
			MaxAge:     4,
		})

		responsesLogger.SetOutput(&lumberjack.Logger{
			Filename:   "./logs/responses.log",
			MaxSize:    500,
			MaxBackups: 4,
			MaxAge:     4,
		})

		if strings.Compare(inputSource, "SERVER") == 0 {
			fmt.Println("Response received for request number: ", requestID)
		} else {
			fmt.Println("Sent request number: ", requestID)
		}

		data := make([]byte, 1024)
		for {
			n, err := r.Read(data)
			if n > 0 {
				content := utils.SliceToHex(data[:n])

				if strings.Compare(inputSource, "SERVER") == 0 {

					if err != nil {
						log.Fatal(err)
					} else {

						responsesLogger.Println("Response number: " + requestID + "\n" + content)
					}

				} else {
					if err != nil {
						log.Fatal(err)
					} else {

						requestsLogger.Println("Request number: " + requestID + "\n" + content)
					}
				}
			}
			if err != nil && err != io.EOF {
				fmt.Printf("unable to read data %v", err)
				break
			}
			if n == 0 {
				break
			}
		}
		requests.Close()
		responses.Close()

	} else if !isFuzz {
		data := make([]byte, 1024)
		for {
			n, err := r.Read(data)
			if n > 0 {
				tmp_var := hex.Dump(data[:n])
				fmt.Println(tmp_var)
				go f.StartFuzz(tmp_var, fuzzPayloadLen, fuzzingDelay)
			}
			if err != nil && err != io.EOF {
				fmt.Printf("unable to read data %v", err)
				break
			}
			if n == 0 {
				break
			}
		}
	}

}

func handleServerMessage(connR, connL net.Conn, id int, closer *sync.Once, isFuzz bool, fuzzPayloadLen int, fuzzingDelay int, requestID string) {
	// see comments in handleConnection

	closeFunc := func() {
		fmt.Println("[*] Connections closed.")
		_ = connL.Close()
		_ = connR.Close()
	}

	r, w := io.Pipe()
	tee := io.MultiWriter(connL, w)

	go recordTraffic(r, "SERVER", id, isFuzz, fuzzPayloadLen, fuzzingDelay, requestID)

	_, e := io.Copy(tee, connR)

	if e != nil && e != io.EOF {
		// check if error and handle gracefully
		netOpError, ok := e.(*net.OpError)
		if ok && netOpError.Err.Error() != "use of closed network connection" {
			fmt.Printf("bad io.Copy [handleServerMessage]: %v", e)
		}
	}

	// close connection
	closer.Do(closeFunc)
}

func handleConnection(connL net.Conn, isTLS bool, isFuzz bool, fuzzPayloadLen int, fuzzingDelay int, requestID string) {
	var err error
	var connR net.Conn
	var closer sync.Once

	// make sure connections get closed
	// ignore these variables
	closeFunc := func() {
		fmt.Println("[*] Connections closed")
		_ = connL.Close()
		_ = connR.Close()
	}

	if isTLS {
		conf := tls.Config{InsecureSkipVerify: true}

		if config.ClientKeyFile != "" { //use mtls
			cert, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
			if err != nil {
				fmt.Printf("couldn't load cert, %v", err)
				return
			}
			conf.Certificates = []tls.Certificate{cert}
		}

		connR, err = tls.Dial("tcp", config.Remotehost, &conf)
	} else {
		connR, err = net.Dial("tcp", config.Remotehost)
		//fmt.Printf("%s", connR)
	}

	if err != nil {
		fmt.Printf("[x] Couldn't connect: %v", err)
		return
	}

	fmt.Printf("[*][%d] Connected to server: %s\n", ids, connR.RemoteAddr())

	// setup handler to read from server and record logs
	go handleServerMessage(connR, connL, ids, &closer, isFuzz, fuzzPayloadLen, fuzzingDelay, requestID)

	// setup a pipe that will allow writing to the output (stdout) writer, without
	// consuming the data
	r, w := io.Pipe()

	// create a MultiWriter which allows writing to multiple writers at once - screen or logs and the remote connection
	tee := io.MultiWriter(connR, w)

	go recordTraffic(r, "CLIENT", ids, isFuzz, fuzzPayloadLen, fuzzingDelay, requestID)

	// consume all data and forward between connections in memory
	_, e := io.Copy(tee, connL)

	if e != nil && e != io.EOF {
		fmt.Printf("bad io.Copy [handleConnection]: %v", e)
	}
	// ensure connections are closed. With the sync, this will either happen here
	// or in the handleServerMessage function

	defer closer.Do(closeFunc)
	fmt.Println("Exiting the handle connection method for the regular listener")

}

func startListener(isTLS bool, isFuzz bool, fuzzPayloadLen int, fuzzingDelay int) {

	var err, errF error
	var conn, connFuzz net.Listener

	if !isFuzz {
		conn, err = net.Listen("tcp", fmt.Sprint(config.Localhost, ":", config.Localport))
		if err != nil {
			panic("failed to start listener: " + err.Error())
		}
	} else {
		connFuzz, errF = net.Listen("tcp", fmt.Sprint(config.Localhost, ":", config.LocalportFuzz))
		if errF != nil {
			panic("failed to start listener: " + errF.Error())
		}
	}

	if isTLS {
		var cert tls.Certificate
		if config.CACertFile != "" {
			cert, _ = tls.LoadX509KeyPair(config.CACertFile, config.CAKeyFile)
		} else {
			fmt.Println("[*] Generating cert")
			cab, priv := genCert()
			cert = tls.Certificate{
				Certificate: [][]byte{cab},
				PrivateKey:  priv,
			}
		}

		if config.IPS != nil || config.Names != nil {
			newCert := genChildCert(cert, config.IPS, config.Names)
			cert.Certificate = [][]byte{newCert}
		}

		// we don't have to set mTLS on the listener, it will simply accept connection with or
		// without the client supplying a cert. The mTLS part happens with the connection to the
		// upstream host
		conf := tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		/* optional to add mTLS on the listener side
		if config.ClientKeyFile != "" {
			caCert, err := ioutil.ReadFile(config.ClientKeyFile)
			if err != nil {
				log.Fatal(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			conf.ClientCAs = caCertPool
			conf.ClientAuth = tls.RequireAndVerifyClientCert
		} */

		conf.Rand = rand.Reader
		// wrap conn into a TLS listener

		if !isFuzz {
			conn = tls.NewListener(conn, &conf)
		} else {
			connFuzz = tls.NewListener(connFuzz, &conf)
		}
	}

	fmt.Println("[*] Listening...")

	if !isFuzz {
		fmt.Println("conn.close() being called in the startListener() method. isFuzz", isFuzz)
		defer conn.Close()
	} else {
		fmt.Println("connFuzz.close() being called in the startListener() method. isFuzz", isFuzz)
		defer connFuzz.Close()
	}

	if !isFuzz {
		for {
			cl, err := conn.Accept()
			if err != nil {
				fmt.Printf("server: accept: %v", err)
			}
			fmt.Printf("[*] Accepted from: %s\n", cl.RemoteAddr())
			s := u.NewLen(25)
			go handleConnection(cl, isTLS, isFuzz, fuzzPayloadLen, fuzzingDelay, s)

		}
	} else {
		for {
			clFuzz, errFuzz := connFuzz.Accept()
			if errFuzz != nil {
				fmt.Printf("server: accept: %v", errFuzz)

			}
			fmt.Printf("[*] Accepted from: %s\n", clFuzz.RemoteAddr())
			sf := u.NewLen(25)
			go handleConnection(clFuzz, isTLS, isFuzz, fuzzPayloadLen, fuzzingDelay, sf)

		}
	}
}

func setConfig(configFile string, localPort int, localHost, remoteHost string, caCertFile, caKeyFile string, clientCertFile, clientKeyFile string, localPortFuzz int, fuzzPayloadLen int, fuzzingDelay int) {
	if configFile != "" {
		data, err := ioutil.ReadFile(configFile)
		if err != nil {
			fmt.Println("[-] Not a valid config file: ", err)
			os.Exit(1)
		}
		err = json.Unmarshal(data, &config)
		if err != nil {
			fmt.Println("[-] Not a valid config file: ", err)
			os.Exit(1)
		}
	} else {
		config = Config{TLS: &TLS{}}
	}

	if caCertFile != "" {
		config.CACertFile = caCertFile
		config.CAKeyFile = caKeyFile
	}

	if clientCertFile != "" {
		config.ClientCertFile = clientCertFile
		config.ClientKeyFile = clientKeyFile
	}

	if localPort != 0 {
		config.Localport = localPort
	}
	if localHost != "" {
		config.Localhost = localHost
	}
	if remoteHost != "" {
		config.Remotehost = remoteHost
	}

	if localPortFuzz != 0 {
		config.LocalportFuzz = localPortFuzz
	}
	if fuzzPayloadLen != 0 {
		config.FuzzPayloadLen = fuzzPayloadLen
	}
	if fuzzingDelay > 1 {
		config.FuzzingDelay = fuzzingDelay
	}
}

func stageListener(isFuzz bool, tlsPtr *bool, fuzzPayloadLen int, fuzzingDelay int) {

	startListener(*tlsPtr, isFuzz, fuzzPayloadLen, fuzzingDelay)

}

func main() {

	localPort := flag.Int("p", 0, "Local Port to listen on")
	localHost := flag.String("l", "", "Local address to listen on")
	remoteHostPtr := flag.String("r", "", "Remote Server address host:port")
	configPtr := flag.String("c", "", "Use a config file (set TLS ect) - Commandline params overwrite config file")
	tlsPtr := flag.Bool("s", false, "Create a TLS Proxy")
	caCertFilePtr := flag.String("cert", "", "Use a specific ca cert file")
	caKeyFilePtr := flag.String("key", "", "Use a specific ca key file (must be set if --cert is set")
	clientCertPtr := flag.String("clientCert", "", "A public client cert to use for mTLS")
	clientKeyPtr := flag.String("clientKey", "", "A public client key to use for mTLS")

	//Added options
	localPortFuzz := flag.Int("f", 0, "Local Port to listen to the fuzzer")
	fuzzPayloadLen := flag.Int("P", 0, "Define the length of the variable header and payload")
	fuzzingDelay := flag.Int("d", 1, "Define time in milliseconds to wait before making a request. Default vaue is 0 seconds")

	flag.Parse()

	if *caCertFilePtr != "" && *caKeyFilePtr == "" {
		fmt.Println("[x] -key is required when -cert is set")
		os.Exit(1)
	}

	if *clientCertPtr != "" && *clientKeyPtr == "" {
		fmt.Println("[x] -clientKey is required when -clientCert is set")
		os.Exit(1)
	}

	setConfig(*configPtr, *localPort, *localHost, *remoteHostPtr, *caCertFilePtr, *caKeyFilePtr, *clientCertPtr, *clientKeyPtr, *localPortFuzz, *fuzzPayloadLen, *fuzzingDelay)

	if config.Remotehost == "" {
		fmt.Println("[x] Remote host required")
		flag.PrintDefaults()
		os.Exit(1)
	}
	// seperate listeners to ensure that fuzz controlled packets aren't reinjected into the fuzzer
	go stageListener(false, tlsPtr, *fuzzPayloadLen, *fuzzingDelay)
	// fuzz listener
	stageListener(true, tlsPtr, *fuzzPayloadLen, *fuzzingDelay)

	fmt.Println("Exiting the main goroutine.")
}
