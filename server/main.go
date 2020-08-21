package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

var (
	serverListen string
	httpListen   string
)

const (
	chunkSize = 254
)

func init() {
	flag.StringVar(&serverListen, "listen", ":53", "Listen address for the server")
	flag.StringVar(&httpListen, "http-listen", ":8080", "Listen address for the http server")
}

type deleteToken struct {
	Signature string `json:"signature"`
	FileID    string `json:"file_id"`
}

type deleteResponse struct {
	Error    bool   `json:"error"`
	ErrorMsg string `json:"error_msg"`
	OK       bool   `json:"ok"`
}

func (d *deleteResponse) JSON() []byte {
	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return b
}

type uploadResponse struct {
	Error       bool   `json:"error"`
	ErrorMsg    string `json:"error_msg"`
	UUID        string `json:"uuid"`
	Size        int64  `json:"size"`
	SHA1        string `json:"sha1"`
	DeleteToken string `json:"delete_token"`
}

func (u *uploadResponse) JSON() []byte {
	b, err := json.Marshal(u)
	if err != nil {
		panic(err)
	}
	return b
}

func readSigningKey(path string) (crypto.PrivateKey, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func readSigningPubKey(path string) (crypto.PublicKey, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func deleteFile(w http.ResponseWriter, r *http.Request) {
	k, err := readSigningPubKey("data/keys/pub")
	if err != nil {
		logrus.WithError(err).Error("could not read signing key")
		result := deleteResponse{
			Error:    true,
			ErrorMsg: err.Error(),
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(result.JSON())
		return
	}

	tokens, ok := r.URL.Query()["token"]

	if !ok || len(tokens[0]) < 1 {
		logrus.WithError(err).Error("no tokens givem")
		result := deleteResponse{
			Error:    true,
			ErrorMsg: "no tokens given",
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(result.JSON())
		return
	}

	token := tokens[0]

	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		logrus.WithError(err).Error("invalid token")
		result := deleteResponse{
			Error:    true,
			ErrorMsg: err.Error(),
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(result.JSON())
		return
	}

	var tkn deleteToken
	err = json.Unmarshal(decodedToken, &tkn)
	if err != nil {
		logrus.WithError(err).Error("invalid token")
		result := deleteResponse{
			Error:    true,
			ErrorMsg: err.Error(),
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(result.JSON())
		return
	}

	sig, err := hex.DecodeString(tkn.Signature)
	if err != nil {
		logrus.WithError(err).Error("invalid signature (hex)")
		result := deleteResponse{
			Error:    true,
			ErrorMsg: err.Error(),
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(result.JSON())
		return
	}

	valid := ed25519.Verify(k.(ed25519.PublicKey), []byte(tkn.FileID), sig)
	if !valid {
		logrus.WithError(err).Error("signature does not match")
		result := deleteResponse{
			Error:    true,
			ErrorMsg: "invalid signature",
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(result.JSON())
		return
	}
	err = os.Remove("data/files/" + tkn.FileID)
	if err != nil {
		logrus.Warning("could not remove file " + tkn.FileID)
	}
	logrus.Info("deleting " + tkn.FileID)
	result := deleteResponse{
		Error:    false,
		ErrorMsg: "",
		OK:       true,
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Write(result.JSON())
	return

}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	k, err := readSigningKey("data/keys/priv")
	if err != nil {
		logrus.WithError(err).Error("could not read signing key")
		result := uploadResponse{
			Error:    true,
			ErrorMsg: err.Error(),
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(result.JSON())
		return
	}

	// 10MBs files tops
	err = r.ParseMultipartForm(10 << 20)
	if err != nil {
		logrus.WithError(err).Error("file too big")
		result := uploadResponse{
			Error:    true,
			ErrorMsg: err.Error(),
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(result.JSON())
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		logrus.WithError(err).Error("could not retrieve the file")
		result := uploadResponse{
			Error:    true,
			ErrorMsg: err.Error(),
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(result.JSON())
		return
	}
	defer file.Close()
	fileID := uuid.NewV4()
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		result := uploadResponse{
			Error:    true,
			ErrorMsg: err.Error(),
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(result.JSON())
		return
	}

	encBytes := base64.StdEncoding.EncodeToString(fileBytes)

	err = ioutil.WriteFile("data/files/"+fileID.String(), []byte(encBytes), 0600)
	if err != nil {
		logrus.WithError(err).Error("could not write the file")
		result := uploadResponse{
			Error:    true,
			ErrorMsg: err.Error(),
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(result.JSON())
		return
	}

	hash := sha1.New()
	hash.Write(fileBytes)
	sum := hash.Sum(nil)

	sig := ed25519.Sign(k.(ed25519.PrivateKey), []byte(fileID.String()))

	tkn := deleteToken{
		FileID:    fileID.String(),
		Signature: hex.EncodeToString(sig),
	}

	b, _ := json.Marshal(&tkn)
	if err != nil {
		panic(err)
	}

	result := uploadResponse{
		Error:       false,
		ErrorMsg:    "",
		UUID:        fileID.String(),
		Size:        int64(len(encBytes)),
		SHA1:        hex.EncodeToString(sum),
		DeleteToken: base64.StdEncoding.EncodeToString(b),
	}
	w.Write(result.JSON())
	return
}

func main() {
	flag.Parse()
	http.HandleFunc("/upload", uploadFile)
	http.HandleFunc("/delete", deleteFile)
	go func() {
		logrus.Info("you can upload a file doing something like curl -F 'file=@some-file.txt' http://localhost:8080/upload")
		logrus.WithError(http.ListenAndServe(httpListen, nil)).Fatal("could not start http server")
	}()
	if _, err := os.Stat("./data/files"); os.IsNotExist(err) {
		logrus.Info("creating the files directory")
		err := os.MkdirAll("./data/files", 0700)
		if err != nil {
			logrus.WithError(err).Fatal("could not create the data directory")
		}
	}
	if _, err := os.Stat("./data/keys"); os.IsNotExist(err) {
		logrus.Info("creating the keys directory")
		err := os.MkdirAll("./data/keys", 0700)
		if err != nil {
			logrus.WithError(err).Fatal("could not create the keys directory")
		}
	}

	if _, err := os.Stat("./data/keys/priv"); os.IsNotExist(err) {
		logrus.Info("generating new ed25519 signing keys")
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			logrus.WithError(err).Fatal("could not generate keys")
		}

		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			panic(err)
		}

		pubBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			panic(err)
		}

		encodedPriv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		encodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

		err = ioutil.WriteFile("./data/keys/priv", encodedPriv, 0600)
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile("./data/keys/pub", encodedPub, 0600)
		if err != nil {
			panic(err)
		}
	}

	server := &dns.Server{Addr: serverListen, Net: "udp"}
	dns.HandleFunc(".", handleRequest)
	logrus.WithError(server.ListenAndServe()).Fatal("error while running the server")
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if len(r.Question) != 1 {
		return
	}
	q := r.Question[0]
	switch q.Qtype {
	case dns.TypeTXT:
		logrus.Info(q.Name)
		splitted := strings.Split(q.Name, ".")
		if len(splitted) < 2 {
			return
		}
		chunkID, err := strconv.Atoi(splitted[0])
		if err != nil {
			logrus.WithError(err).Error("invalid chunk id")
			m = new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}
		fileID := splitted[1]
		file, err := os.Open("data/files/" + fileID)
		if err != nil {
			logrus.WithError(err).Error("could not open file")
			m = new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}
		defer file.Close()
		buffer := make([]byte, chunkSize)
		read, err := file.ReadAt(buffer, int64(chunkID)*chunkSize)
		if read == 0 {
			m = new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}
		if err != nil && err != io.EOF {
			logrus.WithError(err).Error("could not read from file")
			m = new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}
		resp := new(dns.TXT)
		resp.Hdr = dns.RR_Header{
			Rrtype: q.Qtype,
			Class:  dns.ClassINET,
			Name:   q.Name,
		}
		resp.Txt = []string{string(buffer[:read])}
		m.Answer = []dns.RR{resp}
	default:
		m = new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
	}
	w.WriteMsg(m)
}