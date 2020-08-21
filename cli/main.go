package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var (
	resolver string
	domain   string
	fileId   string
	workers  int
)

func init() {
	flag.StringVar(&resolver, "resolver", "8.8.8.8:53", "Resolver to use")
	flag.StringVar(&domain, "domain", "foo.com", "Domain the uuids live under")
	flag.StringVar(&fileId, "uuid", "", "UUID of the file to download")
	flag.IntVar(&workers, "workers", 1, "number of parallel workers to fetch chunks")
}

func main() {
	flag.Parse()
	if fileId == "" {
		logrus.Fatal("You should pass in an UUID to retrieve")
	}

	// Anti idiot protection
	if workers <= 0 {
		workers = 1
	}

	c := new(dns.Client)
	wg := sync.WaitGroup{}

	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	id := fmt.Sprintf("chunks.%s", fileId)
	m.Question[0] = dns.Question{
		Name:   id + "." + domain + ".",
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	}
	in, _, err := c.Exchange(m, resolver)
	if err != nil {
		panic(err)
	}
	var chunks int
	if in.Rcode == dns.RcodeNameError {
		logrus.Fatal("Could not get the number of chunks")
	} else {
		txt := in.Answer[0].(*dns.TXT)
		chunks, err = strconv.Atoi(txt.Txt[0])
		if err != nil {
			logrus.WithError(err).Fatalf("invalid chunk number %s", txt.Txt[0])
		}
	}

	m = new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	id = fmt.Sprintf("hash.%s", fileId)
	m.Question[0] = dns.Question{
		Name:   id + "." + domain + ".",
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	}
	in, _, err = c.Exchange(m, resolver)
	if err != nil {
		panic(err)
	}
	var hash string
	if in.Rcode == dns.RcodeNameError {
		logrus.Fatal("Could not get the hash")
	} else {
		txt := in.Answer[0].(*dns.TXT)
		hash = txt.Txt[0]
	}

	logrus.Infof("will retrieve %d chunks using %d workers, SHA1:%s", chunks, workers, hash)
	wg.Add(chunks)
	workChan := make(chan int, workers)

	chunkList := make([]string, chunks)

	for i := 0; i < workers; i++ {
		go func() {
			for chunk := range workChan {
				m := new(dns.Msg)
				m.Id = dns.Id()
				m.RecursionDesired = true
				m.Question = make([]dns.Question, 1)
				id := fmt.Sprintf("%d.%s", chunk, fileId)
				m.Question[0] = dns.Question{
					Name:   id + "." + domain + ".",
					Qtype:  dns.TypeTXT,
					Qclass: dns.ClassINET,
				}
				in, _, err := c.Exchange(m, resolver)
				if err != nil {
					panic(err)
				}

				// we use NXDOMAIN as EOF lol
				if in.Rcode == dns.RcodeNameError {
					break
				} else {
					txt := in.Answer[0].(*dns.TXT)
					chunkList[chunk] = txt.Txt[0]
					wg.Done()
				}
			}
		}()
	}

	for i := 0; i < chunks; i++ {
		workChan <- i
	}

	wg.Wait()
	close(workChan)

	data := strings.Join(chunkList, "")

	sha := sha1.New()
	sha.Write([]byte(data))
	h := hex.EncodeToString(sha.Sum(nil))

	if h != hash {
		logrus.Fatalf("SHA1 do not match: %s != %s", h, hash)
	} else {
		logrus.Infof("Validated SHA1 %s", h)
	}

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(decoded))
}
