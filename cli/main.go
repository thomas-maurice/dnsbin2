package main

import (
	"encoding/base64"
	"flag"
	"fmt"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var (
	resolver string
	domain   string
	fileId   string
)

func init() {
	flag.StringVar(&resolver, "resolver", "8.8.8.8:53", "Resolver to use")
	flag.StringVar(&domain, "domain", "foo.com", "Domain the uuids live under")
	flag.StringVar(&fileId, "uuid", "", "UUID of the file to download")
}

func main() {
	flag.Parse()
	if fileId == "" {
		logrus.Fatal("You should pass in an UUID to retrieve")
	}
	c := new(dns.Client)
	done := false
	i := 0
	data := ""
	for !done {
		m := new(dns.Msg)
		m.Id = dns.Id()
		m.RecursionDesired = true
		m.Question = make([]dns.Question, 1)
		id := fmt.Sprintf("%d.%s", i, fileId)
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
			done = true
			continue
		} else {
			txt := in.Answer[0].(*dns.TXT)
			data += txt.Txt[0]
		}
		i++
	}
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(decoded))
}
