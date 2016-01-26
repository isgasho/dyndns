// from http://mkaczanowski.com/golang-build-dynamic-dns-service-go/#server_code
package main

import (
	"errors"
	"flag"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/boltdb/bolt"
	"github.com/miekg/dns"
)

var (
	tsig    *string
	dbPath  *string
	port    *int
	bdb     *bolt.DB
	pidFile *string
	debug   *bool

	Log = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
)

const rrBucket = "rr"

func getKey(domain string, rtype uint16) (r string, e error) {
	if *debug {
		Log.Printf("getKey:  domain: %s, resource type: %d\n", domain, rtype)
	}

	if n, ok := dns.IsDomainName(domain); ok {
		labels := dns.SplitDomainName(domain)

		// Reverse domain, starting from top-level domain
		// eg.  ".com.mkaczanowski.test "
		var tmp string
		for i := 0; i < int(math.Floor(float64(n/2))); i++ {
			tmp = labels[i]
			labels[i] = labels[n-1]
			labels[n-1] = tmp
		}

		reverseDomain := strings.Join(labels, ".")
		r = strings.Join([]string{reverseDomain, strconv.Itoa(int(rtype))}, "_")
	} else {
		e = errors.New("Invailid domain: " + domain)
		Log.Println(e.Error())
	}

	return r, e
}

func createBucket(bucket string) (err error) {
	if *debug {
		Log.Printf("createBucket: %s\n", bucket)
	}

	err = bdb.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			e := errors.New("Create bucket: " + bucket)
			Log.Println(e.Error())

			return e
		}

		return nil
	})

	return err
}

func deleteRecord(domain string, rtype uint16) (err error) {
	if *debug {
		Log.Printf("deleteRecord: %s, resource type: %d\n", domain, rtype)
	}

	key, _ := getKey(domain, rtype)
	err = bdb.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(rrBucket))
		err := b.Delete([]byte(key))

		if err != nil {
			e := errors.New("Delete record failed for domain: " + domain)
			Log.Println(e.Error())

			return e
		}

		return nil
	})

	return err
}

func storeRecord(rr dns.RR) (err error) {
	if *debug {
		Log.Printf("Store record: resource record: %+v\n", rr)
	}

	key, _ := getKey(rr.Header().Name, rr.Header().Rrtype)
	err = bdb.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(rrBucket))
		err := b.Put([]byte(key), []byte(rr.String()))

		if err != nil {
			e := errors.New("Store record failed: " + rr.String())
			Log.Println(e.Error())

			return e
		}

		return nil
	})

	return err
}

func getRecord(domain string, rtype uint16) (rr dns.RR, err error) {
	if *debug {
		Log.Printf("getRecord: domain: %s, resource type: %d\n", domain, rtype)
	}

	key, _ := getKey(domain, rtype)
	var v []byte

	err = bdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(rrBucket))
		v = b.Get([]byte(key))

		if string(v) == "" {
			e := errors.New("Record not found, key: " + key)
			Log.Println(e.Error())

			return e
		}

		return nil
	})

	if err == nil {
		rr, err = dns.NewRR(string(v))
	}

	return rr, err
}

func updateRecord(r dns.RR, q *dns.Question) {
	if *debug {
		Log.Printf("updateRecord: resource record: %+v, question: %+v\n", r, q)
	}

	var (
		rr    dns.RR
		name  string
		rtype uint16
		ttl   uint32
		ip    net.IP
	)

	header := r.Header()
	name = header.Name
	rtype = header.Rrtype
	ttl = header.Ttl

	if _, ok := dns.IsDomainName(name); ok {
		if header.Class == dns.ClassANY && header.Rdlength == 0 { // Delete record
			deleteRecord(name, rtype)
		} else { // Add record
			rheader := dns.RR_Header{
				Name:   name,
				Rrtype: rtype,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			}

			if a, ok := r.(*dns.A); ok {
				rrr, err := getRecord(name, rtype)
				if err == nil {
					rr = rrr.(*dns.A)
				} else {
					rr = new(dns.A)
				}

				ip = a.A
				rr.(*dns.A).Hdr = rheader
				rr.(*dns.A).A = ip
			} else if a, ok := r.(*dns.AAAA); ok {
				rrr, err := getRecord(name, rtype)
				if err == nil {
					rr = rrr.(*dns.AAAA)
				} else {
					rr = new(dns.AAAA)
				}

				ip = a.AAAA
				rr.(*dns.AAAA).Hdr = rheader
				rr.(*dns.AAAA).AAAA = ip
			}

			storeRecord(rr)
		}
	}
}

func parseQuery(m *dns.Msg) {
	if *debug {
		Log.Printf("parseQuery: message:  %+v\n", m)
	}

	var rr dns.RR

	for _, q := range m.Question {
		if readRR, e := getRecord(q.Name, q.Qtype); e == nil {
			rr = readRR.(dns.RR)
			if rr.Header().Name == q.Name {
				m.Answer = append(m.Answer, rr)
			}
		}
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if *debug {
		Log.Printf("handleRequest: message: %+v\n", r)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)

	case dns.OpcodeUpdate:
		for _, question := range r.Question {
			for _, rr := range r.Ns {
				updateRecord(rr, &question)
			}
		}
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name,
				dns.HmacMD5, 300, time.Now().Unix())
		} else {
			Log.Println("Status", w.TsigStatus().Error())
		}
	}

	w.WriteMsg(m)
}

func serve(name, secret string, port int) {
	server := &dns.Server{Addr: "0.0.0.0:" + strconv.Itoa(port), Net: "udp"}

	if name != "" {
		server.TsigSecret = map[string]string{name: secret}
	}

	Log.Println("Starting server")
	err := server.ListenAndServe()
	defer server.Shutdown()

	if err != nil {
		Log.Fatalf("Failed to setup the udp server: %s\n", err.Error())
	}
}

func main() {
	var (
		name   string // tsig keyname
		secret string // tsig base64
	)

	// Parse flags
	port = flag.Int("port", 53, "server port ")
	tsig = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
	dbPath = flag.String("db_path", "./dyndns.db", "location where db will be stored")
	pidFile = flag.String("pid", "./go-dyndns.pid", "pid file location")
	debug = flag.Bool("debug", false, "log debug to console")

	flag.Parse()

	// Open db
	db, err := bolt.Open(*dbPath, 0600, &bolt.Options{Timeout: 10 * time.Second})

	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	bdb = db

	// Create dns bucket if doesn't exist
	createBucket(rrBucket)

	// Attach request handler func
	dns.HandleFunc(".", handleDNSRequest)

	// Tsig extract
	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1]
	}

	// Pidfile
	file, err := os.OpenFile(*pidFile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		Log.Panic("Couldn't create pid file: ", err)
	} else {
		file.Write([]byte(strconv.Itoa(syscall.Getpid())))
		defer file.Close()
	}

	// Start server
	go serve(name, secret, *port)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
endless:
	for {
		select {
		case s := <-sig:
			Log.Printf("Signal (%v) received, stopping", s)
			break endless
		}
	}
}
