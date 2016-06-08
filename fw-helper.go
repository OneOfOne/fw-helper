package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var rules = compileRules(
	`Failed.*?(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})`,
	`Disconnected from (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).*[preauth]`,
)

func compileRules(rules ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(rules))
	for i, r := range rules {
		out[i] = regexp.MustCompile(r)
	}
	return out
}
func main() {
	ips := Blocker{}
	for e := range readJournal() {
		msg := e.Message()
		for _, r := range rules {
			ip := r.FindStringSubmatch(msg)
			if len(ip) != 2 {
				continue
			}
			if ip := ip[1]; ips.AddAndCheck(ip) {
				log.Printf("[%s] blocked ip %s.", e.Service(), ip)
			}
			break
		}
	}
}

type M map[string]string

func (m M) Message() string {
	return m["MESSAGE"]
}

func (m M) Service() string {
	return m["SYSLOG_IDENTIFIER"]
}
func (m M) TS() time.Time {
	t, _ := strconv.ParseInt(m["_SOURCE_REALTIME_TIMESTAMP"], 10, 64)
	if t == 0 {
		t, _ = strconv.ParseInt(m["__REALTIME_TIMESTAMP"], 10, 64)
	}
	return time.Unix(0, t*1000)
}

func readJournal() chan M {
	jctl := exec.Command("journalctl", "-f", "-ojson", "-n50")
	r, _ := jctl.StdoutPipe()
	if err := jctl.Start(); err != nil {
		log.Fatal(err)
	}
	ch := make(chan M, 100)
	go func() {
		defer close(ch)
		defer r.Close()
		jr := json.NewDecoder(r)
		for {
			var m M
			if err := jr.Decode(&m); err != nil {
				log.Println(err)
				break
			}
			ch <- m
		}
	}()
	return ch
}

type Blocker map[string]int

func (b Blocker) AddAndCheck(ip string) (blocked bool) {
	ip3 := ip[:strings.LastIndex(ip, ".")]
	if blocked = b[ip3] > 6; blocked {
		blockNet(ip3 + ".0")
		delete(b, ip3)
	} else if blocked = b[ip] > 3; blocked {
		blockIP(ip)
		delete(b, ip)
		b[ip3]++
	} else {
		b[ip3]++
		b[ip]++
	}
	return
}

func blockIP(ip string) {
	o, err := exec.Command("firewall-cmd", "--ipset=blacklist", "--add-entry="+ip).CombinedOutput()
	if err != nil {
		log.Println(err)
		return
	}
	if !bytes.HasPrefix(o, []byte("success")) {
		log.Printf("%s", o)
	}
}

func blockNet(ip string) {
	o, err := exec.Command("firewall-cmd", "--ipset=badblocks", "--add-entry="+ip+".0/24").CombinedOutput()
	if err != nil {
		log.Println(err)
		return
	}
	if !bytes.HasPrefix(o, []byte("success")) {
		log.Printf("%s", o)
	}
}
