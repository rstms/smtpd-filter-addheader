package filter

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const Version = "0.0.1"

const FID_EVENT = 4
const FID_SID = 5

var Verbose bool

type Message struct {
	Id       string
	From     string
	To       []string
	State    string
	InHeader bool
}

func NewMessage(mid string) *Message {
	return &Message{
		Id:       mid,
		To:       []string{},
		State:    "init",
		InHeader: true,
	}
}

type Session struct {
	Id             string
	Messages       map[string]*Message
	RDNS           string
	Confirmed      bool
	Remote         string
	Local          string
	AuthorizedUser string
	DataMessage    string
}

func NewSession(sid, rdns string, confirmed bool, remote, local string) *Session {
	return &Session{
		Id:        sid,
		RDNS:      rdns,
		Confirmed: confirmed,
		Remote:    remote,
		Local:     local,
		Messages:  make(map[string]*Message),
	}
}

type Callback struct {
	Handler func(string, []string)
	Args    int
}

type Filter struct {
	Name      string
	Headers   map[string]string
	Sessions  map[string]*Session
	Protocol  string
	Subsystem string
	reports   []string
	filters   []string
	verbose   bool
	input     *bufio.Scanner
	output    io.Writer
}

func NewFilter(reader io.Reader, writer io.Writer) *Filter {
	executable, err := os.Executable()
	if err != nil {
		log.Fatal(Fatal(err))
	}
	f := Filter{
		Name:     filepath.Base(executable),
		verbose:  ViperGetBool("verbose"),
		Headers:  make(map[string]string),
		Sessions: make(map[string]*Session),
		input:    bufio.NewScanner(reader),
		output:   writer,
		reports: []string{
			"link-connect",
			"link-disconnect",
			"link-auth",
			"tx-reset",
			"tx-begin",
			"tx-mail",
			"tx-rcpt",
			"tx-data",
			"tx-commit",
			"tx-rollback",
		},
		filters: []string{
			"data-line",
		},
	}
	return &f
}

func (f *Filter) AddHeader(key, value string) {
	f.Headers[key] = value
}

func (f *Filter) Config() {
	for f.input.Scan() {
		line := f.input.Text()
		if f.verbose {
			log.Printf("%s config: %s\n", f.Name, line)
		}
		fields := strings.Split(line, "|")
		if len(fields) < 2 {
			log.Fatal(Fatalf("unexpected config line: %s", line))
		}
		switch fields[1] {
		case "protocol":
			f.Protocol = fields[2]
		case "subsystem":
			f.Subsystem = fields[2]
		case "ready":
			return
		}
	}
	err := f.input.Err()
	if err != nil {
		log.Fatal(Fatal(err))
	}
	log.Fatal(Fatalf("config failure"))
}

func (f *Filter) Register() {
	for _, name := range f.reports {
		_, err := fmt.Fprintf(f.output, "register|report|%s|%s\n", f.Subsystem, name)
		if err != nil {
			log.Fatal(Fatal(err))
		}
	}
	for _, name := range f.filters {
		_, err := fmt.Fprintf(f.output, "register|filter|%s|%s\n", f.Subsystem, name)
		if err != nil {
			log.Fatal(Fatal(err))
		}
	}
	_, err := fmt.Fprintf(f.output, "register|ready\n")
	if err != nil {
		log.Fatal(Fatal(err))
	}

}

func requireArgs(name string, atoms []string, count int) {
	if len(atoms) < count {
		log.Fatal(Fatalf("%s: expected %d args, got '%v'", name, count, atoms))
	}
}

func lastAtom(line string, atoms []string, field int) string {
	var index int
	for i := 0; i < field; i++ {
		index += (len(atoms[i]) + 1)
	}
	ret := line[index:]
	return ret
}

func (f *Filter) Run() {
	log.Printf("Starting %s v%s uid=%d gid=%d verbose=%v\n", f.Name, Version, os.Getuid(), os.Getgid(), f.verbose)
	f.Config()
	f.Register()
	for f.input.Scan() {
		line := f.input.Text()
		atoms := strings.Split(line, "|")
		if len(atoms) < 6 {
			log.Fatal(Fatalf("missing atoms: %s", line))
		}
		switch atoms[0] {
		case "report":
			name := atoms[4]
			sid := atoms[5]
			switch name {
			case "link-connect":
				requireArgs(name, atoms, 10)
				f.linkConnect(name, sid, atoms[6], atoms[7], atoms[8], atoms[9])
			case "link-disconnect":
				f.linkDisconnect(name, sid)
			case "link-auth":
				requireArgs(name, atoms, 8)
				f.linkAuth(name, sid, atoms[6], atoms[7])
			case "tx-reset":
				requireArgs(name, atoms, 7)
				f.txReset(name, sid, atoms[6])
			case "tx-begin":
				requireArgs(name, atoms, 7)
				f.txBegin(name, sid, atoms[6])
			case "tx-mail":
				requireArgs(name, atoms, 9)
				f.txMail(name, sid, atoms[6], atoms[7], atoms[8])
			case "tx-rcpt":
				requireArgs(name, atoms, 9)
				f.txRcpt(name, sid, atoms[6], atoms[7], atoms[8])
			case "tx-data":
				requireArgs(name, atoms, 8)
				f.txData(name, sid, atoms[6], atoms[7])
			case "tx-commit":
				requireArgs(name, atoms, 8)
				f.txCommit(name, sid, atoms[6], atoms[7])
			case "tx-rollback":
				requireArgs(name, atoms, 7)
				f.txRollback(name, sid, atoms[6])
			}
		case "filter":
			phase := atoms[4]
			sid := atoms[5]
			token := atoms[6]
			switch phase {
			case "data-line":
				requireArgs(phase, atoms, 8)
				f.dataLine(phase, sid, token, lastAtom(line, atoms, 7))
			}
		default:
			log.Fatal(Fatalf("unexpected input: %v", line))
		}
	}
	err := f.input.Err()
	if err != nil {
		log.Fatal(Fatalf("input failed with: %v", err))
	}
	log.Printf("%s: unexpected EOF on stdin\n", f.Name)
}

func (f *Filter) getSession(name, sid string) *Session {
	session, ok := f.Sessions[sid]
	if !ok {
		log.Fatal(Fatalf("%s: unknown session: %s\n", name, sid))
	}
	return session
}

func (f *Filter) getSessionMessage(name, sid, mid string) (*Session, *Message) {
	session := f.getSession(name, sid)
	message, ok := session.Messages[mid]
	if !ok {
		log.Fatal(Fatalf("%s: session %s unknown messageId: %s\n", name, sid, mid))
	}
	return session, message
}

func parseArgs(name string, args []string) (string, string, string, string) {
	for len(args) < 4 {
		args = append(args, "")
	}
	return args[0], args[1], args[2], args[3]
}

func (f *Filter) linkConnect(name, sid, rdns, confirmed, src, dst string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s rdns=%s confirmed=%s src=%s dst=%s\n", f.Name, name, sid, rdns, confirmed, src, dst)
	}
	_, ok := f.Sessions[sid]
	if ok {
		log.Fatal(Fatalf("%s.%s: existing session: %s", f.Name, name, sid))
	}
	f.Sessions[sid] = NewSession(sid, rdns, confirmed == "pass", src, dst)
}

func (f *Filter) linkDisconnect(name, sid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s\n", f.Name, name, sid)
	}
	f.getSession(name, sid)
	delete(f.Sessions, sid)
}

func (f *Filter) linkAuth(name, sid, result, username string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s result=%s username=%s\n", f.Name, name, sid, result, username)
	}
	session := f.getSession(name, sid)
	if result == "pass" {
		session.AuthorizedUser = username
	}
}

func (f *Filter) txReset(name, sid, mid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	session, _ := f.getSessionMessage(name, sid, mid)
	session.Messages[mid] = NewMessage(mid)
}

func (f *Filter) txBegin(name, sid, mid string) {
	if f.verbose {
		log.Printf("%s %s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	session := f.getSession(name, sid)
	_, ok := session.Messages[mid]
	if ok {
		log.Fatal(Fatalf("%s: in session %s for existing message %s", name, sid, mid))
	}
	session.Messages[mid] = NewMessage(mid)
}

func (f *Filter) txMail(name, sid, mid, result, address string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	if result == "ok" {
		message.From = address
	}
}

func (f *Filter) txRcpt(name, sid, mid, result, address string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s result=%s address=%s\n", f.Name, name, sid, mid, result, address)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	if result == "ok" {
		message.To = append(message.To, address)
	}
}

func (f *Filter) txData(name, sid, mid, result string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	session, message := f.getSessionMessage(name, sid, mid)
	if result == "ok" {
		session.DataMessage = mid
		message.State = "data"
		message.InHeader = true
	}
}

func (f *Filter) txCommit(name, sid, mid, size string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s size=%s\n", f.Name, name, sid, mid, size)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	message.State = "commit"
}

func (f *Filter) txRollback(name, sid, mid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	message.State = "rollback"
}

func (f *Filter) sessionTimeout(name, sid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s\n", f.Name, name, sid)
	}
	f.getSession(name, sid)
	delete(f.Sessions, sid)
}

func (f *Filter) dataLine(name, sid, token, line string) {
	if f.verbose {
		log.Printf("%s.%s: sid=%s token=%s line=%s\n", f.Name, name, sid, token, line)
	}
	lines := []string{line}
	session := f.getSession(name, sid)
	_, message := f.getSessionMessage(name, sid, session.DataMessage)
	if message.InHeader {
		// if at end of message header lines
		if strings.TrimSpace(line) == "" {
			// add filter headers
			lines = []string{}
			for key, value := range f.Headers {
				log.Printf("%s.%s: adding header %s.%s\n", f.Name, name, key, value)
				lines = append(lines, fmt.Sprintf("%s: %s", key, value))
			}
			lines = append(lines, line)
			// mark end of header
			message.InHeader = false
		}
	}
	for _, oline := range lines {
		_, err := fmt.Fprintf(f.output, "filter-dataline|%s|%s|%s\n", sid, token, oline)
		if err != nil {
			log.Fatal(Fatal(err))
		}
	}
}
