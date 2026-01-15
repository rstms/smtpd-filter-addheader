package filter

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const Version = "0.0.6"

const FID_NAME = 4
const FID_SID = 5
const FID_TOKEN = 6

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
	Name              string
	Headers           map[string]string
	RecipientPatterns []*regexp.Regexp
	Sessions          map[string]*Session
	Protocol          string
	Subsystem         string
	reports           []string
	filters           []string
	verbose           bool
	input             *bufio.Scanner
	output            io.Writer
}

func NewFilter(reader io.Reader, writer io.Writer) *Filter {
	executable, err := os.Executable()
	if err != nil {
		log.Fatal(Fatalf("NewFilter failed with: %v", err))
	}
	f := Filter{
		Name:              filepath.Base(executable),
		verbose:           ViperGetBool("verbose"),
		Headers:           make(map[string]string),
		Sessions:          make(map[string]*Session),
		RecipientPatterns: []*regexp.Regexp{},
		input:             bufio.NewScanner(reader),
		output:            writer,
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

func (f *Filter) AddRecipientPattern(pattern string) {
	p, err := regexp.Compile(pattern)
	if err != nil {
		Warning("AddRecipientPattern(%s) failed with: %v", pattern, err)
	}
	f.RecipientPatterns = append(f.RecipientPatterns, p)
}

func (f *Filter) Config() {
	for f.input.Scan() {
		line := f.input.Text()
		if f.verbose {
			log.Printf("%s config: %s\n", f.Name, line)
		}
		fields := strings.Split(line, "|")
		if len(fields) < 2 {
			Warning("Config: unexpected line: %s", line)
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
		log.Fatalf("Config: input scanner failed with: %v", err)
	}
	log.Fatalf("Config: unexpected EOF")
}

func (f *Filter) Register() {
	for _, name := range f.reports {
		line := fmt.Sprintf("register|report|%s|%s", f.Subsystem, name)
		log.Printf("%s.Register: %s\n", f.Name, line)
		_, err := fmt.Fprintf(f.output, "%s\n", line)
		if err != nil {
			Warning("Register: report output failed with: %v", err)
		}
	}
	for _, name := range f.filters {
		line := fmt.Sprintf("register|filter|%s|%s", f.Subsystem, name)
		if f.verbose {
			log.Printf("%s.Register: %s\n", f.Name, line)
		}
		_, err := fmt.Fprintf(f.output, "%s\n", line)
		if err != nil {
			Warning("Register: filter output failed with: %v", err)
		}
	}
	line := fmt.Sprintf("register|ready")
	if f.verbose {
		log.Printf("%s.Register: %s\n", f.Name, line)
	}
	_, err := fmt.Fprintf(f.output, "%s\n", line)
	if err != nil {
		Warning("Register: ready output failed with: %v", err)
	}

}

func requireArgs(name string, atoms []string, count int) bool {
	if len(atoms) < count {
		Warning("%s: expected %d args, got '%v'", name, count, atoms)
		return false
	}
	return true
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
	log.Printf("Starting %s v%s\n", f.Name, Version)
	for _, header := range ViperGetStringSlice("header") {
		key, value, ok := strings.Cut(header, "=")
		if !ok {
			log.Fatal(Fatalf("invalid header config: %s", header))
		}
		f.AddHeader(key, value)
	}
	for _, pattern := range ViperGetStringSlice("recipient") {
		f.AddRecipientPattern(pattern)
	}
	if f.verbose {
		log.Printf("pid=%d uid=%d gid=%d\n", os.Getpid(), os.Getuid(), os.Getgid())
		for key, value := range f.Headers {
			log.Printf("header: '%s: %s'\n", key, value)
		}
		for _, pattern := range f.RecipientPatterns {
			log.Printf("recipient pattern: `%v`\n", pattern)
		}
	}
	f.Config()
	f.Register()
	for f.input.Scan() {
		line := f.input.Text()
		atoms := strings.Split(line, "|")
		if len(atoms) < 6 {
			panic("failed parsing: '" + line + "'")
		} else {
			switch atoms[0] {
			case "report":
				name := atoms[FID_NAME]
				sid := atoms[FID_SID]
				switch name {
				case "link-connect":
					if requireArgs(name, atoms, 10) {
						f.linkConnect(name, sid, atoms[6], atoms[7], atoms[8], atoms[9])
					}
				case "link-disconnect":
					f.linkDisconnect(name, sid)
				case "link-auth":
					if requireArgs(name, atoms, 8) {
						f.linkAuth(name, sid, atoms[6], atoms[7])
					}
				case "tx-reset":
					if requireArgs(name, atoms, 7) {
						f.txReset(name, sid, atoms[6])
					}
				case "tx-begin":
					if requireArgs(name, atoms, 7) {
						f.txBegin(name, sid, atoms[6])
					}
				case "tx-mail":
					if requireArgs(name, atoms, 9) {
						f.txMail(name, sid, atoms[6], atoms[7], atoms[8])
					}
				case "tx-rcpt":
					if requireArgs(name, atoms, 9) {
						f.txRcpt(name, sid, atoms[6], atoms[7], atoms[8])
					}
				case "tx-data":
					if requireArgs(name, atoms, 8) {
						f.txData(name, sid, atoms[6], atoms[7])
					}
				case "tx-commit":
					if requireArgs(name, atoms, 8) {
						f.txCommit(name, sid, atoms[6], atoms[7])
					}
				case "tx-rollback":
					if requireArgs(name, atoms, 7) {
						f.txRollback(name, sid, atoms[6])
					}
				}
			case "filter":
				phase := atoms[FID_NAME]
				sid := atoms[FID_SID]
				token := atoms[FID_TOKEN]
				switch phase {
				case "data-line":
					if requireArgs(phase, atoms, 8) {
						f.dataLine(phase, sid, token, lastAtom(line, atoms, 7))
					}
				}
			default:
				Warning("unexpected input: %v", line)
			}
		}
	}
	err := f.input.Err()
	if err != nil {
		Warning("input failed with: %v", err)
	}
	Warning("%s: unexpected EOF on stdin", f.Name)
}

func (f *Filter) getSession(name, sid string) *Session {
	session, ok := f.Sessions[sid]
	if !ok {
		Warning("%s: unknown session: %s", name, sid)
		return nil

	}
	return session
}

func (f *Filter) getSessionMessage(name, sid, mid string) (*Session, *Message) {
	session := f.getSession(name, sid)
	if session == nil {
		return nil, nil
	}
	message, ok := session.Messages[mid]
	if !ok {
		Warning("%s: session %s unknown messageId: %s", name, sid, mid)
		return nil, nil
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
		Warning("%s.%s: existing session: %s", f.Name, name, sid)
		return
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
	if session != nil && result == "pass" {
		session.AuthorizedUser = username
	}
}

func (f *Filter) txReset(name, sid, mid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	session, _ := f.getSessionMessage(name, sid, mid)
	if session != nil {
		session.Messages[mid] = NewMessage(mid)
	}
}

func (f *Filter) txBegin(name, sid, mid string) {
	if f.verbose {
		log.Printf("%s %s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	session := f.getSession(name, sid)
	if session == nil {
		return
	}
	_, ok := session.Messages[mid]
	if ok {
		Warning("%s: unexpected tx-begin in session %s for existing message %s", name, sid, mid)
		return
	}
	session.Messages[mid] = NewMessage(mid)
}

func (f *Filter) txMail(name, sid, mid, result, address string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	if message != nil && result == "ok" {
		message.From = address
	}
}

func (f *Filter) txRcpt(name, sid, mid, result, address string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s result=%s address=%s\n", f.Name, name, sid, mid, result, address)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	if message != nil && result == "ok" {
		message.To = append(message.To, address)
	}
}

func (f *Filter) txData(name, sid, mid, result string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	session, message := f.getSessionMessage(name, sid, mid)
	if session != nil && message != nil && result == "ok" {
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
	if message != nil {
		message.State = "commit"
	}
}

func (f *Filter) txRollback(name, sid, mid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	if message != nil {
		message.State = "rollback"
	}
}

func (f *Filter) sessionTimeout(name, sid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s\n", f.Name, name, sid)
	}
	session := f.getSession(name, sid)
	if session != nil {
		delete(f.Sessions, sid)
	}
}

func (f *Filter) recipientMatches(name string, message *Message) bool {
	// if no patterns exist, add the header unconditionally
	if len(f.RecipientPatterns) == 0 {
		return true
	}
	// if patterns exist, only add the header if a recipient address matches
	for _, recipient := range message.To {
		if f.verbose {
			log.Printf("%s.%s: checking recipient patterns for: %s\n", f.Name, name, recipient)
		}
		for _, pattern := range f.RecipientPatterns {
			if pattern.MatchString(recipient) {
				if f.verbose {
					log.Printf("%s.%s: recipient match found: %s\n", f.Name, name, recipient)
				}
				return true
			}
		}
		if f.verbose {
			log.Printf("%s.%s: no match for recipient: %s\n", f.Name, name, recipient)
		}
	}
	return false
}

func (f *Filter) dataLine(name, sid, token, line string) {
	if f.verbose {
		log.Printf("%s.%s: sid=%s token=%s line=%s\n", f.Name, name, sid, token, line)
	}
	lines := []string{line}
	session := f.getSession(name, sid)
	if session != nil {
		_, message := f.getSessionMessage(name, sid, session.DataMessage)
		if message != nil && message.InHeader {
			// if at end of message header lines
			if strings.TrimSpace(line) == "" {
				// add filter headers
				if f.recipientMatches(name, message) {
					lines = []string{}
					for key, value := range f.Headers {
						log.Printf("%s.%s: adding header '%s: %s'\n", f.Name, name, key, value)
						lines = append(lines, fmt.Sprintf("%s: %s", key, value))
					}
					lines = append(lines, line)
				}
				// mark end of header
				message.InHeader = false
			}
		}
	}
	for _, oline := range lines {
		_, err := fmt.Fprintf(f.output, "filter-dataline|%s|%s|%s\n", sid, token, oline)
		if err != nil {
			Warning("failed writing data line: %v", err)
		}
	}
}
