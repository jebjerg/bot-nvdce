package main

import (
	"compress/gzip"
	"encoding/xml"
	"flag"
	"fmt"
	"github.com/cenkalti/rpc2"
	irc "github.com/fluffle/goirc/client"
	"github.com/jebjerg/fixedhistory"
	cfg "github.com/jebjerg/go-bot/bot/config"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

type PrivMsg struct {
	Target, Text string
}

type BaseMetrics struct {
	XMLName xml.Name `xml:"base_metrics"`
	Score   float32  `xml:"score"`
}

type CVSS struct {
	XMLName xml.Name    `xml:"cvss"`
	Metrics BaseMetrics `xml:"base_metrics"`
}

type Entry struct {
	XMLName        xml.Name  `xml:"entry"`
	ID             string    `xml:"id,attr"`
	CVSS           CVSS      `xml:"cvss"`
	Summary        string    `xml:"summary"`
	Published      time.Time `xml:"published-datetime"`
	LatestModified time.Time `xml:"last-modified-datetime"`
}

func (e *Entry) UpdatedOrNew() string {
	if e.Published == e.LatestModified {
		return "NEW"
	}
	return "UPDATE"
}

type Feed struct {
	XMLName xml.Name `xml:"nvd"`
	Entries []Entry  `xml:"entry"`
}

type ByDate []Entry

func (e ByDate) Len() int      { return len(e) }
func (e ByDate) Swap(i, j int) { e[i], e[j] = e[j], e[i] }
func (e ByDate) Less(i, j int) bool {
	return e[i].LatestModified.UnixNano() < e[j].LatestModified.UnixNano()
}

func CVEFeed() (*Feed, error) {
	var res *http.Response
	var err error
	if debug {
		res, err = http.Get("http://localhost:8080/nvdcve-2.0-Modified.xml.gz")
	} else {
		res, err = http.Get(config.FeedURL)
	}
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	gzReader, err := gzip.NewReader(res.Body)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(gzReader)
	if err != nil {
		return nil, err
	}
	feed := &Feed{}
	return feed, xml.Unmarshal(data, feed)
}

const CVE_DATE = "Jan 2, 2006 15:04"

var config *nvdce_conf
var debug bool

func init() {
	config = &nvdce_conf{}
	if err := cfg.NewConfig(config, "nvdce.json"); err != nil {
		panic(err)
	}
}

func Highlight(channel, input string) string {
	output := input
	if config == nil {
		return output
	}
	highlights, ok := config.Highlights[channel]
	if !ok {
		return output
	}
	for _, word := range highlights {
		re := regexp.MustCompile(fmt.Sprintf("(%v)", word))
		output = re.ReplaceAllString(output, "\002\00308$1\003\002")
	}
	return output
}

type nvdce_conf struct {
	Channels   []string            `json:"channels"`
	BotHost    string              `json:"bot_host"`
	Interval   int                 `json:"check_interval_minutes"`
	Highlights map[string][]string `json:"highlights"`
	FeedURL    string              `json:"feed_url"`
}

func Remove(element string, elements *[]string) error {
	index := -1
	for i, e := range *elements {
		if e == element {
			index = i
		}
	}
	if index != -1 {
		*elements = append((*elements)[:index], (*elements)[index+1:]...)
	} else {
		return fmt.Errorf("element (%v) not found in (%v)", element, elements)
	}
	return nil
}

func main() {
	flag.BoolVar(&debug, "debug", false, "debug mode (localhost xml feed)")
	flag.Parse()

	conn, err := net.Dial("tcp", config.BotHost)
	if err != nil {
		panic(err)
	}
	c := rpc2.NewClient(conn)
	go c.Run()
	// just for kicks
	c.Handle("privmsg", func(client *rpc2.Client, args *irc.Line, reply *bool) error {
		channel, line := args.Args[0], args.Args[1]
		for _, s := range []string{".cve", "bugs?"} {
			if line == s {
				client.Call("privmsg", &PrivMsg{channel, s}, &reply)
				break
			}
		}
		if strings.Fields(line)[0] == ".highlights" {
			hl, ok := config.Highlights[channel]
			if ok {
				client.Call("privmsg", &PrivMsg{channel, strings.Join(hl, ", ")}, &reply)
			} else {
				client.Call("privmsg", &PrivMsg{channel, fmt.Sprintf("No highlights for %v", channel)}, &reply)
			}
		} else if strings.Fields(line)[0] == ".highlight" {
			line = line[len(".highlight")+1:]
			_, ok := config.Highlights[channel]
			if ok {
				token := line
				add := true // op {{{
				if token[0] == '+' {
					add = true
				} else if token[0] == '-' {
					add = false
				}
				if token[0] == '+' || token[0] == '-' {
					token = token[1:]
				} // }}}
				if add == true {
					config.Highlights[channel] = append(config.Highlights[channel], token)
				} else {
					hls := config.Highlights[channel]
					Remove(token, &hls)
					config.Highlights[channel] = hls
				}
				cfg.Save(config, "nvdce.json")
				client.Call("privmsg", &PrivMsg{channel, strings.Join(config.Highlights[channel], ", ")}, &reply)
			}
		}
		return nil
	})
	var reply bool
	c.Call("register", struct{}{}, &reply)

	for _, channel := range config.Channels {
		c.Call("join", channel, &reply)
	}

	// history
	feed, err := CVEFeed()
	if err != nil {
		panic(err)
	}
	history := fixedhistory.NewHistory(50)
	sort.Sort(ByDate(feed.Entries))
	for _, entry := range feed.Entries[2:] { // Allow a couple to know it's working on restart
		history.Push(entry.ID + entry.LatestModified.Format(CVE_DATE))
	}

	max_items := 5
	go func() {
		interval := time.NewTicker(time.Duration(config.Interval) * time.Minute)
		for {
			feed, err := CVEFeed()
			if err != nil {
				panic(err)
			}
			sort.Sort(ByDate(feed.Entries))
			for i, entry := range feed.Entries[0:max_items] {
				if i > max_items-1 || history.Contains(entry.ID+entry.LatestModified.Format(CVE_DATE)) {
					continue
				}
				history.Push(entry.ID + entry.LatestModified.Format(CVE_DATE))
				var score string
				if entry.CVSS.Metrics.Score >= 8 {
					score = fmt.Sprintf("\00304%0.1f\003", entry.CVSS.Metrics.Score)
				} else {
					score = fmt.Sprintf("%0.1f", entry.CVSS.Metrics.Score)
				}
				for _, channel := range config.Channels {
					msg := fmt.Sprintf("\002%v\002 [\00303%v\003] \002%v\002 (%v) %v", entry.LatestModified.Format(CVE_DATE), entry.ID, entry.UpdatedOrNew(), score, Highlight(channel, entry.Summary))
					go c.Call("privmsg", &PrivMsg{channel, msg}, &reply)
				}
			}
			<-interval.C
		}
	}()
	forever := make(chan bool)
	<-forever
}
