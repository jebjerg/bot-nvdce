package main

import (

	"github.com/jebjerg/fixedhistory"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/cenkalti/rpc2"
	irc "github.com/fluffle/goirc/client"
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
	res, err := http.Get(config.FeedURL)
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

func Highlight(input string) string {
	output := input
	for _, word := range config.Highlights {
		re := regexp.MustCompile(fmt.Sprintf("(%v)", word))
		output = re.ReplaceAllString(output, "\002\00308$1\003\002")
	}
	return output
}

type Config struct {
	Channels   []string `json:"channels"`
	Interval   int      `json:"check_interval_minutes"`
	Highlights []string `json:"highlights"`
	FeedURL    string   `json:"feed_url"`
}

func (c *Config) Save(path string) error {
	if data, err := json.Marshal(c); err != nil {
		return err
	} else {
		return ioutil.WriteFile(path, data, 600)
	}
}

func NewConfig(path string) (*Config, error) {
	config := &Config{}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, config)
	return config, err
}

var config *Config

func main() {
	config, _ = NewConfig("./nvdce.json")

	conn, err := net.Dial("tcp", "localhost:1234")
	if err != nil {
		panic(err)
	}
	c := rpc2.NewClient(conn)
	go c.Run()
	// just for kicks
	c.Handle("privmsg", func(client *rpc2.Client, args *irc.Line, reply *bool) error {
		for _, s := range []string{".cve", "bugs?"} {
			if strings.Join(args.Args[1:], " ") == s {
				client.Call("privmsg", &PrivMsg{args.Args[0], s}, &reply)
				break
			}
		}
		return nil
	})
	var reply bool
	c.Call("register", struct{}{}, &reply)

	// history
	feed, err := CVEFeed()
	if err != nil {
		panic(err)
	}
	history := fixedhistory.NewHistory(50)
	sort.Sort(ByDate(feed.Entries))
	for _, entry := range feed.Entries[5:] {
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
				msg := fmt.Sprintf("\002%v\002 [\00303%v\003] \002%v\002 (%v) %v", entry.LatestModified.Format(CVE_DATE), entry.ID, entry.UpdatedOrNew(), score, Highlight(entry.Summary))
				for _, channel := range config.Channels {
					go c.Call("privmsg", &PrivMsg{channel, msg}, &reply)
				}
			}
			<-interval.C
		}
	}()
	forever := make(chan bool)
	<-forever
}
