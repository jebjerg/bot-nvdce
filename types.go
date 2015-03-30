package main

import (
	"encoding/xml"
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

const CVE_DATE = "Jan 2, 2006 15:04"

type nvdce_conf struct {
	Channels   []string            `json:"channels"`
	BotHost    string              `json:"bot_host"`
	Interval   int                 `json:"check_interval_minutes"`
	Highlights map[string][]string `json:"highlights"`
	FeedURL    string              `json:"feed_url"`
}
