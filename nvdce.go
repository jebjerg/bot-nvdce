package main

import (

	"compress/gzip"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/rpc"
)

type VoidArgs struct{}

type PrivMsgArgs struct {
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
	XMLName xml.Name `xml:"entry"`
	ID      string   `xml:"id,attr"`
	CVSS    CVSS     `xml:"cvss"`
	Summary string   `xml:"summary"`
}

func main() {
	c, err := rpc.DialHTTP("tcp", "localhost:1234")
	if err != nil {
		panic(err)
	}

	res, err := http.Get("http://localhost:8080/nvdcve-2.0-Modified.xml.gz")
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	gzReader, _ := gzip.NewReader(res.Body)
	xmlDecoder := xml.NewDecoder(gzReader)
	var reply bool
	for {
		t, _ := xmlDecoder.Token()
		if t == nil {
			break
		}
		switch startElem := t.(type) {
		case xml.StartElement:
			if startElem.Name.Local == "entry" {
				var entry Entry
				xmlDecoder.DecodeElement(&entry, &startElem)
				go func() {
					var score string
					if entry.CVSS.Metrics.Score >= 6 {
						score = fmt.Sprintf("\00304%0.1f\003", entry.CVSS.Metrics.Score)
					} else {
						score = fmt.Sprintf("%0.1f", entry.CVSS.Metrics.Score)
					}
					msg := fmt.Sprintf("[\002%v\002] (%v) %v", entry.ID, score, entry.Summary[0:50])
					c.Call("IRCRPC.Announce", &PrivMsgArgs{"#generic", msg}, &reply)
				}()
			}
		}
	}
}
