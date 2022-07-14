package main

import (
	"bufio"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func getNewestLog(dir string) string {
	files, _ := ioutil.ReadDir(dir)
	var newestFile string
	var newestTime int64 = 0
	for _, f := range files {
		filename := f.Name()
		if strings.Contains(filename, "pcoip-connmgr") {
			fi, err := os.Stat(dir + f.Name())
			if err != nil {
				fmt.Println(err)
			}
			currTime := fi.ModTime().Unix()
			if currTime > newestTime {
				newestTime = currTime
				newestFile = f.Name()
			}
		}
	}
	return newestFile
}

type PCoIPLogEntry struct {
	Timestamp string
	SessionID string
	LogLevel  string
	Method    string
	Message   string
}

type PCoIPSession struct {
	ConnectTime string
	Username    string
	Hostname    string
	HostIP      string
	CMSGName    string
	CMSGIP      string
	ClientMac   string
	ClientIp    string
	ClientName  string
}
type PcoipAgentRequest struct {
	Request       xml.Name `xml:"pcoip-agent"`
	Text          string   `xml:",chardata"`
	Version       string   `xml:"version,attr"`
	LaunchSession struct {
		Text        string `xml:",chardata"`
		SessionType string `xml:"session-type"`
		IpAddress   string `xml:"ip-address"`
		Hostname    string `xml:"hostname"`
		Logon       struct {
			Text     string `xml:",chardata"`
			Method   string `xml:"method,attr"`
			Username string `xml:"username"`
			Password string `xml:"password"`
			Domain   string `xml:"domain"`
		} `xml:"logon"`
		ClientMac       string `xml:"client-mac"`
		ClientIp        string `xml:"client-ip"`
		ClientName      string `xml:"client-name"`
		LicensePath     string `xml:"license-path"`
		SessionLogID    string `xml:"session-log-id"`
		TimeZoneWindows string `xml:"time-zone-windows"`
	} `xml:"launch-session"`
}

type PcoipAgentResponse struct {
	Response          xml.Name `xml:"pcoip-agent"`
	LaunchSessionResp struct {
		Text        string `xml:",chardata"`
		ResultID    string `xml:"result-id"`
		SessionInfo struct {
			Text       string `xml:",chardata"`
			IpAddress  string `xml:"ip-address"`
			Sni        string `xml:"sni"`
			Port       string `xml:"port"`
			SessionTag string `xml:"session-tag"`
			SessionID  string `xml:"session-id"`
		} `xml:"session-info"`
	} `xml:"launch-session-resp"`
}

type PcoipBrokerRequest struct {
	Request xml.Name `xml:"pcoip-broker"`
	Text    string   `xml:",chardata"`
	Version string   `xml:"version,attr"`
	Hello   struct {
		Text       string `xml:",chardata"`
		ClientInfo struct {
			Text           string `xml:",chardata"`
			ProductName    string `xml:"product-name"`
			ProductVersion string `xml:"product-version"`
			Platform       string `xml:"platform"`
			Locale         string `xml:"locale"`
			Hostname       string `xml:"hostname"`
			SerialNumber   string `xml:"serial-number"`
			DeviceName     string `xml:"device-name"`
			PcoipUniqueID  string `xml:"pcoip-unique-id"`
			OrganizationID string `xml:"organization-id"`
		} `xml:"client-info"`
		PcmInfo struct {
			Text           string `xml:",chardata"`
			ProductName    string `xml:"product-name"`
			ProductVersion string `xml:"product-version"`
			Platform       string `xml:"platform"`
			IpAddress      string `xml:"ip-address"`
			Hostname       string `xml:"hostname"`
		} `xml:"pcm-info"`
		Caps struct {
			Text string   `xml:",chardata"`
			Cap  []string `xml:"cap"`
		} `xml:"caps"`
		ServerAddress struct {
			Text      string `xml:",chardata"`
			IpAddress string `xml:"ip-address"`
			Hostname  string `xml:"hostname"`
		} `xml:"server-address"`
	} `xml:"hello"`
}

func formatLogLine(line string) (PCoIPLogEntry, error) {
	var entry PCoIPLogEntry
	s := strings.Split(line, " ")
	if len(s) < 6 {
		return entry, errors.New("Not enough args in line")
	}
	entry.Timestamp = s[0]
	// throw away duff lines, errors from the logs etc
	if ok, _ := regexp.MatchString("(.*-.*-.*-.*)", s[1]); ok {
		entry.SessionID = s[1]
	}
	entry.LogLevel = s[4]
	entry.Method = s[5]
	entry.Message = strings.TrimSpace(strings.Join(s[6:], " "))
	return entry, nil
}

func readLog(logpath string) []PCoIPLogEntry {
	var logLines []PCoIPLogEntry
	fmt.Println(logpath)
	file, err := os.Open(logpath)
	if err != nil {
		log.Fatalf("failed to open")
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		logLine, err := formatLogLine(scanner.Text())
		if err == nil {
			logLines = append(logLines, logLine)
		}
	}
	file.Close()
	return logLines
}

func getSessions(l []PCoIPLogEntry) map[string]*PCoIPSession {
	sessions := make(map[string]*PCoIPSession)
	for _, line := range l {
		if _, ok := sessions[line.SessionID]; !ok {
			sessions[line.SessionID] = &PCoIPSession{}
		}
		session := sessions[line.SessionID]
		// get CMSG name and ip
		if strings.Contains(line.Message, "Sending request to PCoIP broker (hello)") && line.Method == "PCoIPBrokerHttpsConnectionImpl" {
			sp := strings.Split(line.Message, ":")
			myXML := strings.TrimSpace(strings.Join(sp[2:], ""))
			pcoipBrokerRequest := parsePCoIPBrokerRequestXML(myXML)
			session.CMSGName = pcoipBrokerRequest.Hello.PcmInfo.Hostname
			session.CMSGIP = pcoipBrokerRequest.Hello.PcmInfo.IpAddress
		}
		// get username, dest hostname, dest ip
		if strings.Contains(line.Message, "Sending request to PCoIP Agent") && line.Method == "PCoIPAgent" {
			sp := strings.Split(line.Message, ":")
			myXML := strings.TrimSpace(strings.Join(sp[2:], ""))
			pcoipAgentRequest := parsePCoIPAgentRequestXML(myXML)
			session.Hostname = pcoipAgentRequest.LaunchSession.Hostname
			session.HostIP = pcoipAgentRequest.LaunchSession.IpAddress
			session.Username = pcoipAgentRequest.LaunchSession.Logon.Username
			session.ClientIp = pcoipAgentRequest.LaunchSession.ClientIp
			session.ClientName = pcoipAgentRequest.LaunchSession.ClientName
			session.ClientMac = pcoipAgentRequest.LaunchSession.ClientMac
		}
		// get connect time
		if strings.Contains(line.Message, "Received response from PCoIP Agent") && line.Method == "PCoIPAgent" {
			sp := strings.Split(line.Message, ":")
			myXML := strings.TrimSpace(strings.Join(sp[2:], ""))
			pcoipAgentResponse := parsePCoIPAgentResponseXML(myXML)
			if pcoipAgentResponse.LaunchSessionResp.ResultID == "SUCCESSFUL" {
				session.ConnectTime = line.Timestamp
			}
		}
	}
	return sessions
}

func parsePCoIPBrokerRequestXML(x string) PcoipBrokerRequest {
	// fmt.Printf("%s\n", x)
	var pcoipBrokerRequest PcoipBrokerRequest
	xml.Unmarshal([]byte(x), &pcoipBrokerRequest)
	// fmt.Printf("broker: %+v\n", pcoipBrokerRequest)
	return pcoipBrokerRequest
}

func parsePCoIPAgentRequestXML(x string) PcoipAgentRequest {
	var pcoipAgentRequest PcoipAgentRequest
	xml.Unmarshal([]byte(x), &pcoipAgentRequest)
	return pcoipAgentRequest
}

func parsePCoIPAgentResponseXML(x string) PcoipAgentResponse {
	var pcoipAgentResponse PcoipAgentResponse
	xml.Unmarshal([]byte(x), &pcoipAgentResponse)
	return pcoipAgentResponse
}

func printSessionsOrdered(s map[string]*PCoIPSession) {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, id := range keys {
		if len(s[id].ConnectTime) > 0 {
			fmt.Printf("%s %+v\n", id, s[id])
		}
	}
}

func main() {
	var listenAddress = flag.String("listen-address", ":9666", "The address to listen on for HTTP requests.")
	var logdir = flag.String("log-dir", "/var/log/Teradici/ConnectionManager/", "Path the directory containing pcoip connection manager logs.")
	flag.Parse()
	// set up metrics we're tracking
	var labels = []string{"connect_time", "username", "hostname", "ip", "cmsg_name", "cmsg_ip"}
	var pcoipSessions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pcoip_sessions",
		Help: "PCoIP Sessions on this CM/SG",
	}, labels)
	prometheus.MustRegister(pcoipSessions)
	// here we do the work async
	go func() {
		fmt.Printf("entering main Goroutine")
		for {
			fmt.Printf("clearing gauge")
			pcoipSessions.Reset()
			logfile := getNewestLog(*logdir)
			logpath := fmt.Sprintf("%s/%s", *logdir, logfile)
			logLines := readLog(logpath)
			sessions := getSessions(logLines)
			for _, session := range sessions {
				pcoipSessions.WithLabelValues(
					session.ConnectTime,
					session.Username,
					session.Hostname,
					session.HostIP,
					session.CMSGName,
					session.CMSGIP,
				).Add(1)
			}
			time.Sleep(60 * time.Second)
		}
	}()
	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: false,
		},
	))
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
