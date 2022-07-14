# go-cmsgexporter
go app to export prometheus metrics from PCoIP CM/SGs
# included files
* exporter source
* grafana dashboard json
* kubernetes yaml for servicemonitor (to scrape metrics endpoint)
* linux binary (amd64)
# usage
```
Usage of ./cmsg_exporter:
  -listen-address string
    	The address to listen on for HTTP requests. (default ":9666")
  -log-dir string
    	Path the directory containing pcoip connection manager logs. (default "/var/log/Teradici/ConnectionManager/")
```
# how to build on macos
build prerequisites:
* go 1.18 set up properly
```
git clone https://github.ps.thmulti.com/davey/go-cmsgexporter.git
GOOS=linux GOARCH=amd64 go build -o cmsg_exporter .
```
# how to setup and run
mill azure cmsg example
```
export https_proxy=web-proxy.chi.themill.com:3128
export http_proxy=web-proxy.chi.themill.com:3128
yum install git
GIT_SSL_NO_VERIFY=true git clone https://github.ps.thmulti.com/davey/go-cmsgexporter.git
cd go-cmsgexporter/
(./cmsg_exporter -log-dir /var/log/Teradici/ConnectionManager/ &)
```
# TODO
systemd unit file?
use client MAC as unique session ID?