# Path MTU Discovery Daemon

Path MTU Discovery Daemon is daemon that relays received ICMP packet too big messages to all backend instances of an L3/L4 balanced service using IP encapsulation.

[![Build Status](https://travis-ci.com/exaring/pmtud.svg?branch=main&status=created)](https://travis-ci.com/exaring/pmtud)
[![Coverage Status](https://coveralls.io/repos/exaring/pmtud/badge.svg?branch=master&service=github)](https://coveralls.io/github/exaring/pmtud?branch=master)
[![Go ReportCard](http://goreportcard.com/badge/exaring/pmtud)](http://goreportcard.com/report/exaring/pmtud)
[![Go Doc](https://godoc.org/github.com/exaring/pmtud?status.svg)](https://godoc.org/github.com/exaring/pmtud)

## Install

```go get github.com/exaring/pmtud```

## Run

```pmtud -cfg.file /path/to/config.yml```

## Configuration

```yaml
# interfaces to read ICMP type 3 code 4 packet from
interfaces: ["enp4s0"]
# IP tunnel endpoints to send the read packets to
backends:
  - 10.0.0.0
  - 10.0.0.1
```
