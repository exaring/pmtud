# Path MTU Discovery Daemon

[![Build Status](https://travis-ci.com/exaring/pmtud.svg?branch=main&status=created)](https://travis-ci.com/exaring/pmtud)
[![Coverage Status](https://coveralls.io/repos/exaring/pmtud/badge.svg?branch=master&service=github)](https://coveralls.io/github/exaring/pmtud?branch=master)
[![Go ReportCard](http://goreportcard.com/badge/exaring/pmtud)](http://goreportcard.com/report/exaring/pmtud)
[![Go Doc](https://godoc.org/github.com/exaring/pmtud?status.svg)](https://godoc.org/github.com/exaring/pmtud)

In ECMP or L4 load balanced environments ICMP messages are mostly routed to the wrong servers.
Path MTU Discovery Daemon solves this problem by "broadcasting" received ICMP packet too big messages to all backend instances of an L3/L4 load balanced service using IPIP encapsulation.
Some Details:

  * https://tools.ietf.org/html/draft-jaeggli-v6ops-pmtud-ecmp-problem-00

If you've stumbled over [https://github.com/cloudflare/pmtud/](https://github.com/cloudflare/pmtud/) but you're in an environment where your servers are in different L2 domains this is probably what you're looking for.

## Install

```go get github.com/exaring/pmtud```

You may need to install the ```libpcap``` header files. On a Debian system you can do that by ```apt-get install libpcap-dev```

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
