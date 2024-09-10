package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/exaring/pmtud/pkg/config"
	"github.com/exaring/pmtud/pkg/icmp34relay"
	"github.com/exaring/pmtud/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	cfgFilePath = flag.String("cfg.file", "config.yaml", "Config file")
)

func main() {
	flag.Parse()

	cfg, err := config.GetConfig(*cfgFilePath)
	if err != nil {
		log.Fatalf("unable to get config: %s", err)
	}

	relays := make([]*icmp34relay.Relay, 0)
	for _, ifa := range cfg.Interfaces {
		relay, err := icmp34relay.New(ifa, cfg.GetBackends())
		if err != nil {
			log.Fatalf("unable to get ICMP34 relay: %s", err)
		}

		err = relay.Start()
		if err != nil {
			log.Fatalf("unable to start relay: %s", err)
		}

		relays = append(relays, relay)
	}

	if len(relays) == 0 {
		log.Fatal("no matching interface found")
	}

	m := metrics.New(relays)
	prometheus.Register(m)

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9994", nil)
}
