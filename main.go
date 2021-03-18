package main

import (
	"flag"
	"net/http"

	"github.com/exaring/pmtud/pkg/config"
	"github.com/exaring/pmtud/pkg/icmp34relay"
	"github.com/exaring/pmtud/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	log "github.com/sirupsen/logrus"
)

var (
	cfgFilePath = flag.String("cfg.file", "config.yaml", "Config file")
)

func main() {
	flag.Parse()

	cfg, err := config.GetConfig(*cfgFilePath)
	if err != nil {
		log.WithError(err).Fatal("Unable to get config")
	}

	relays := make([]*icmp34relay.Relay, 0)
	for _, ifa := range cfg.Interfaces {
		relay, err := icmp34relay.New(ifa, cfg.GetBackends())
		if err != nil {
			log.WithError(err).Fatal("Unable to get ICMP34 relay")
		}

		err = relay.Start()
		if err != nil {
			log.WithError(err).Fatal("Unable to start relay")
		}

		relays = append(relays, relay)
	}

	m := metrics.New(relays)
	prometheus.Register(m)

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9994", nil)
}
