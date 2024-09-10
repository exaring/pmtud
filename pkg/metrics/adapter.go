package metrics

import (
	"github.com/exaring/pmtud/pkg/icmp34relay"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	prefix = "pmtud_"
)

var (
	packetForwardedDesc *prometheus.Desc
)

func init() {
	labels := []string{"ifName", "ipFamily"}

	packetForwardedDesc = prometheus.NewDesc(prefix+"forwarded_packets", "Number of ICMP packets forwarded (attempted, not guaranteed)", labels, nil)
}

// New creates a new collector instance for an ICMP34 relay
func New(relays []*icmp34relay.Relay) prometheus.Collector {
	return &icmp34relayCollector{
		relays: relays,
	}
}

// icmp34relayCollector provides a collector for icmp34relay metrcis with Prometheus
type icmp34relayCollector struct {
	relays []*icmp34relay.Relay
}

// Describe conforms to the prometheus collector interface
func (rrc *icmp34relayCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- packetForwardedDesc
}

// Collect conforms to the prometheus collector interface
func (rrc *icmp34relayCollector) Collect(ch chan<- prometheus.Metric) {
	for _, r := range rrc.relays {
		ch <- prometheus.MustNewConstMetric(packetForwardedDesc, prometheus.CounterValue, float64(r.PacketsForwardedIPv6()), []string{r.GetIfName(), "ipv6"}...)
		ch <- prometheus.MustNewConstMetric(packetForwardedDesc, prometheus.CounterValue, float64(r.PacketsForwardedIPv4()), []string{r.GetIfName(), "ipv4"}...)
	}
}
