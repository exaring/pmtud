package icmp34relay

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	snapLen  = 1514
	ttl      = 64
	ethHLen  = 14
	IPv6HLen = 40
)

// Relay is a packet relay
type Relay struct {
	ifName               string
	backendsIPv4         []net.IP
	backendsIPv6         []net.IP
	rawconnIpv4          *ipv4.RawConn
	pktconnIpv6          *ipv6.PacketConn
	pcapIPv4             *pcap.Handle
	pcapIPv6             *pcap.Handle
	wg                   sync.WaitGroup
	stop                 chan struct{}
	logger               *zap.Logger
	packetsForwardedIPv4 uint64
	packetsForwardedIPv6 uint64
}

// New creates a new relay
func New(ifName string, backendsIPv4 []net.IP, backendsIPv6 []net.IP) (*Relay, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, errors.Wrap(err, "Unable to get logger")
	}

	return &Relay{
		ifName:       ifName,
		backendsIPv4: backendsIPv4,
		backendsIPv6: backendsIPv6,
		stop:         make(chan struct{}),
		logger:       logger,
	}, nil
}

// PacketsForwarded gets the amount of forwarded packets
func (r *Relay) PacketsForwarded() uint64 {
	return atomic.LoadUint64(&r.packetsForwardedIPv4) + atomic.LoadUint64(&r.packetsForwardedIPv6)
}

// PacketsForwardedIPv4 gets the amount of forwarded packets for the IPv4 address familiy
func (r *Relay) PacketsForwardedIPv4() uint64 {
	return atomic.LoadUint64(&r.packetsForwardedIPv4)
}

// PacketsForwardedIPv4 gets the amount of forwarded packets for the IPv6 address familiy
func (r *Relay) PacketsForwardedIPv6() uint64 {
	return atomic.LoadUint64(&r.packetsForwardedIPv6)
}

// GetIfName gets the interface name the relay is listening on
func (r *Relay) GetIfName() string {
	return r.ifName
}

// Start starts the relay
func (r *Relay) Start() error {
	if len(r.backendsIPv4) != 0 {
		err := r.startListenerIPv4()
		if err != nil {
			return errors.Wrap(err, "Unable to set up listener for IPv4")
		}

		r.wg.Add(1)
		go r.serveIPv4()
	}

	if len(r.backendsIPv6) != 0 {
		err := r.startListenerIPv6()
		if err != nil {
			return errors.Wrap(err, "Unable to set up listener for IPv6")
		}

		r.wg.Add(1)
		go r.serveIPv6()
	}

	return nil
}

func (r *Relay) startListenerIPv4() error {
	h, err := pcap.OpenLive(r.ifName, snapLen, false, pcap.BlockForever)
	if err != nil {
		return errors.Wrap(err, "Unable to get pcap handler")
	}

	r.pcapIPv4 = h

	err = h.SetBPFFilter("icmp and icmp[0] == 3 and icmp[1] == 4")
	if err != nil {
		return errors.Wrap(err, "Unable to set BPF filter for ICMP")
	}

	c, err := net.ListenPacket("ip4:4", "0.0.0.0")
	if err != nil {
		return errors.Wrap(err, "Unable to get tx socket for IPv4")
	}

	rc, err := ipv4.NewRawConn(c)
	if err != nil {
		return errors.Wrap(err, "Unable to get IPv4 raw conn")
	}

	r.rawconnIpv4 = rc

	return nil
}

func (r *Relay) startListenerIPv6() error {
	h, err := pcap.OpenLive(r.ifName, snapLen, false, pcap.BlockForever)
	if err != nil {
		return errors.Wrap(err, "Unable to get pcap handler")
	}

	r.pcapIPv6 = h

	err = h.SetBPFFilter("icmp6 and ip6[40] == 2")
	if err != nil {
		return errors.Wrap(err, "Unable to set BPF filter for ICMPv6")
	}

	c, err := net.ListenPacket("ip6:ipv6-icmp", "::0")
	if err != nil {
		return errors.Wrap(err, "Unable to get tx socket for IPv6")
	}

	r.pktconnIpv6 = ipv6.NewPacketConn(c)

	return nil
}

// Stop stops the relay
func (r *Relay) Stop() {
	close(r.stop)
}

// WaitForStop waits for the relay to stop
func (r *Relay) WaitForStop() {
	r.wg.Wait()
}

func (r *Relay) stopped() bool {
	select {
	case <-r.stop:
		return true
	default:
		return false
	}
}

func (r *Relay) serveIPv4() {
	defer r.wg.Done()

	hdr := &ipv4.Header{
		Version:  ipv4.Version,
		Protocol: int(layers.IPProtocolIPv4),
		Len:      ipv4.HeaderLen,
		TTL:      ttl,
	}

	for {
		if r.stopped() {
			return
		}

		payload, _, err := r.pcapIPv4.ZeroCopyReadPacketData()
		if err != nil {
			r.logger.Error("Unable to get packet",
				zap.String("error", err.Error()),
				zap.String("interface", r.ifName))
			continue
		}

		payload = payload[ethHLen:] // cut off ethernet header

		hdr.TotalLen = ipv4.HeaderLen + len(payload)

		for _, b := range r.backendsIPv4 {
			hdr.Dst = b

			err = r.rawconnIpv4.WriteTo(hdr, payload, nil)
			if err != nil {
				r.logger.Error("Unable to relay packet",
					zap.String("error", err.Error()),
					zap.String("interface", r.ifName),
					zap.String("backend", b.String()))
			}
		}

		atomic.AddUint64(&r.packetsForwardedIPv4, 1)
	}
}

func (r *Relay) serveIPv6() {
	defer r.wg.Done()

	var dst net.IPAddr

	for {
		if r.stopped() {
			return
		}

		// Read packet
		payload, _, err := r.pcapIPv6.ZeroCopyReadPacketData()
		if err != nil {
			r.logger.Error("Unable to get packet",
				zap.String("error", err.Error()),
				zap.String("interface", r.ifName))
			continue
		}

		// Parse IPv6 header from payload
		payload = payload[ethHLen:] // cut off ethernet header
		hdr, err := ipv6.ParseHeader(payload)
		if err != nil {
			r.logger.Error("Unable to parse packet header",
				zap.String("error", err.Error()),
				zap.String("interface", r.ifName))
			continue
		}

		// Strip ICMPv6 header from incoming packet, so that only the ICMPv6 Packet To Big
		// header + bits from original packet fragement are being relayed
		payload = payload[IPv6HLen:]

		// Re(p)lay packet to all IPv6 backends
		for _, b := range r.backendsIPv6 {
			dst.IP = b

			_, err = r.pktconnIpv6.WriteTo(payload, nil, &dst)
			if err != nil {
				r.logger.Error("Unable to relay packet",
					zap.String("error", err.Error()),
					zap.String("ingress interface", r.ifName),
					zap.String("source", hdr.Src.String()),
					zap.String("backend", b.String()))
			}
		}

		atomic.AddUint64(&r.packetsForwardedIPv6, 1)
	}
}
