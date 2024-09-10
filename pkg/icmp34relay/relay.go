package icmp34relay

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	snapLen    = 1514
	ethHLen    = 14
	bpfFilter4 = "icmp and icmp[0] == 3 and icmp[1] == 4"
	bpfFilter6 = "icmp6 and ip6[40] == 2"
)

// Relay is a packet relay
type Relay struct {
	ifName            string
	backends          []netip.Addr
	rc6               *ipv6.PacketConn
	rc4               *ipv4.PacketConn
	pc6               *pcap.Handle
	pc4               *pcap.Handle
	logger            *zap.Logger
	packetsForwarded6 atomic.Uint64
	packetsForwarded4 atomic.Uint64
}

// New creates a new relay
func New(ifName string, backends []netip.Addr) (*Relay, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("unable to create new logger: %w", err)
	}

	return &Relay{
		ifName:   ifName,
		backends: backends,
		logger:   logger,
	}, nil
}

// PacketsForwardedIPv6 returns the number of forwarded packets of IPv6 address family.
func (r *Relay) PacketsForwardedIPv6() uint64 {
	return r.packetsForwarded6.Load()
}

// PacketsForwardedIPv4 returns the number of forwarded packets of IPv4 address family.
func (r *Relay) PacketsForwardedIPv4() uint64 {
	return r.packetsForwarded4.Load()
}

// GetIfName gets the interface name the relay is listening on
func (r *Relay) GetIfName() string {
	return r.ifName
}

// Start starts the relay
func (r *Relay) Start() error {
	if err := r.setupInterface6(); err != nil {
		return fmt.Errorf("unable to set up interface for IPv6: %w", err)
	}

	if err := r.setupInterface4(); err != nil {
		return fmt.Errorf("unable to set up interface for IPv4: %w", err)
	}

	go r.serve6()
	go r.serve4()

	return nil
}

func (r *Relay) setupInterface6() error {
	var err error

	r.pc6, err = pcap.OpenLive(r.ifName, snapLen, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("unable to get pcap handler: %w", err)
	}

	if err = r.pc6.SetBPFFilter(bpfFilter6); err != nil {
		return fmt.Errorf("unable to set BPF filter: %w", err)
	}

	// use IPv6 Encapsulation (RFC2473)
	c, err := net.ListenPacket("ip6:41", "::")
	if err != nil {
		return fmt.Errorf("unable to get tx socket: %w", err)
	}

	r.rc6 = ipv6.NewPacketConn(c)
	return nil
}

func (r *Relay) setupInterface4() error {
	var err error

	r.pc4, err = pcap.OpenLive(r.ifName, snapLen, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("unable to get pcap handler: %w", err)
	}

	if err = r.pc4.SetBPFFilter(bpfFilter4); err != nil {
		return fmt.Errorf("unable to set BPF filter: %w", err)
	}

	// use IP-in-IP (RFC2003)
	c, err := net.ListenPacket("ip4:4", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("unable to get tx socket: %w", err)
	}

	r.rc4 = ipv4.NewPacketConn(c)
	return nil
}

func (r *Relay) serve6() {
	r.logger.Info("start service for IPv6")

	for {
		payload, _, err := r.pc6.ZeroCopyReadPacketData()
		if err != nil {
			r.logger.Error("Unable to get packet",
				zap.String("error", err.Error()),
				zap.String("interface", r.ifName))
			continue
		}

		payload = payload[ethHLen:] // cut off ethernet

		for _, b := range r.backends {
			if !b.Is6() {
				continue
			}

			if _, err = r.rc6.WriteTo(payload, nil, &net.IPAddr{IP: net.IP(b.AsSlice())}); err != nil {
				r.logger.Error("Unable to relay packet",
					zap.String("error", err.Error()),
					zap.String("interface", r.ifName),
					zap.String("backend", b.String()))
			}
		}

		_ = r.packetsForwarded6.Add(1)
	}
}

func (r *Relay) serve4() {
	r.logger.Info("start service for IPv4")

	for {
		payload, _, err := r.pc4.ZeroCopyReadPacketData()
		if err != nil {
			r.logger.Error("Unable to get packet",
				zap.String("error", err.Error()),
				zap.String("interface", r.ifName))
			continue
		}

		payload = payload[ethHLen:] // cut off ethernet header

		for _, b := range r.backends {
			if !b.Is4() {
				continue
			}

			if _, err = r.rc4.WriteTo(payload, nil, &net.IPAddr{IP: net.IP(b.AsSlice())}); err != nil {
				r.logger.Error("Unable to relay packet",
					zap.String("error", err.Error()),
					zap.String("interface", r.ifName),
					zap.String("backend", b.String()))
			}
		}

		_ = r.packetsForwarded4.Add(1)
	}
}
