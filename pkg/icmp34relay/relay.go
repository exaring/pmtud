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
)

const (
	snapLen = 1514
	ttl     = 64
	ethHLen = 14
)

// Relay is a packet relay
type Relay struct {
	ifName           string
	backends         []net.IP
	rc               *ipv4.RawConn
	pc               *pcap.Handle
	wg               sync.WaitGroup
	stop             chan struct{}
	logger           *zap.Logger
	packetsForwarded uint64
}

// New creates a new relay
func New(ifName string, backends []net.IP) (*Relay, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, errors.Wrap(err, "Unable to get logger")
	}

	return &Relay{
		ifName:   ifName,
		backends: backends,
		stop:     make(chan struct{}),
		logger:   logger,
	}, nil
}

// PacketsForwarded gets the amount of forwarded packets
func (r *Relay) PacketsForwarded() uint64 {
	return atomic.LoadUint64(&r.packetsForwarded)
}

// GetIfName gets the interface name the relay is listening on
func (r *Relay) GetIfName() string {
	return r.ifName
}

// Start starts the relay
func (r *Relay) Start() error {
	err := r.setupInterface()
	if err != nil {
		return errors.Wrap(err, "Unable to set up interface")
	}

	r.wg.Add(1)
	go r.serve()

	return nil
}

func (r *Relay) setupInterface() error {
	h, err := pcap.OpenLive(r.ifName, snapLen, false, pcap.BlockForever)
	if err != nil {
		return errors.Wrap(err, "Unable to get pcap handler")
	}

	r.pc = h

	err = h.SetBPFFilter("icmp and icmp[0] == 3 and icmp[1] == 4")
	if err != nil {
		return errors.Wrap(err, "Unable to set BPF filter")
	}

	c, err := net.ListenPacket("ip4:4", "0.0.0.0")
	if err != nil {
		return errors.Wrap(err, "Unable to get tx socket")
	}

	rc, err := ipv4.NewRawConn(c)
	if err != nil {
		return errors.Wrap(err, "Unable to get IPv4 raw conn")
	}

	r.rc = rc

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

func (r *Relay) serve() {
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

		payload, _, err := r.pc.ZeroCopyReadPacketData()
		if err != nil {
			r.logger.Error("Unable to get packet",
				zap.String("error", err.Error()),
				zap.String("interface", r.ifName))
			continue
		}

		payload = payload[ethHLen:] // cut off ethernet header
		hdr.TotalLen = ipv4.HeaderLen + len(payload)

		for _, b := range r.backends {
			hdr.Dst = b

			err = r.rc.WriteTo(hdr, payload, nil)
			if err != nil {
				r.logger.Error("Unable to relay packet",
					zap.String("error", err.Error()),
					zap.String("interface", r.ifName),
					zap.String("backend", b.String()))
			}
		}

		atomic.AddUint64(&r.packetsForwarded, 1)
	}
}
