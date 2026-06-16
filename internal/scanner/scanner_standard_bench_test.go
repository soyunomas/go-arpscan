package scanner

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func benchmarkStandardConfig() (*net.Interface, *Config, net.IP, net.IP) {
	iface := &net.Interface{
		Name:         "bench0",
		HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x20, 0x30},
	}
	cfg := &Config{
		Interface:         iface,
		EthernetPrototype: 0x0806,
		ArpHardwareType:   1,
		ArpProtocolType:   0x0800,
		ArpHardwareLen:    6,
		ArpProtocolLen:    4,
		ArpOpCode:         1,
		VlanID:            -1,
	}
	return iface, cfg, net.IPv4(192, 168, 24, 10).To4(), net.IPv4(192, 168, 24, 1).To4()
}

func BenchmarkStandardPacketSerializeReused(b *testing.B) {
	iface, cfg, srcIP, dstIP := benchmarkStandardConfig()
	builder := newStandardPacketBuilder(nil, iface, cfg)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := builder.serialize(srcIP, dstIP); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStandardPacketSerializeLegacy(b *testing.B) {
	iface, cfg, srcIP, dstIP := benchmarkStandardConfig()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := serializeLegacyStandardARP(iface, cfg, srcIP, dstIP, buf, opts); err != nil {
			b.Fatal(err)
		}
		buf.Clear()
	}
}

func serializeLegacyStandardARP(iface *net.Interface, cfg *Config, srcIP, dstIP net.IP, buf gopacket.SerializeBuffer, opts gopacket.SerializeOptions) ([]byte, error) {
	sourceEthMAC := iface.HardwareAddr
	if cfg.EthSrcMAC != nil {
		sourceEthMAC = cfg.EthSrcMAC
	}
	destinationEthMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if cfg.EthDstMAC != nil {
		destinationEthMAC = cfg.EthDstMAC
	}
	sourceArpSHA := iface.HardwareAddr
	if cfg.ArpSHA != nil {
		sourceArpSHA = cfg.ArpSHA
	}
	destinationArpTHA := []byte{0, 0, 0, 0, 0, 0}
	if cfg.ArpTHA != nil {
		destinationArpTHA = []byte(cfg.ArpTHA)
	}

	eth := layers.Ethernet{
		SrcMAC:       sourceEthMAC,
		DstMAC:       destinationEthMAC,
		EthernetType: layers.EthernetType(cfg.EthernetPrototype),
	}
	arp := layers.ARP{
		AddrType:          layers.LinkType(cfg.ArpHardwareType),
		Protocol:          layers.EthernetType(cfg.ArpProtocolType),
		HwAddressSize:     cfg.ArpHardwareLen,
		ProtAddressSize:   cfg.ArpProtocolLen,
		Operation:         cfg.ArpOpCode,
		SourceHwAddress:   []byte(sourceArpSHA),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      destinationArpTHA,
		DstProtAddress:    []byte(dstIP.To4()),
	}

	layersToSerialize := make([]gopacket.SerializableLayer, 0, 5)
	if cfg.UseLLC {
		llc := layers.LLC{DSAP: 0xAA, SSAP: 0xAA, Control: 0x03}
		snap := layers.SNAP{OrganizationalCode: []byte{0x00, 0x00, 0x00}, Type: layers.EthernetType(cfg.EthernetPrototype)}
		if cfg.VlanID >= 0 {
			eth.EthernetType = layers.EthernetTypeDot1Q
			dot1q := layers.Dot1Q{VLANIdentifier: uint16(cfg.VlanID)}
			layersToSerialize = append(layersToSerialize, &eth, &dot1q, &llc, &snap, &arp)
		} else {
			layersToSerialize = append(layersToSerialize, &eth, &llc, &snap, &arp)
		}
	} else {
		if cfg.VlanID >= 0 {
			eth.EthernetType = layers.EthernetTypeDot1Q
			dot1q := layers.Dot1Q{VLANIdentifier: uint16(cfg.VlanID), Type: layers.EthernetType(cfg.EthernetPrototype)}
			layersToSerialize = append(layersToSerialize, &eth, &dot1q, &arp)
		} else {
			layersToSerialize = append(layersToSerialize, &eth, &arp)
		}
	}
	if len(cfg.PaddingData) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(cfg.PaddingData))
	}
	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
