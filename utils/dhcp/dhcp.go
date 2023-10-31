package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/KellyLSB/packet/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/kr/pretty"
)

var (
	HOSTCIDR = "0000:0000:0000:0000:0000:ffff:c0a8:0101/124"
	HOSTNAME = "home.kellybecker.me"
	HOSTIPDB *utils.IPDB
)

func main() {
	if hostcidr := os.Getenv("HOSTCIDR"); hostcidr != "" {
		HOSTCIDR = hostcidr
	}

	if hostname := os.Getenv("HOSTNAME"); hostname != "" {
		HOSTNAME = hostname
	}

	HOSTIPDB = utils.NewIPDB(HOSTCIDR, HOSTNAME)

	if filename := os.Getenv("PCAPFILE"); filename != "" {
		f, err := os.Open(filename)
		if err != nil {
			panic(err)
		}

		r, err := pcapgo.NewReader(f)
		if err != nil {
			panic(err)
		}

		PacketReader(r)
		return
	}

	netInterface := "lo"
	if netIfi := os.Getenv("NETIFI"); netIfi != "" {
		netInterface = netIfi
	}

	r, err := pcapgo.NewEthernetHandle(netInterface)
	if err != nil {
		panic(err)
	}

	PacketReader(r)
}

func PacketReader(r gopacket.PacketDataSource) {
	pkgsrc := gopacket.NewPacketSource(r, layers.LayerTypeEthernet)
	for packet := range pkgsrc.Packets() {
		for _, layer := range packet.Layers() {
			switch layer.LayerType() {
			case layers.LayerTypeDHCPv4:
				tcp, _ := layer.(*layers.DHCPv4)
				DHCPv4(tcp)
			}
		}
	}
}

func DHCPv4(tcp *layers.DHCPv4) {
	res := layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,       // 6 = 10mb eth
		Xid:          tcp.Xid, // Transaction ID
	}

	fmt.Println(HOSTIPDB)

	hostname := string(bytes.Trim(tcp.ServerName, "\x00"))

	var lease *utils.Lease
	for _, option := range tcp.Options {
		switch option.Type {
		case layers.DHCPOptMessageType:
			switch layers.DHCPMsgType(option.Data[0]) {
			case layers.DHCPMsgTypeDiscover:
				lease = HOSTIPDB.AddHost(
					tcp.ClientIP,
					tcp.ClientHWAddr,
					hostname,
				)

				res.YourClientIP = lease.IP
				res.ClientHWAddr = lease.HardwareAddr
				res.Options = append(res.Options, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPMsgTypeOffer),
					Length: 1,
					Data:   []byte{2},
				}, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptServerID),
					Length: HOSTIPDB.MainIP.IPLength(),
					Data:   HOSTIPDB.MainIP.IPBytes(),
				}, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptLeaseTime),
					Length: 4,
					Data:   []byte{0, 0, 0, 30}, // Seconds?
				}, layers.DHCPOption{
					// Rebinding Time Value
					Type:   layers.DHCPOpt(layers.DHCPOptT2),
					Length: 4,
					Data:   []byte{0, 0, 0, 59}, // Seconds?
				}, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptSubnetMask),
					Length: uint8(len(HOSTIPDB.Mask)),
					Data:   HOSTIPDB.Mask,
				}, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptRouter),
					Length: HOSTIPDB.MainIP.IPLength(),
					Data:   HOSTIPDB.MainIP.IPBytes(),
				}, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptDNS),
					Length: HOSTIPDB.DNSIPs.DNSLength(),
					Data:   HOSTIPDB.DNSIPs.DNSIPs(),
				}, layers.DHCPOption{
					Type: layers.DHCPOpt(layers.DHCPOptEnd),
				})
			case layers.DHCPMsgTypeOffer:
			case layers.DHCPMsgTypeRequest:
			case layers.DHCPMsgTypeAck:
			case layers.DHCPMsgTypeNak:
			case layers.DHCPMsgTypeDecline:
			case layers.DHCPMsgTypeRelease:
			case layers.DHCPMsgTypeInform:
			}
		case layers.DHCPOptClientID:
			lease.ClientIdentifier = string(option.Data)
		case layers.DHCPOptHostname:
			lease.Hostname = string(option.Data)
		}
	}

	fmt.Println(HOSTIPDB)
	pretty.Println(res)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{},
		&layers.IPv4{},
		&layers.TCP{},
		&res)
	fmt.Println(buf.Bytes())
}
