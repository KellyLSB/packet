package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/KellyLSB/packet/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/kr/pretty"
)

var (
	HOSTCIDR = "0000:0000:0000:0000:0000:ffff:c0a8:0001/124"
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

	if filenames := os.Getenv("PCAPFILE"); filenames != "" {
		for _, filename := range strings.Split(filenames, ":") {
			f, err := os.Open(filename)
			if err != nil {
				panic(err)
			}

			r, err := pcapgo.NewReader(f)
			if err != nil {
				panic(err)
			}

			PacketReader(r)
		}
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

	// @TODO:
	// REMOVE FILLER
	HOSTIPDB.AddHost(
		net.IP{192, 168, 0, 2},
		net.HardwareAddr{},
		"filler",
	)

	fmt.Println(HOSTIPDB)

	hostname := string(bytes.Trim(tcp.ServerName, "\x00"))

	var parameters []byte

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
					Data:   []byte{byte(layers.DHCPMsgTypeOffer)},
				}, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptServerID),
					Length: HOSTIPDB.MainIP.IPLength(),
					Data:   HOSTIPDB.MainIP.IPBytes(),
				}, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptLeaseTime),
					Length: 4,
					Data:   binary.BigEndian.AppendUint32([]byte{}, lease.LeaseTime),
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
				// NOOP on Server
			case layers.DHCPMsgTypeRequest:
				lease = HOSTIPDB.GetHost(
					net.IP{}, tcp.ClientHWAddr, hostname,
				)

				res.YourClientIP = lease.IP
				res.ClientHWAddr = lease.HardwareAddr
				res.Options = append(res.Options, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPMsgTypeOffer),
					Length: 1,
					Data:   []byte{byte(layers.DHCPMsgTypeAck)},
				}, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptServerID),
					Length: HOSTIPDB.MainIP.IPLength(),
					Data:   HOSTIPDB.MainIP.IPBytes(),
				}, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptLeaseTime),
					Length: 4,
					Data:   binary.BigEndian.AppendUint32([]byte{}, lease.LeaseTime),
				}, layers.DHCPOption{
					// Renewal Time Value
					Type:   layers.DHCPOpt(layers.DHCPOptT1),
					Length: 4,
					Data:   []byte{0, 0, 0, 30}, // Seconds?
				}, layers.DHCPOption{
					// Rebinding Time Value
					Type:   layers.DHCPOpt(layers.DHCPOptT2),
					Length: 4,
					Data:   []byte{0, 0, 0, 52}, // Seconds?
				}, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptHostname),
					Length: uint8(len(lease.Hostname)),
					Data:   []byte(lease.Hostname),
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
			case layers.DHCPMsgTypeAck:
			case layers.DHCPMsgTypeNak:
			case layers.DHCPMsgTypeDecline:
			case layers.DHCPMsgTypeRelease:
			case layers.DHCPMsgTypeInform:
			}
		case layers.DHCPOptClientID:
			lease.ClientIdentifier = string(option.Data)
		case layers.DHCPOptHostname:
			hostname = string(option.Data)
			lease.Hostname = hostname
		case layers.DHCPOptMaxMessageSize:
			val := binary.BigEndian.Uint16(option.Data)
			fmt.Printf("MaxMessageSize: %d\n", val)
		case layers.DHCPOptServerID:
			if !HOSTIPDB.MainIP.IP.Equal(utils.ParseIP(option.Data)) {
				panic(fmt.Errorf("DHCP Server isn't the HOSTCIDR %v\n", HOSTCIDR))
			}
		case layers.DHCPOptRequestIP:
			if !lease.IP.Equal(utils.ParseIP(option.Data)) {
				panic(fmt.Errorf("Requested IP isn't Lease %v\n", lease))
			}
		case layers.DHCPOptLeaseTime:
			lease.LeaseTime = binary.BigEndian.Uint32(option.Data)
		case layers.DHCPOptParamsRequest:
			parameters = append(parameters, option.Data...)
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
