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
	HOSTIDNT = "router:dhcpv4"
	HOSTNAME = "home.kellybecker.me"
	HOSTIPDB *utils.IPDB
)

func main() {
	if hostcidr := os.Getenv("HOSTCIDR"); hostcidr != "" {
		HOSTCIDR = hostcidr
	}

	if hostidnt := os.Getenv("HOSTIDNT"); hostidnt != "" {
		HOSTIDNT = hostidnt
	}

	if hostname := os.Getenv("HOSTNAME"); hostname != "" {
		HOSTNAME = hostname
	}

	HOSTIPDB = utils.NewIPDB(HOSTCIDR, HOSTNAME, HOSTIDNT)

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
	// @TODO:
	// REMOVE FILLER
	HOSTIPDB.AddHost(
		net.IP{192, 168, 0, 2},
		net.HardwareAddr{},
		"filler",
	)

	// Hostname identifying the Client
	// DHCPOptHostname overrides this value.
	hostname := string(bytes.Trim(tcp.ServerName, "\x00"))

	// Prepare the DHCPv4 Response packet.
	res := layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,       // 6 = 10mb eth
		Xid:          tcp.Xid, // Transaction ID
	}

	var (
		parameters []byte              // Requested Response Options
		options    []layers.DHCPOption // Response Option Cache
		lease      *utils.Lease        // Lease of Client
	)

	// Begin iteration over the Request packet Options
	for _, option := range tcp.Options {
		switch option.Type {
		case layers.DHCPOptMessageType:
			switch layers.DHCPMsgType(option.Data[0]) {
			case layers.DHCPMsgTypeDiscover:
				lease = HOSTIPDB.GetLeaseByIP(tcp.ClientIP)

				switch {
				case lease == nil:
					lease = HOSTIPDB.AddHost(
						tcp.ClientIP,
						tcp.ClientHWAddr,
						hostname,
					)
					fallthrough
				case lease != nil &&
					bytes.Equal(lease.HardwareAddr, tcp.ClientHWAddr):
					lease.Hostname = hostname
					res.YourClientIP = lease.IP
					res.ClientHWAddr = lease.HardwareAddr
					options = append(options, layers.DHCPOption{
						Type:   layers.DHCPOpt(layers.DHCPOptMessageType),
						Length: 1,
						Data:   []byte{byte(layers.DHCPMsgTypeOffer)},
					})
				case lease != nil &&
					!bytes.Equal(lease.HardwareAddr, tcp.ClientHWAddr):
					options = append(options, layers.DHCPOption{
						Type:   layers.DHCPOpt(layers.DHCPOptMessageType),
						Length: 1,
						Data:   []byte{byte(layers.DHCPMsgTypeDecline)},
					})
				}

				// layers.DHCPOption{
				// 	// Rebinding Time Value
				// 	Type:   layers.DHCPOpt(layers.DHCPOptT2),
				// 	Length: 4,
				// 	Data:   []byte{0, 0, 0, 59}, // Seconds?
				// }
			case layers.DHCPMsgTypeOffer:
				// NOOP on Server
			case layers.DHCPMsgTypeRequest:
				lease = HOSTIPDB.GetHost(
					tcp.ClientIP,
					tcp.ClientHWAddr,
					hostname,
				)

				res.ClientIP = tcp.ClientIP
				res.YourClientIP = lease.IP
				res.ClientHWAddr = lease.HardwareAddr
				options = append(options, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptMessageType),
					Length: 1,
					Data:   []byte{byte(layers.DHCPMsgTypeAck)},
				})

				// layers.DHCPOption{
				// 	// Renewal Time Value
				// 	Type:   layers.DHCPOpt(layers.DHCPOptT1),
				// 	Length: 4,
				// 	Data:   []byte{0, 0, 0, 30}, // Seconds?
				// }, layers.DHCPOption{
				// 	// Rebinding Time Value
				// 	Type:   layers.DHCPOpt(layers.DHCPOptT2),
				// 	Length: 4,
				// 	Data:   []byte{0, 0, 0, 52}, // Seconds?
				// }
			case layers.DHCPMsgTypeAck:
				// NOOP on Server
			case layers.DHCPMsgTypeNak:
			case layers.DHCPMsgTypeDecline:
			case layers.DHCPMsgTypeRelease:
			case layers.DHCPMsgTypeInform:
			}

		// Collect Request Options
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
				panic(fmt.Errorf("DHCP Server isn't the HOSTCIDR %v", HOSTCIDR))
			}
		case layers.DHCPOptRequestIP:
			if !lease.IP.Equal(utils.ParseIP(option.Data)) {
				panic(fmt.Errorf("Requested IP isn't Lease %v", lease))
			}
		case layers.DHCPOptLeaseTime:
			lease.LeaseTime = binary.BigEndian.Uint32(option.Data)
		case layers.DHCPOptParamsRequest:
			parameters = append(parameters, option.Data...)
		}
	}

	// Populate the Response packet Options
	for _, parameter := range parameters {
		opt := layers.DHCPOption{
			Type: layers.DHCPOpt(parameter),
		}

		switch layers.DHCPOpt(parameter) {
		case layers.DHCPOptSubnetMask:
			opt.Length = uint8(len(HOSTIPDB.Mask))
			opt.Data = HOSTIPDB.Mask
		case layers.DHCPOptRouter:
			opt.Length = HOSTIPDB.MainIP.IPLength()
			opt.Data = HOSTIPDB.MainIP.IPBytes()
		case layers.DHCPOptDNS:
			opt.Length = HOSTIPDB.DNSIPs.DNSLength()
			opt.Data = HOSTIPDB.DNSIPs.DNSIPs()
		case layers.DHCPOptHostname:
			host := []byte(lease.Hostname)
			opt.Length = uint8(len(host))
			opt.Data = host
		case layers.DHCPOptDomainName:
			fqdn := []byte(lease.FQDN(HOSTIPDB))
			opt.Length = uint8(len(fqdn))
			opt.Data = fqdn
		case layers.DHCPOptLeaseTime:
			opt.Length = 4
			opt.Data = binary.BigEndian.AppendUint32([]byte{}, lease.LeaseTime)
		case layers.DHCPOptServerID:
			opt.Length = HOSTIPDB.MainIP.IPLength()
			opt.Data = HOSTIPDB.MainIP.IPBytes()
		}

		if opt.Length > 0 {
			options = append(options, opt)
		}
	}

	res.Options = append(options, layers.DHCPOption{
		Type: layers.DHCPOpt(layers.DHCPOptEnd),
	})

	fmt.Println(HOSTIPDB)
	pretty.Println(res)

	// Serialize the Response packet for byte interface
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{},
		&layers.IPv4{},
		&layers.TCP{},
		&res)
	fmt.Println(buf.Bytes())
	fmt.Println(string(buf.Bytes()))
}
