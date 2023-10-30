package main

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	HOSTCIDR = "192.168.1.1/24"
	HOSTNAME = "home.kellybecker.me"
	POOL     *IPDB
)

func main() {
	if hostcidr := os.Getenv("HOSTCIDR"); hostcidr != "" {
		HOSTCIDR = hostcidr
	}

	if hostname := os.Getenv("HOSTNAME"); hostname != "" {
		HOSTNAME = hostname
	}

	POOL = NewIPDB(HOSTCIDR, HOSTNAME)

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
	// res := layers.DHCPv4{
	// 	Operation:    layers.DHCPOpReply,
	// 	HardwareType: layers.LinkTypeEthernet,
	// 	HardwareLen:  6,       // 6 = 10mb eth
	// 	Xid:          tcp.Xid, // Transaction ID
	// }

	//fmt.Println(tcp)

	fmt.Println(POOL)

	hostname := string(bytes.Trim(tcp.ServerName, "\x00"))

	for _, option := range tcp.Options {
		switch option.Type {
		case layers.DHCPOptMessageType:
			switch layers.DHCPMsgType(option.Data[0]) {
			case layers.DHCPMsgTypeDiscover:
				POOL.AddHost(
					tcp.ClientIP,
					tcp.ClientHWAddr,
					hostname,
				)
				POOL.AddHost(
					net.IP{192, 168, 3, 2},
					net.HardwareAddr{},
					hostname,
				)
				POOL.AddHost(
					net.IP{192, 168, 3, 1},
					net.HardwareAddr{},
					hostname,
				)
				POOL.AddHost(
					tcp.ClientIP,
					net.HardwareAddr{},
					hostname,
				)
			case layers.DHCPMsgTypeOffer:
			case layers.DHCPMsgTypeRequest:
			case layers.DHCPMsgTypeAck:
			case layers.DHCPMsgTypeNak:
			case layers.DHCPMsgTypeDecline:
			case layers.DHCPMsgTypeRelease:
			case layers.DHCPMsgTypeInform:
			}
		}
	}

	fmt.Println(POOL)
}
