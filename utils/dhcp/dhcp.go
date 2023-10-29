package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var ROUTER = "192.168.1.1/24"
var POOL *IPDB

func main() {
	if router := os.Getenv("ROUTER"); router != "" {
		ROUTER = router
	}

	POOL = NewIPDB(ROUTER, "router")

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

	r, err := pcapgo.NewEthernetHandle("lo")
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

	for _, option := range tcp.Options {
		switch option.Type {
		case layers.DHCPOptMessageType:
			switch layers.DHCPMsgType(option.Data[0]) {
			case layers.DHCPMsgTypeDiscover:
				POOL.AddHost(
					tcp.ClientIP,
					tcp.ClientHWAddr,
					string(tcp.ServerName),
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
