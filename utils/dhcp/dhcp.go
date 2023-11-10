package main

import (
	"os"
	"strings"

	"github.com/KellyLSB/packet/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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
			case layers.LayerTypeDHCPv6:
				tcp, _ := layer.(*layers.DHCPv6)
				DHCPv6(tcp, packet)
			}
		}
	}
}
