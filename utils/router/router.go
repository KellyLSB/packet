package main

import (
	"os"
	"strings"

	"github.com/KellyLSB/packet/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	HOSTCIDR = "192.168.0.1/24"
	HOSTIDNT = "router:dhcpv4,dhcpv6"
	HOSTNAME = "home.kellybecker.me"
	HOSTIPDB *utils.IPDB
)

func main() {
	var (
		file *os.File
		err  error
	)

	if hostcidr := os.Getenv("HOSTCIDR"); hostcidr != "" {
		HOSTCIDR = hostcidr
	}

	if hostidnt := os.Getenv("HOSTIDNT"); hostidnt != "" {
		HOSTIDNT = hostidnt
	}

	if hostname := os.Getenv("HOSTNAME"); hostname != "" {
		HOSTNAME = hostname
	}

	if filename := os.Getenv("FILENAME"); filename != "" {
		file, err = os.Create(filename)
		if err != nil {
			panic(err)
		}
	}

	HOSTIPDB = utils.NewIPDB(HOSTCIDR, HOSTNAME, HOSTIDNT)

	if filenames := os.Getenv("PCAPFILE"); filenames != "" {
		for _, filename := range strings.Split(filenames, ":") {
			f, err := os.Open(filename)
			if err != nil {
				panic(err)
			}

			open, err := pcap.OpenOfflineFile(f)
			if err != nil {
				panic(err)
			}

			PacketSourcer(open, file)
		}
		return
	}

	netInterface := "lo"
	if netIfi := os.Getenv("NETIFI"); netIfi != "" {
		netInterface = netIfi
	}

	open, err := pcap.OpenLive(netInterface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	PacketSourcer(open, file)
}

func PacketSourcer(open *pcap.Handle, f *os.File) {
	var (
		writer *pcapgo.NgWriter
		err    error
	)

	if f != nil {
		writer, err = pcapgo.NewNgWriter(f, open.LinkType())
		if err != nil {
			panic(err)
		}
		defer writer.Flush()
	}

	packets := gopacket.NewPacketSource(open, open.LinkType())
	for packet := range packets.Packets() {
		var data []byte
		for _, layer := range packet.Layers() {
			switch layer.LayerType() {
			case layers.LayerTypeDHCPv4:
				tcp, _ := layer.(*layers.DHCPv4)
				data = DHCPv4(tcp)
				err = open.WritePacketData(data)
			case layers.LayerTypeDHCPv6:
				tcp, _ := layer.(*layers.DHCPv6)
				data = DHCPv6(tcp, packet)
				err = open.WritePacketData(data)
			}
		}

		if err != nil {
			panic(err)
		}

		if writer != nil {
			ci := packet.Metadata().CaptureInfo
			ci.InterfaceIndex = 0
			err = writer.WritePacket(ci, packet.Data())
			if err != nil {
				panic(err)
			}

			packet = gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
			if len(packet.Data()) > 0 {
				ci := packet.Metadata().CaptureInfo
				ci.InterfaceIndex = 0
				ci.Length = len(packet.Data())
				ci.CaptureLength = len(packet.Data())
				err = writer.WritePacket(ci, packet.Data())
				if err != nil {
					panic(err)
				}
			}
			writer.Flush()
		}
	}
}
