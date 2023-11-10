package main

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kr/pretty"
)

func DHCPv6(tcp *layers.DHCPv6, packet gopacket.Packet) {
	// Prepare the DHCPv6 Response packet.
	res := layers.DHCPv6{
		MsgType:       layers.DHCPv6MsgTypeAdverstise,
		TransactionID: tcp.TransactionID,
	}

	var (
		hostname   string
		clientDUID = new(layers.DHCPv6DUID)
		parameters []layers.DHCPv6Opt
		options    layers.DHCPv6Options
	)

	for _, option := range tcp.Options {
		switch option.Code {
		case layers.DHCPv6OptClientID:
			clientDUID.DecodeFromBytes(option.Data)
		case layers.DHCPv6OptOro:
			for i := uint16(0); i < (option.Length / 2); i++ {
				parameters = append(parameters, layers.DHCPv6Opt(
					binary.BigEndian.Uint16(option.Data[i*2:]),
				))
			}
		case layers.DHCPv6OptClientFQDN:
			hostname = string(option.Data)
		}
	}

	// Since there doesn't appear to be an address assignment in DHCPv6
	HOSTIPDB.AddHost(
		packet.NetworkLayer().(*layers.IPv6).SrcIP,
		clientDUID.LinkLayerAddress,
		hostname,
	)

	for _, parameter := range parameters {
		switch parameter {
		case layers.DHCPv6OptServerID:
			serverDUID := (&layers.DHCPv6DUID{
				LinkLayerAddress: HOSTIPDB.MainIP.HardwareAddr,
			}).Encode()

			options = append(options, layers.DHCPv6Option{
				Code:   parameter,
				Length: uint16(len(serverDUID)),
				Data:   serverDUID,
			})
		case layers.DHCPv6OptDNSServers:
			options = append(options, layers.DHCPv6Option{
				Code:   parameter,
				Length: uint16(HOSTIPDB.DNSIPs.DNSLength(true)),
				Data:   HOSTIPDB.DNSIPs.DNSIPs(true),
			})
		}
	}

	res.Options = options

	pretty.Println(res)

	// Serialize the Response packet for byte interface
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{},
		&layers.IPv6{},
		&layers.UDP{},
		&res)
	fmt.Println(buf.Bytes())
	fmt.Println(string(buf.Bytes()))
}
