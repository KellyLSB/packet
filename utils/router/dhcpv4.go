package main

import (
	"bytes"
	"encoding/binary"

	"github.com/KellyLSB/packet/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kr/pretty"
)

func DHCPv4(tcp *layers.DHCPv4) []byte {
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
			case layers.DHCPMsgTypeOffer:
				// NOOP on Server
			case layers.DHCPMsgTypeRequest:
				lease = HOSTIPDB.GetHost(
					tcp.ClientIP,
					tcp.ClientHWAddr,
					hostname,
				)

				lease.Renew()

				res.ClientIP = tcp.ClientIP
				res.YourClientIP = lease.IP
				res.ClientHWAddr = lease.HardwareAddr
				options = append(options, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptMessageType),
					Length: 1,
					Data:   []byte{byte(layers.DHCPMsgTypeAck)},
				})
			case layers.DHCPMsgTypeAck:
				// NOOP on Server
			case layers.DHCPMsgTypeNak:
				// NOOP on Server
			case layers.DHCPMsgTypeDecline:
				// NOOP on Server
			case layers.DHCPMsgTypeRelease:
				lease = HOSTIPDB.GetHost(
					tcp.ClientIP,
					tcp.ClientHWAddr,
					hostname,
				)

				HOSTIPDB.Release(lease)

				res.ClientIP = tcp.ClientIP
				res.ClientHWAddr = lease.HardwareAddr
				options = append(options, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptMessageType),
					Length: 1,
					Data:   []byte{byte(layers.DHCPMsgTypeAck)},
				})
			case layers.DHCPMsgTypeInform:
				res.ClientIP = tcp.ClientIP
				res.ClientHWAddr = tcp.ClientHWAddr
				options = append(options, layers.DHCPOption{
					Type:   layers.DHCPOpt(layers.DHCPOptMessageType),
					Length: 1,
					Data:   []byte{byte(layers.DHCPMsgTypeAck)},
				})
			}

		// Collect Request Options
		case layers.DHCPOptClientID:
			lease.ClientIdentifier = string(option.Data)
		case layers.DHCPOptHostname:
			hostname = string(option.Data)
			lease.Hostname = hostname
		//case layers.DHCPOptMaxMessageSize:
		//val := binary.BigEndian.Uint16(option.Data)
		//fmt.Printf("MaxMessageSize: %d\n", val)
		case layers.DHCPOptServerID:
			// NAK The response if the DHCP server isn't the expectation.
			if !HOSTIPDB.MainIP.IP.Equal(utils.ParseIP(option.Data)) {
				for i, option := range options {
					if option.Type == layers.DHCPOptMessageType {
						options[i].Data = []byte{byte(layers.DHCPMsgTypeNak)}
					}
				}
			}
		case layers.DHCPOptRequestIP:
			// NAK The response if the lease cannot request an IP address
			ip := utils.ParseIP(option.Data)
			if HOSTIPDB.GetLeaseByIP(ip) == nil {
				if !utils.EmptyIP(res.YourClientIP) {
					res.YourClientIP = ip
				}
				lease.IP = ip
			}

			if !lease.IP.Equal(ip) {
				for i, option := range options {
					if option.Type == layers.DHCPOptMessageType {
						options[i].Data = []byte{byte(layers.DHCPMsgTypeNak)}
					}
				}
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

	// Serialize the Response packet for byte interface
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{},
		&layers.IPv4{},
		&layers.UDP{},
		&res)

	pretty.Println(res)
	return buf.Bytes()
}
