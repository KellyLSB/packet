package utils

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket/layers"
)

type DNS struct {
	IPs []net.IP
}

func (d *DNS) DNSLength() (num uint8) {
	for _, ip := range d.IPs {
		if ips := ip.To4(); ips != nil {
			num += uint8(len(ips))
		} else {
			num += uint8(len(ip))
		}
	}

	return num
}

func (d *DNS) DNSIPs() []byte {
	var buf [][]byte = [][]byte{}
	for _, ip := range d.IPs {
		if ip.To4() != nil {
			buf = append(buf, []byte(ip.To4()))
		} else {
			buf = append(buf, []byte(ip))
		}
	}
	return bytes.Join(buf, []byte(""))
}

type Lease struct {
	net.IP
	net.HardwareAddr
	Hostname         string
	ClientIdentifier string
}

func (l *Lease) IPLength() uint8 {
	if ip := l.IP.To4(); ip != nil {
		return uint8(len(ip))
	} else {
		return uint8(len(l.IP))
	}
}

func (l *Lease) IPBytes() []byte {
	if ip := l.IP.To4(); ip != nil {
		return []byte(ip)
	} else {
		return []byte(l.IP)
	}
}

func (l *Lease) DNSResourceRecord() layers.DNSResourceRecord {
	return layers.DNSResourceRecord{
		Name: []byte(l.Hostname),
		Type: layers.DNSTypeA,
		IP:   l.IP,
	}
}

type IPDB struct {
	net.IPNet
	LastIP net.IP
	DNSIPs *DNS
	MainIP *Lease
	Leases []*Lease
}

func (i *IPDB) AddHost(
	ip net.IP,
	hardware net.HardwareAddr,
	hostname string,
) *Lease {
	if hardware.String() != "" {
		if lease := i.GetLeaseByHardwareAddr(hardware); lease != nil {
			return lease
		}
	}

	if hostname != "" {
		if lease := i.GetLeaseByHostname(hostname); lease != nil {
			return lease
		}
	}

	var nextIP net.IP
	switch {
	case ip.Equal(net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
		ip.Equal(net.IP{0, 0, 0, 0}),
		ip.Equal(net.IP{}):
		nextIP = i.NextIP()
	default:
		nextIP = i.OrNextIP(ip)
	}

	lease := &Lease{
		IP:           nextIP,
		HardwareAddr: hardware,
		Hostname:     hostname,
	}

	i.Leases = append(i.Leases, lease)
	i.LastIP = nextIP
	return lease
}

func (i *IPDB) GetLeaseByIP(ip net.IP) *Lease {
	for _, lease := range i.Leases {
		if lease.IP.Equal(ip) {
			return lease
		}
	}

	return nil
}

func (i *IPDB) ContainsIP(ip net.IP) bool {
	if lease := i.GetLeaseByIP(ip); lease != nil {
		return true
	}

	return false
}

func (i *IPDB) GetLeaseByHardwareAddr(hardware net.HardwareAddr) *Lease {
	for _, lease := range i.Leases {
		if lease.HardwareAddr.String() == hardware.String() {
			return lease
		}
	}

	return nil
}

func (i *IPDB) ContainsHardwareAddr(hardware net.HardwareAddr) bool {
	if lease := i.GetLeaseByHardwareAddr(hardware); lease != nil {
		return true
	}

	return false
}

func (i *IPDB) GetLeaseByHostname(hostname string) *Lease {
	for _, lease := range i.Leases {
		if lease.Hostname == hostname {
			return lease
		}
	}

	return nil
}

func (i *IPDB) ContainsHostname(hostname string) bool {
	if lease := i.GetLeaseByHostname(hostname); lease != nil {
		return true
	}

	return false
}

func (i *IPDB) DNS() layers.DNS {
	dns := layers.DNS{
		ANCount: i.NumLeasesWithHostnames(),
	}

	for _, lease := range i.Leases {
		if lease.Hostname == "" {
			continue
		}

		record := lease.DNSResourceRecord()
		if !bytes.ContainsAny(record.Name, ".") {
			record.Name = bytes.Join([][]byte{
				[]byte(i.MainIP.Hostname),
				record.Name,
			}, []byte("."))
		}

		dns.Answers = append(dns.Answers, record)
	}

	return dns
}

func (i *IPDB) NumLeasesWithHostnames() (num uint16) {
	for _, lease := range i.Leases {
		if lease.Hostname != "" {
			num += 1
		}
	}

	return num
}

func (i *IPDB) OrNextIP(ip net.IP) net.IP {
	for i.ContainsIP(ip) {
		ip = NextIP(ip, i.IPNet.Mask)
	}

	i.LastIP = ip
	return ip
}

func (i *IPDB) NextIP() net.IP {
	return i.OrNextIP(NextIP(i.LastIP, i.IPNet.Mask))
}

func NextIP(ip net.IP, masks ...net.IPMask) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)
	var typ = 16

	if nip := newIP.To4(); nip != nil {
		newIP = nip
		typ = 4
	}

	var mask net.IPMask
	for _, msk := range masks {
		if len(msk) == typ {
			mask = msk
		}
	}

	for i := typ - 1; i > 0; i-- {
		// Qualify subnet range...
		size, _ := mask.Size()
		switch typ {
		case 16:
			switch {
			case size >= 128 && i == 16,
				size >= 124 && i == 15,
				size >= 120 && i == 14,
				size >= 116 && i == 13,
				size >= 112 && i == 12,
				size >= 108 && i == 11,
				size >= 104 && i == 10,
				size >= 100 && i == 9,
				size >= 96 && i == 8,
				size >= 92 && i == 7,
				size >= 88 && i == 6,
				size >= 84 && i == 5,
				size >= 80 && i == 4,
				size >= 76 && i == 3,
				size >= 72 && i == 2,
				size >= 68 && i == 1,
				size >= 64 && i == 0:
				newIP[15] += 1
				return newIP
			}
		case 4:
			switch {
			case size >= 32 && i == 3,
				size >= 24 && i == 2,
				size >= 16 && i == 1,
				size >= 8 && i == 0:
				newIP[3] += 1
				return newIP
			}
		}

		// increase subnet
		if newIP[i] < 254 {
			newIP[i] += 1
			for n := i + 1; n < typ; n++ {
				if newIP[n] < 254 {
					newIP[n] += 1
					break
				}
			}
			break
		} else {
			newIP[i] = 0
		}
	}

	return newIP
}

func (i *IPDB) String() string {
	var output string = ""
	output += fmt.Sprintln(i.IPNet)

	for _, lease := range i.Leases {
		output += fmt.Sprintln(lease)
	}

	return output
}

func NewIPDB(input ...string) *IPDB {
	var (
		hostname         string
		network          string
		clientIdentifier string
	)

	switch len(input) {
	case 1:
		network = input[0]
	case 2:
		network = input[0]
		hostname = input[1]
	case 3:
		network = input[0]
		hostname = input[1]
		clientIdentifier = input[2]
	}

	ip, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		panic(err)
	}

	netInterface := "lo"
	if netIfi := os.Getenv("NETIFI"); netIfi != "" {
		netInterface = netIfi
	}

	netIface, err := net.InterfaceByName(netInterface)
	if err != nil {
		panic(err)
	}

	lease := &Lease{
		IP:               ip,
		HardwareAddr:     netIface.HardwareAddr,
		Hostname:         hostname,
		ClientIdentifier: clientIdentifier,
	}

	return &IPDB{
		IPNet:  *ipnet,
		LastIP: ip,
		DNSIPs: &DNS{IPs: []net.IP{ip}},
		MainIP: lease,
		Leases: []*Lease{lease},
	}
}
