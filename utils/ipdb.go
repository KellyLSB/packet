package utils

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type DNS struct {
	IPs []net.IP
}

func (d *DNS) DNSLength(c16 ...bool) (num uint8) {
	for _, ip := range d.IPs {
		if ips := ip.To4(); ips != nil && len(c16) < 1 {
			num += uint8(len(ips))
		} else {
			num += uint8(len(ip))
		}
	}

	return num
}

func (d *DNS) DNSIPs(c16 ...bool) []byte {
	var buf [][]byte = [][]byte{}
	var bol bool
	for _, ip := range d.IPs {
		if ips := ip.To4(); ips != nil && len(c16) < 1 {
			buf = append(buf, []byte(ips))
			bol = true
		} else {
			if !bol {
				buf = append(buf, []byte(ip))
			}
		}
	}
	return bytes.Join(buf, []byte(""))
}

type Lease struct {
	net.IP
	net.HardwareAddr
	Allocated        bool
	LeaseTime        uint32
	LeasedTime       time.Time
	Hostname         string
	ClientIdentifier string
}

func NewLease(
	ip net.IP,
	hardware net.HardwareAddr,
	hostname string,
) (lease *Lease) {
	lease = &Lease{
		IP:           ip,
		HardwareAddr: hardware,
		LeaseTime:    uint32(60),
		LeasedTime:   time.Now(),
		Hostname:     hostname,
	}

	return lease
}

func (l *Lease) Renew() bool {
	l.LeasedTime = time.Now()
	return true
}

func (l *Lease) FQDN(i *IPDB) string {
	if strings.Contains(l.Hostname, ".") {
		return l.Hostname
	}

	return strings.Join([]string{
		l.Hostname,
		i.MainIP.Hostname,
	}, ".")
}

func (l *Lease) IPLength(c16 ...bool) uint8 {
	if ip := l.IP.To4(); ip != nil && len(c16) < 1 {
		return uint8(len(ip))
	} else {
		return uint8(len(l.IP))
	}
}

func (l *Lease) IPBytes(c16 ...bool) []byte {
	if ip := l.IP.To4(); ip != nil && len(c16) < 1 {
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
	sync.Mutex

	net.IPNet
	LastIP net.IP
	DNSIPs *DNS
	MainIP *Lease
	Leases []*Lease
}

func (i *IPDB) Release(l *Lease) bool {
	i.Mutex.Lock()
	defer i.Mutex.Unlock()
	index := slices.Index(i.Leases, l)

	i.Leases = append(
		i.Leases[0:index],
		i.Leases[index:]...,
	)

	return true
}

func (i *IPDB) AddHost(
	ip net.IP,
	hardware net.HardwareAddr,
	hostname string,
) *Lease {
	if lease := i.GetHost(net.IP{}, hardware, hostname); lease != nil {
		return lease
	}

	var (
		nextIP net.IP
		ipZero bool
	)

	if EmptyIP(ip) {
		nextIP = i.NextIP()
		ipZero = true
	} else {
		nextIP = i.OrNextIP(ip)
	}

	i.Mutex.Lock()
	defer i.Mutex.Unlock()

	lease := NewLease(nextIP, hardware, hostname)
	i.Leases = append(i.Leases, lease)
	if ipZero {
		i.LastIP = nextIP
	}

	return lease
}

func (i *IPDB) GetHost(
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

	return i.GetLeaseByIP(ip)
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

func (i *IPDB) GetLeaseByIPHardwareAddr(ip net.IP, hardware net.HardwareAddr, or ...bool) *Lease {
	for _, lease := range i.Leases {
		if len(or) > 0 {
			if lease.IP.Equal(ip) || lease.HardwareAddr.String() == hardware.String() {
				return lease
			}
		} else {
			if lease.IP.Equal(ip) && lease.HardwareAddr.String() == hardware.String() {
				return lease
			}
		}
	}

	return nil
}

func (i *IPDB) ContainsIPHardwareAddr(ip net.IP, hardware net.HardwareAddr, or ...bool) bool {
	if lease := i.GetLeaseByIPHardwareAddr(ip, hardware, or...); lease != nil {
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

		host := lease.DNSResourceRecord()
		record := lease.DNSResourceRecord()
		record.Name = []byte(lease.FQDN(i))
		if bytes.ContainsAny(host.Name, ".") {
			dns.Answers = append(dns.Answers, host)
		} else {
			dns.Answers = append(dns.Answers, host, record)
		}
	}

	return dns
}

func (i *IPDB) NumLeasesWithHostnames() (num uint16) {
	for _, lease := range i.Leases {
		if lease.Hostname != "" {
			host := lease.DNSResourceRecord()
			if bytes.ContainsAny(host.Name, ".") {
				num += 1
			} else {
				num += 2
			}
		}
	}

	return num
}

func (i *IPDB) OrNextIP(ip net.IP) net.IP {
	for i.ContainsIP(ip) {
		ip = NextIP(ip, i.IPNet.Mask)
	}

	return ip
}

func (i *IPDB) NextIP() net.IP {
	return i.OrNextIP(NextIP(i.LastIP, i.IPNet.Mask))
}

func NextIP(ip net.IP, masks ...net.IPMask) net.IP {
	newIP := ParseIP(ip)
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

	lease := NewLease(ip, netIface.HardwareAddr, hostname)
	lease.ClientIdentifier = clientIdentifier

	return &IPDB{
		IPNet:  *ipnet,
		LastIP: ip,
		DNSIPs: &DNS{IPs: []net.IP{ip}},
		MainIP: lease,
		Leases: []*Lease{lease},
	}
}

func ParseIP(in []byte) (ip net.IP) {
	ip = make(net.IP, len(in))
	copy(ip, in)
	return ip
}

func EmptyIP(ip net.IP) bool {
	return ip.Equal(net.IP{}) || ip.IsUnspecified()
}
