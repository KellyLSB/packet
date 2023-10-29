package main

import (
	"fmt"
	"net"
)

type Lease struct {
	net.IP
	net.HardwareAddr
	Hostname string
}

type IPDB struct {
	net.IPNet
	LastIP net.IP
	Leases []*Lease
}

func (i *IPDB) AddHost(
	ip net.IP,
	hardware net.HardwareAddr,
	hostname string,
) {
	nextIP := make(net.IP, len(i.LastIP))

	switch {
	case ip.Equal(net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), ip.Equal(net.IP{0, 0, 0, 0}), ip.Equal(net.IP{}):
		nextIP = NextIP(i.LastIP)
	default:
		copy(nextIP, ip)
	}

	i.Leases = append(i.Leases, &Lease{
		IP:           nextIP,
		HardwareAddr: hardware,
		Hostname:     hostname,
	})

	i.LastIP = nextIP
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

func (i *IPDB) NextIP() net.IP {
	ip := NextIP(i.LastIP)
	for !i.ContainsIP(ip) {
		ip = NextIP(ip)
	}

	return ip
}

func NextIP(ip net.IP) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)
	var typ = 6

	if newIP.To4() != nil {
		newIP = newIP.To4()
		typ = 4
	}

	switch typ {
	case 4:
		for i := 3; i > 0; i-- {
			if newIP[i] < 255 {
				newIP[i] = newIP[i] + 1
				break
			}
		}
	case 16:
		for i := 15; i > 0; i-- {
			if newIP[i] < 255 {
				newIP[i] = newIP[i] + 1
				break
			}
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
	var hostname string
	var network string
	switch len(input) {
	case 1:
		network = input[0]
	case 2:
		network = input[0]
		hostname = input[1]
	}

	ip, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		panic(err)
	}

	return &IPDB{
		IPNet:  *ipnet,
		LastIP: ip,
		Leases: []*Lease{
			&Lease{ip, net.HardwareAddr{}, hostname},
		},
	}
}
