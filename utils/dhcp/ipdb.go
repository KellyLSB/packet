package main

import (
	"fmt"
	"net"
	"os"
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
	case ip.Equal(net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
		ip.Equal(net.IP{0, 0, 0, 0}),
		ip.Equal(net.IP{}):
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
	for i.ContainsIP(ip) {
		ip = NextIP(ip)
	}

	return ip
}

func NextIP(ip net.IP, masks ...net.IPMask) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)
	var typ = 16

	if newIP.To4() != nil {
		newIP = newIP.To4()
		typ = 4
	}

	for i := typ - 1; i > 0; i-- {
		if newIP[i] < 255 {
			newIP[i] = newIP[i] + 1
			for n := i + 1; n < typ; n++ {
				if newIP[n] < 255 {
					newIP[n] = newIP[n] + 1
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

	netInterface := "lo"
	if netIfi := os.Getenv("NETIFI"); netIfi != "" {
		netInterface = netIfi
	}

	netIface, err := net.InterfaceByName(netInterface)
	if err != nil {
		panic(err)
	}

	return &IPDB{
		IPNet:  *ipnet,
		LastIP: ip,
		Leases: []*Lease{
			{ip, netIface.HardwareAddr, hostname},
		},
	}
}
