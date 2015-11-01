// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the GOPACKET.LICENSE file in the root of the source
// tree.
//
// Modified from http://github.com/google/gopacket/tree/master/layers/udp.go
// by Kelly Lauren-Summer Becker-Neuding <kbecker@kellybecker.me>, 2015

package packet

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerTypeUDP is a extensible UDP packet LayerType
var LayerTypeUDP = gopacket.RegisterLayerType(1045, gopacket.LayerTypeMetadata{
	Name: "UDP", Decoder: gopacket.DecodeFunc(decodeUDP),
})

// Replace the UDP Packet handler with out new custom one.
func init() {
	layers.IPProtocolMetadata[layers.IPProtocolUDP] = layers.EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeUDP),
		Name:       "UDP", LayerType: LayerTypeUDP,
	}
}

// UDP is the layer for UDP headers.
type UDP struct {
	layers.BaseLayer
	SrcPort, DstPort UDPPort
	Length           uint16
	Checksum         uint16
	sPort, dPort     []byte
}

// LayerType returns LayerTypeUDP
func (u *UDP) LayerType() gopacket.LayerType { return LayerTypeUDP }

// DecodeFromBytes decodes a UDP packet into the UDP structure.
func (u *UDP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	u.SrcPort = UDPPort(binary.BigEndian.Uint16(data[0:2]))
	u.sPort = data[0:2]
	u.DstPort = UDPPort(binary.BigEndian.Uint16(data[2:4]))
	u.dPort = data[2:4]
	u.Length = binary.BigEndian.Uint16(data[4:6])
	u.Checksum = binary.BigEndian.Uint16(data[6:8])
	u.BaseLayer = layers.BaseLayer{Contents: data[:8]}
	switch {
	case u.Length >= 8:
		hlen := int(u.Length)
		if hlen > len(data) {
			df.SetTruncated()
			hlen = len(data)
		}
		u.Payload = data[8:hlen]
	case u.Length == 0: // Jumbogram, use entire rest of data
		u.Payload = data[8:]
	default:
		return fmt.Errorf("UDP packet too small: %d bytes", u.Length)
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (u *UDP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	//var jumbo bool

	payload := b.Bytes()
	// if _, ok := u.pseudoheader.(*IPv6); ok {
	// 	if len(payload)+8 > 65535 {
	// 		jumbo = true
	// 	}
	// }
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, uint16(u.SrcPort))
	binary.BigEndian.PutUint16(bytes[2:], uint16(u.DstPort))
	if opts.FixLengths {
		// if jumbo {
		// 	u.Length = 0
		// } else {
		u.Length = uint16(len(payload)) + 8
		// }
	}
	binary.BigEndian.PutUint16(bytes[4:], u.Length)
	// if opts.ComputeChecksums {
	// 	// zero out checksum bytes
	// 	bytes[6] = 0
	// 	bytes[7] = 0
	// 	csum, err := u.computeChecksum(b.Bytes(), layers.IPProtocolUDP)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	u.Checksum = csum
	// }
	// binary.BigEndian.PutUint16(bytes[6:], u.Checksum)
	return nil
}

// CanDecode returns the LayerType that UDP can decode.
func (u *UDP) CanDecode() gopacket.LayerClass {
	return LayerTypeUDP
}

// NextLayerType use the destination port to select the
// right next decoder. It tries first to decode via the
// destination port, then the source port.
func (u *UDP) NextLayerType() gopacket.LayerType {
	if lt := u.DstPort.LayerType(); lt != gopacket.LayerTypePayload {
		return lt
	}
	return u.SrcPort.LayerType()
}

// TransportFlow creates a flow for UDP
// packets on the source and destination ports.
func (u *UDP) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(layers.EndpointUDPPort, u.sPort, u.dPort)
}

func decodeUDP(data []byte, p gopacket.PacketBuilder) error {
	u := &UDP{}
	err := u.DecodeFromBytes(data, p)
	p.AddLayer(u)
	p.SetTransportLayer(u)
	if err != nil {
		return err
	}
	return p.NextDecoder(u.NextLayerType())
}

// UDPPort is a port in a UDP layer.
type UDPPort uint16

// String returns the port as "number(name)" if there's a well-known port name,
// or just "number" if there isn't.  Well-known names are stored in
// UDPPortNames.
func (a UDPPort) String() string {
	if name, ok := layers.UDPPortNames[layers.UDPPort(a)]; ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}

// LayerType returns a LayerType that would be able to decode the
// application payload. It use some well-known port such as 53 for DNS.
//
// Returns gopacket.LayerTypePayload for unknown/unsupported port numbers.
func (a UDPPort) LayerType() gopacket.LayerType {
	if layerType := UDPPortLayerTypes[a]; layerType > 0 {
		return UDPPortLayerTypes[a]
	}
	return gopacket.LayerTypePayload
}

// UDPPortLayerTypes is a UDPPort LayerType mapping for decoding.
var UDPPortLayerTypes = map[UDPPort]gopacket.LayerType{
	53:   layers.LayerTypeDNS,
	6343: layers.LayerTypeSFlow,
}

// RegisterUDPPortLayerType registers a NextLayerType for a UDPPort.
// This can be used with UnregisterUDPPortLayerType to enable TID
// sessions for a protocol such as TFTP.
func RegisterUDPPortLayerType(port UDPPort, layer gopacket.LayerType) {
	if UDPPortLayerTypes[port] > 0 {
		panic(fmt.Sprintf("UDPPort (%d) LayerType is already set!", port))
	}

	UDPPortLayerTypes[port] = layer
}

// UnregisterUDPPortLayerType unregisters a NextLayerType for a UDPPort.
func UnregisterUDPPortLayerType(port UDPPort) {
	if UDPPortLayerTypes[port] < 0 {
		panic(fmt.Sprintf("UDPPort (%d) LayerType is not set!", port))
	}

	UDPPortLayerTypes[port] = 0
}
