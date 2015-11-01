// TFTP GoPacket ApplicationLayer
// by Kelly Lauren-Summer Becker-Neuding <kbecker@kellybecker.me>, 2015
// MIT License

package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TFTPOpCode defines the TFTP packet operation.
type TFTPOpCode uint16

const (
	_ TFTPOpCode = iota
	// TFTPOpRead performs a read operation.
	TFTPOpRead
	// TFTPOpWrite performs a write operation.
	TFTPOpWrite
	// TFTPOpData performs a data operation.
	TFTPOpData
	// TFTPOpAck acknowledges a statement.
	TFTPOpAck
	// TFTPOpError performs an error operation.
	TFTPOpError
)

// TFTPErrorCode defines the TFTP error codes.
// These messages are meant to be user customized.
type TFTPErrorCode uint16

const (
	_ TFTPErrorCode = iota
)

// LayerTypeTFTP defines a GoPacket application layer.
var LayerTypeTFTP = gopacket.RegisterLayerType(1000, gopacket.LayerTypeMetadata{
	Name: "TFTP", Decoder: gopacket.DecodeFunc(decodeTFTP),
})

// TFTP defines a TFTP packet layer.
type TFTP struct {
	layers.BaseLayer
	TFTPOpCode

	Filename, Mode string
	Block          uint16
	Data           []byte
	Last           bool

	TFTPErrorCode
	ErrorMessage string
}

// LayerType returns LayerTypeTFTP.
func (t *TFTP) LayerType() gopacket.LayerType {
	return LayerTypeTFTP
}

// DecodeFromBytes decodes packet data and populates the TFTP structure.
func (t *TFTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) > 516 {
		return fmt.Errorf("TFTP packet longer than 516 (total) bytes")
	}

	t.BaseLayer = layers.BaseLayer{Contents: data[:len(data)]}
	t.TFTPOpCode = TFTPOpCode(binary.BigEndian.Uint16(data[:2]))

	switch t.TFTPOpCode {
	case TFTPOpRead, TFTPOpWrite:
		filemode := bytes.Split(data[2:], []byte{0x0})
		t.Filename = string(filemode[0])
		t.Mode = string(filemode[1])
	case TFTPOpData:
		if len(data[4:]) < 512 {
			t.Last = true
		}

		t.Block = binary.BigEndian.Uint16(data[2:4])
		t.Data = data[4:]
	case TFTPOpAck:
		t.Block = binary.BigEndian.Uint16(data[2:4])
	case TFTPOpError:
		t.TFTPErrorCode = TFTPErrorCode(binary.BigEndian.Uint16(data[2:4]))
		t.ErrorMessage = string(data[4:])
	default:
		panic(fmt.Sprintf("Unknown TFTPOpCode (%d)", t.TFTPOpCode))
	}

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (t *TFTP) SerializeTo(
	b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions,
) error {
	bytes, err := b.PrependBytes(t.getLayerLength())
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint16(bytes, uint16(t.TFTPOpCode))

	switch t.TFTPOpCode {
	case TFTPOpRead, TFTPOpWrite:
		modeLoc := 3 + len(t.Filename)
		copy(bytes[2:modeLoc-1], t.Filename)
		copy(bytes[modeLoc:modeLoc+len(t.Mode)], t.Mode)
	case TFTPOpData:
		binary.BigEndian.PutUint16(bytes[2:], uint16(t.Block))
		copy(bytes[4:4+len(t.Data)], t.Data)
	case TFTPOpAck:
		binary.BigEndian.PutUint16(bytes[2:], uint16(t.Block))
	case TFTPOpError:
		binary.BigEndian.PutUint16(bytes[2:], uint16(t.TFTPErrorCode))
		copy(bytes[4:4+len(t.ErrorMessage)], t.ErrorMessage)
	default:
		// Not Needed getLayerLength() errors for us
	}

	return nil
}

// CanDecode returns what LayerType TFTP can decode.
func (t *TFTP) CanDecode() gopacket.LayerClass {
	return LayerTypeTFTP
}

// NextLayerType returns gopacket.LayerTypePayload.
func (t *TFTP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Payload returns the remaining Payload (should be nil)
func (t *TFTP) Payload() []byte {
	return nil
}

func (t *TFTP) getLayerLength() int {
	switch t.TFTPOpCode {
	case TFTPOpRead, TFTPOpWrite:
		return 4 + len([]byte(t.Filename)) + len([]byte(t.Mode))
	case TFTPOpData:
		return 4 + len(t.Data)
	case TFTPOpAck:
		return 4
	case TFTPOpError:
		return 4 + len([]byte(t.ErrorMessage))
	default:
		panic(fmt.Sprintf("Unknown TFTPOpCode (%d)", t.TFTPOpCode))
	}
}

func decodeTFTP(data []byte, p gopacket.PacketBuilder) error {
	t := new(TFTP)

	if err := t.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(t)
	p.SetApplicationLayer(t)
	return nil
}
