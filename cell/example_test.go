package cell_test

import (
	"bytes"
	"fmt"
	"veil/cell"
)

func ExampleCodec() {
	codec, err := cell.NewCodec(4)
	if err != nil {
		panic(err)
	}
	payload, err := cell.EncodeCreate2(cell.HandshakeNtor, []byte("example handshake"))
	if err != nil {
		panic(err)
	}
	var wire bytes.Buffer
	if err := codec.Write(&wire, cell.Cell{CircuitID: 0x80000001, Command: cell.Create2, Payload: payload}); err != nil {
		panic(err)
	}
	decoded, err := codec.Read(&wire)
	if err != nil {
		panic(err)
	}
	typeID, handshake, err := cell.DecodeCreate2(decoded.Payload)
	if err != nil {
		panic(err)
	}
	fmt.Println(decoded.Command, typeID, string(handshake))
	// Output: CREATE2 2 example handshake
}
