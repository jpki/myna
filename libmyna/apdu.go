package libmyna

import (
	"fmt"
)

type APDU struct {
	cmd []byte
}

func NewAPDU(s string) (*APDU, error) {
	cmd := ToBytes(s)
	if len(cmd) < 4 {
		return nil, fmt.Errorf("invalid apdu %s", s)
	}
	apdu := APDU{cmd}
	return &apdu, nil
}

func NewAPDUCase1(cla byte, ins byte, p1 byte, p2 byte) *APDU {
	apdu := APDU{[]byte{cla, ins, p1, p2}}
	return &apdu
}

func NewAPDUCase2(cla byte, ins byte, p1 byte, p2 byte, le byte) *APDU {
	apdu := APDU{[]byte{cla, ins, p1, p2, le}}
	return &apdu
}

func NewAPDUCase3(cla byte, ins byte, p1 byte, p2 byte, data []byte) *APDU {
	cmd := append([]byte{cla, ins, p1, p2, byte(len(data))}, data...)
	apdu := APDU{cmd}
	return &apdu
}

func NewAPDUCase4(cla byte, ins byte, p1 byte, p2 byte, data []byte, le byte) *APDU {
	cmd := append([]byte{cla, ins, p1, p2, byte(len(data))}, data...)
	cmd = append(cmd, le)
	apdu := APDU{cmd}
	return &apdu
}

func (self *APDU) ToString() string {
	return fmt.Sprintf("% X", self.cmd)
}
