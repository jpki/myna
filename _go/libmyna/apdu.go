package libmyna

import (
	"fmt"
)

type APDU struct {
	cmd []uint8
}

func NewAPDU(s string) (*APDU, error) {
	cmd := ToBytes(s)
	if len(cmd) < 4 {
		return nil, fmt.Errorf("invalid apdu %s", s)
	}
	apdu := APDU{cmd}
	return &apdu, nil
}

func NewAPDUCase1(cla uint8, ins uint8, p1 uint8, p2 uint8) *APDU {
	apdu := APDU{[]uint8{cla, ins, p1, p2}}
	return &apdu
}

func NewAPDUCase2(cla uint8, ins uint8, p1 uint8, p2 uint8, le uint8) *APDU {
	apdu := APDU{[]uint8{cla, ins, p1, p2, le}}
	return &apdu
}

func NewAPDUCase3(cla uint8, ins uint8, p1 uint8, p2 uint8, data []uint8) *APDU {
	cmd := append([]uint8{cla, ins, p1, p2, uint8(len(data))}, data...)
	apdu := APDU{cmd}
	return &apdu
}

func NewAPDUCase4(cla uint8, ins uint8, p1 uint8, p2 uint8, data []uint8, le uint8) *APDU {
	cmd := append([]uint8{cla, ins, p1, p2, uint8(len(data))}, data...)
	cmd = append(cmd, le)
	apdu := APDU{cmd}
	return &apdu
}

func (self *APDU) ToString() string {
	return fmt.Sprintf("% X", self.cmd)
}
