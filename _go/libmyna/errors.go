package libmyna

import (
	"fmt"
)

type APDUError struct {
	sw1 uint8
	sw2 uint8
}

func NewAPDUError(sw1 uint8, sw2 uint8) error {
	return &APDUError{sw1, sw2}
}

func (self *APDUError) Error() string {
	return fmt.Sprintf("APDU Error SW1=%02X SW2=%02X", self.sw1, self.sw2)
}
