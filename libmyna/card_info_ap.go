package libmyna

import ()

type CardInfoAP struct {
	reader *Reader
}

func (self *CardInfoAP) LookupPinA() (int, error) {
	err := self.reader.SelectEF("00 13")
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *CardInfoAP) VerifyPinA(pin string) error {
	err := self.reader.SelectEF("00 13")
	if err != nil {
		return err
	}
	err = self.reader.Verify(pin)
	return err
}

func (self *CardInfoAP) LookupPinB() (int, error) {
	err := self.reader.SelectEF("00 12")
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *CardInfoAP) VerifyPinB(pin string) error {
	err := self.reader.SelectEF("00 12")
	if err != nil {
		return err
	}
	err = self.reader.Verify(pin)
	return err
}

func (self *CardInfoAP) Test() error {
	return nil
}
