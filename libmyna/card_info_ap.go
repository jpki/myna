package libmyna

import (
	"errors"

	"github.com/hamano/brokenasn1"
)

type CardInfoAP struct {
	reader *Reader
}

type CardFront struct {
	Header []byte `asn1:"private,tag:33"`
	Birth  string `asn1:"private,tag:34"`
	Age    string `asn1:"private,tag:35"`
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

func (self *CardInfoAP) GetCardFront(pin string) (*CardFront, error) {
	err := self.reader.SelectEF("00 02")
	if err != nil {
		return nil, err
	}
	data := self.reader.ReadBinary(7)
	if len(data) != 7 {
		return nil, errors.New("Error at ReadBinary()")
	}

	parser := ASN1PartialParser{}
	err = parser.Parse(data)
	if err != nil {
		return nil, err
	}
	data = self.reader.ReadBinary(parser.GetSize())

	var front CardFront
	_, err = asn1.UnmarshalWithParams(data, &front, "private,tag:32")
	if err != nil {
		return nil, err
	}
	return &front, nil
}
