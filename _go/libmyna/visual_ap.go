package libmyna

import (
	"errors"

	"github.com/jpki/myna/asn1"
)

type VisualAP struct {
	reader *Reader
}

type VisualInfo struct {
	Header    []byte `asn1:"private,tag:33"`
	Birth     string `asn1:"private,tag:34"`
	Sex       string `asn1:"private,tag:35"`
	PublicKey []byte `asn1:"private,tag:36"`
	Name      []byte `asn1:"private,tag:37"`
	Addr      []byte `asn1:"private,tag:38"`
	Photo     []byte `asn1:"private,tag:39"`
	Signature []byte `asn1:"private,tag:40"`
	Expire    string `asn1:"private,tag:41"`
	Code      []byte `asn1:"private,tag:42"`
}

func (self *VisualAP) LookupPinA() (int, error) {
	err := self.reader.SelectEF("0013")
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *VisualAP) VerifyPinA(pin string) error {
	err := self.reader.SelectEF("0013")
	if err != nil {
		return err
	}
	err = self.reader.Verify(pin)
	return err
}

func (self *VisualAP) LookupPinB() (int, error) {
	err := self.reader.SelectEF("0012")
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *VisualAP) VerifyPinB(pin string) error {
	err := self.reader.SelectEF("0012")
	if err != nil {
		return err
	}
	err = self.reader.Verify(pin)
	return err
}

func (self *VisualAP) GetVisualInfo() (*VisualInfo, error) {
	err := self.reader.SelectEF("0002")
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

	var front VisualInfo
	_, err = asn1.UnmarshalWithParams(data, &front, "private,tag:32")
	if err != nil {
		return nil, err
	}
	return &front, nil
}
