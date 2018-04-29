// AP Specific API

package libmyna

import (
	"bytes"
	"crypto/x509"
	"errors"
)

type CARD_INFO_AP struct {
	reader *Reader
}

type CARD_INPUT_HELPER_AP struct {
	reader *Reader
}

type JPKI_AP struct {
	reader *Reader
}

func (self *CARD_INFO_AP) LookupPinA() (int, error) {
	err := self.reader.SelectEF("00 12")
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *CARD_INFO_AP) LookupPinB() (int, error) {
	err := self.reader.SelectEF("00 13")
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *CARD_INPUT_HELPER_AP) LookupPin() (int, error) {
	err := self.reader.SelectEF("00 11") // 券面事項入力補助用PIN
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *CARD_INPUT_HELPER_AP) LookupPinA() (int, error) {
	err := self.reader.SelectEF("00 14")
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *CARD_INPUT_HELPER_AP) LookupPinB() (int, error) {
	err := self.reader.SelectEF("00 15")
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *JPKI_AP) GetToken() (string, error) {
	err := self.reader.SelectEF("00 06") // トークン情報EF
	if err != nil {
		return "", err
	}

	data := self.reader.ReadBinary(0x20)
	token := string(bytes.TrimRight(data, " "))
	return token, nil
}

func (self *JPKI_AP) LookupAuthPin() (int, error) {
	err := self.reader.SelectEF("00 18") // JPKI認証用PIN
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *JPKI_AP) VerifyAuthPin(pin string) error {
	err := self.reader.SelectEF("00 18") // JPKI認証用PIN
	if err != nil {
		return err
	}
	err = self.reader.Verify(pin)
	if err != nil {
		return err
	}
	return nil
}

func (self *JPKI_AP) LookupSignPin() (int, error) {
	err := self.reader.SelectEF("00 1B") // JPKI署名用PIN
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *JPKI_AP) VerifySignPin(pin string) error {
	err := self.reader.SelectEF("00 1B") // JPKI署名用PIN
	if err != nil {
		return err
	}
	err = self.reader.Verify(pin)
	if err != nil {
		return err
	}
	return nil
}

func (self *JPKI_AP) ReadCertificate(efid string) (*x509.Certificate, error) {
	err := self.reader.SelectEF(efid)
	data := self.reader.ReadBinary(7)
	if len(data) != 7 {
		return nil, errors.New("ReadBinary: invalid length")
	}

	parser := ASN1PartialParser{}
	err = parser.Parse(data)
	if err != nil {
		return nil, err
	}
	data = self.reader.ReadBinary(parser.GetSize())
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
