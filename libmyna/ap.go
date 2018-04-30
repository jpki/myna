// AP Specific API

package libmyna

import (
	"bytes"
	"crypto/x509"
	"errors"
)

type JPKIAP struct {
	reader *Reader
}

func (self *JPKIAP) GetToken() (string, error) {
	err := self.reader.SelectEF("00 06") // トークン情報EF
	if err != nil {
		return "", err
	}

	data := self.reader.ReadBinary(0x20)
	token := string(bytes.TrimRight(data, " "))
	return token, nil
}

func (self *JPKIAP) LookupAuthPin() (int, error) {
	err := self.reader.SelectEF("00 18") // JPKI認証用PIN
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *JPKIAP) VerifyAuthPin(pin string) error {
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

func (self *JPKIAP) LookupSignPin() (int, error) {
	err := self.reader.SelectEF("00 1B") // JPKI署名用PIN
	if err != nil {
		return 0, err
	}
	count := self.reader.LookupPin()
	return count, nil
}

func (self *JPKIAP) VerifySignPin(pin string) error {
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

func (self *JPKIAP) ReadCertificate(efid string) (*x509.Certificate, error) {
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
