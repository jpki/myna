// JPKIAP Operation API

package libmyna

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/jpki/myna/asn1"
)

type JPKIAP struct {
	reader *Reader
}

func (self *JPKIAP) ReadToken() (string, error) {
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

func (self *JPKIAP) ReadSignCert() (*x509.Certificate, error) {
	return self.ReadCertificate("00 01")
}

func (self *JPKIAP) ReadSignCACert() (*x509.Certificate, error) {
	return self.ReadCertificate("00 02")
}

func (self *JPKIAP) ReadAuthCert() (*x509.Certificate, error) {
	return self.ReadCertificate("00 0A")
}

func (self *JPKIAP) ReadAuthCACert() (*x509.Certificate, error) {
	return self.ReadCertificate("00 0B")
}

type JPKICertificate struct {
	*x509.Certificate
}

var oidExtensionSubjectAltName = []int{2, 5, 29, 17}
var oidJPKICertificateName = []int{1, 2, 392, 200149, 8, 5, 5, 1}
var oidJPKICertificateNameAlt = []int{1, 2, 392, 200149, 8, 5, 5, 2}
var oidJPKICertificateSex = []int{1, 2, 392, 200149, 8, 5, 5, 3}
var oidJPKICertificateBirth = []int{1, 2, 392, 200149, 8, 5, 5, 4}
var oidJPKICertificateAddr = []int{1, 2, 392, 200149, 8, 5, 5, 5}
var oidJPKICertificateAddrAlt = []int{1, 2, 392, 200149, 8, 5, 5, 6}

func (self *JPKICertificate) GetSubjectAltNames() *pkix.Extension {
	for _, ext := range self.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			return &ext
		}
	}
	return nil
}

type JPKICertificateAttr struct {
	Oid    asn1.ObjectIdentifier
	Values JPKICertificateAttrValues `asn1:"tag:0"`
}

type JPKICertificateAttrValues struct {
	Value string
}

type JPKICertificateAttrs struct {
	Name    string
	NameAlt string
	Sex     string
	Birth   string
	Addr    string
	AddrAlt string
}

func (self *JPKICertificate) GetAttributes() (*JPKICertificateAttrs, error) {
	attrs := JPKICertificateAttrs{}
	san := self.GetSubjectAltNames()
	if san == nil {
		return nil, nil
	}
	var seq asn1.RawValue
	_, err := asn1.Unmarshal(san.Value, &seq)
	if err != nil {
		return nil, err
	}

	rest := seq.Bytes
	for len(rest) > 0 {
		var v JPKICertificateAttr
		rest, err = asn1.UnmarshalWithParams(rest, &v, "tag:0")
		if err != nil {
			return nil, err
		}
		if v.Oid == nil {
			return nil, nil
		}
		if v.Oid.Equal(oidJPKICertificateName) {
			attrs.Name = v.Values.Value
		} else if v.Oid.Equal(oidJPKICertificateNameAlt) {
			attrs.NameAlt = v.Values.Value
		} else if v.Oid.Equal(oidJPKICertificateSex) {
			attrs.Sex = v.Values.Value
		} else if v.Oid.Equal(oidJPKICertificateBirth) {
			attrs.Birth = v.Values.Value
		} else if v.Oid.Equal(oidJPKICertificateAddr) {
			attrs.Addr = v.Values.Value
		} else if v.Oid.Equal(oidJPKICertificateAddrAlt) {
			attrs.AddrAlt = v.Values.Value
		}
	}
	return &attrs, nil
}

func (self *JPKICertificate) ToString() string {
	var ret string
	ret += fmt.Sprintf("SerialNumber: %s\n", self.SerialNumber)
	ret += fmt.Sprintf("Subject: %s\n", Name2String(self.Subject))
	ret += fmt.Sprintf("Issuer: %s\n", Name2String(self.Issuer))
	ret += fmt.Sprintf("NotBefore: %s\n", self.NotBefore)
	ret += fmt.Sprintf("NotAfter: %s\n", self.NotAfter)
	ret += fmt.Sprintf("KeyUsage: %v\n", self.KeyUsage)
	attrs, _ := self.GetAttributes()
	if attrs != nil {
		ret += fmt.Sprintf("Name: %s\n", attrs.Name)
		ret += fmt.Sprintf("Sex: %s\n", attrs.Sex)
		ret += fmt.Sprintf("Birth: %s\n", attrs.Birth)
		ret += fmt.Sprintf("Addr: %s\n", attrs.Addr)
	}
	return ret
}
