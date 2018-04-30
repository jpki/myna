package libmyna

import (
	"encoding/hex"
	"errors"
	"strings"
)

func ToBytes(s string) []byte {
	b, _ := hex.DecodeString(strings.Replace(s, " ", "", -1))
	return b
}

func ToHexString(b []byte) string {
	s := hex.EncodeToString(b)
	return s
}

type ASN1PartialParser struct {
	offset uint16
	length uint16
}

func (self *ASN1PartialParser) GetOffset() uint16 {
	return self.offset
}

func (self *ASN1PartialParser) GetSize() uint16 {
	return self.offset + self.length
}

func (self *ASN1PartialParser) parseTag(data []byte) error {
	var tagsize uint16 = 1
	if len(data) < 2 {
		return errors.New("few data size")
	}
	if data[0]&0x1f == 0x1f {
		tagsize++
		if len(data) < 2 || data[1]&0x80 != 0 {
			return errors.New("unexpected tag size")
		}
	}
	self.offset = tagsize
	return nil
}

func (self *ASN1PartialParser) parseLength(data []byte) error {
	if int(self.offset) >= len(data) {
		return errors.New("few data size")
	}
	b := data[self.offset]
	self.offset++
	if b&0x80 == 0 {
		self.length = uint16(b)
	} else {
		lol := int(b & 0x7f)
		for i := 0; i < lol; i++ {
			if int(self.offset) >= len(data) {
				return errors.New("truncated tag or length")
			}
			b = data[self.offset]
			self.offset++
			self.length <<= 8
			self.length |= uint16(int(b))
		}
	}
	return nil
}

func (self *ASN1PartialParser) Parse(data []byte) error {
	err := self.parseTag(data)
	if err != nil {
		return err
	}
	err = self.parseLength(data)
	if err != nil {
		return err
	}
	return err
}
