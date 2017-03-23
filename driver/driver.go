package driver

import (
	"fmt"
	"errors"
	"strings"
	"github.com/urfave/cli"
	"encoding/hex"
	"encoding/asn1"
)

type CardInfo struct {
	Number string
	Header string
	Name string
	Address string
	Birth string
	Sex string
}

func ToBytes(s string) []byte {
	b, _ := hex.DecodeString(strings.Replace(s, " ", "", -1))
	return b
}

func ToHexString(b []byte) string {
	s := hex.EncodeToString(b)
	return s
}

func Check(c *cli.Context) error {
	reader := NewReader(c)
	if reader == nil {
		return errors.New("リーダーが見つかりません。")
	}
	defer reader.Finalize()
	_, err := reader.CheckCard()
	return err
}

func GetCardInfo(c *cli.Context, pin []byte) (*CardInfo, error) {
	reader := NewReader(c)
	if reader == nil {
		return nil, errors.New("リーダーが見つかりません。")
	}
	defer reader.Finalize()
	card := reader.WaitForCard()
	if card == nil {
		return nil, errors.New("カードが見つかりません。")
	}

	reader.SelectAP("D3 92 10 00 31 00 01 01 04 08")
	reader.SelectEF("00 11") // EF for VERIFY
	reader.Verify(pin)
	reader.SelectEF("00 01")
	data := reader.ReadBinary(16)
	var number asn1.RawValue
	asn1.Unmarshal(data[1:], &number)

	reader.SelectEF("00 02")
	data = reader.ReadBinary(5)
	if len(data) != 5 {
		return nil, errors.New("Error at ReadBinary()")
	}
	data_size := uint16(data[3]) << 8 | uint16(data[4])
	data = reader.ReadBinary(5 + data_size)
	var attr[5] asn1.RawValue
	pos := 5
	for i := 0; i < 5; i++ {
		asn1.Unmarshal(data[pos:], &attr[i])
		pos += len(attr[i].FullBytes)
	}

	info := new(CardInfo)
	info.Number = string(number.Bytes)
	info.Header = fmt.Sprintf("% X", attr[0].Bytes)
	info.Name = string(attr[1].Bytes)
	info.Address = string(attr[2].Bytes)
	info.Birth = string(attr[3].Bytes)
	info.Sex = string(attr[4].Bytes)
	return info, nil
}

