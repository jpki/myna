package driver

import (
	"fmt"
	"bytes"
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

func CheckCard(c *cli.Context) error {
	reader := NewReader(c)
	if reader == nil {
		return errors.New("リーダーが見つかりません。")
	}
	defer reader.Finalize()
	var sw1, sw2 uint8
	reader.WaitForCard()
	if ! reader.SelectAP("D3 92 f0 00 26 01 00 00 00 01") {
		return errors.New("これは個人番号カードではありません。")
	}

	sw1, sw2 = reader.SelectEF("00 06")
	if ! (sw1 == 0x90 && sw2 == 0x00) {
		return errors.New("トークン情報を取得できません。")
	}

	var data []byte
	data = reader.ReadBinary(0x20)
	token := string(bytes.TrimRight(data, " "))
	if token == "JPKIAPICCTOKEN2" {
		return nil
	} else if token == "JPKIAPICCTOKEN" {
		return errors.New("これは住基カードですね?")
	} else {
		return fmt.Errorf("不明なトークン情報: %s", token)
	}
}

func GetCardInfo(c *cli.Context, pin string) (map[string]string, error) {
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
	reader.SelectEF("00 11") // 券面入力補助PIN IEF
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

	info := map[string]string{}
	info["number"] = string(number.Bytes)
	info["header"] = fmt.Sprintf("% X", attr[0].Bytes)
	info["name"] = string(attr[1].Bytes)
	info["address"] = string(attr[2].Bytes)
	info["birth"] = string(attr[3].Bytes)
	info["sex"] = string(attr[4].Bytes)
	return info, nil
}
