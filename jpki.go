package main

import (
	"os"
	"fmt"
	"errors"
	"strings"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/asn1"
	"encoding/pem"
	"encoding/json"
	"github.com/urfave/cli"
	"github.com/howeyc/gopass"
	"github.com/ebfe/go.pcsclite/scard"
	"github.com/ianmcmahon/encoding_ssh"
	//reflect"
    //"github.com/vaughan0/go-ini"
)

func showAuthCert(c *cli.Context) error {
	pin := []byte(c.String("pin"))
	if len(pin) == 0 {
		fmt.Printf("認証用暗証番号(4桁数字): ")
		pin, _ = gopass.GetPasswd()
	}
	if len(pin) != 4 {
		fmt.Printf("エラー: 認証用暗証番号(4桁数字)を入力してください。\n")
		return nil
	}
	reader := NewReader()
	if reader == nil {
		os.Exit(1)
	}
	defer reader.Finalize()
	card := reader.WaitForCard()
	status, _ := card.Status()
	fmt.Printf("Card Status: %s\n", status)
	aid := "D3 92 f0 00 26 01 00 00 00 01"
	apdu := "00 A4 04 0C" + " 0A " + aid
	tx(card, apdu)
	tx(card, "00 a4 02 0C 02 00 18") // PIN for AUTH
	tx(card, "00 20 00 80")
	apdu = "00 20 00 80 " + fmt.Sprintf("%02X % X", len(pin), pin)
	tx(card, apdu)
	//tx(card, "00 A4 02 0C 02 00 0B") // AUTH CA
	tx(card, "00 A4 02 0C 02 00 0A") // AUTH CERT

	data := readBinary(card, 4)
	if len(data) != 4 {
		fmt.Printf("エラー: Unkown\n")
		return errors.New("error")
	}
	data_size := uint16(data[2]) << 8 | uint16(data[3])
	data = readBinary(card, 4 + data_size)

	/*
	fp, _ := os.Create("cert.der")
	defer fp.Close()
	fp.Write(data)
    */

	form := c.String("form")
	if form == "ssh" {
		cert, _ := x509.ParseCertificate(data)
		rsaPubkey := cert.PublicKey.(*rsa.PublicKey)
		sshPubkey, _ := ssh.EncodePublicKey(*rsaPubkey, "")
		fmt.Println(sshPubkey)
	}else{
		var block pem.Block
		block.Type = "CERTIFICATE"
		block.Bytes = data
		pem.Encode(os.Stdout, &block)
	}

	return nil
}

func showSignCert(c *cli.Context) error {
	return nil
}

func ToHexString(b []byte) string {
	s := hex.EncodeToString(b)
	return s
}

func ToBytes(s string) []byte {
	b, _ := hex.DecodeString(strings.Replace(s, " ", "", -1))
	return b
}

func showMynumber(c *cli.Context) error {
	pin := []byte(c.String("pin"))
	if len(pin) == 0 {
		fmt.Printf("暗証番号(4桁): ")
		pin, _ = gopass.GetPasswd()
	}
	if len(pin) != 4 {
		fmt.Printf("エラー: 暗証番号(4桁)を入力してください。\n")
		return nil
	}
	reader := NewReader()
	if reader == nil {
		os.Exit(1)
	}
	defer reader.Finalize()
	card := reader.WaitForCard()
	if card == nil {
		os.Exit(1)
	}

	status, _ := card.Status()
	fmt.Printf("Card Status: %s\n", status)
	aid := "D3 92 10 00 31 00 01 01 04 08"
	apdu := "00 A4 04 0C" + " 0A " + aid
	tx(card, apdu)
	tx(card, "00 a4 02 0C 02 00 11") // EF for VERIFY
	tx(card, "00 20 00 80")
	apdu = "00 20 00 80 " + fmt.Sprintf("%02X % X", len(pin), pin)
	tx(card, apdu)
	tx(card, "00 A4 02 0C 02 00 01")
	data := readBinary(card, 16)
	var mynum asn1.RawValue
	asn1.Unmarshal(data, &mynum)

	tx(card, "00 A4 02 0C 02 00 02")
	data = readBinary(card, 5)
	if len(data) != 5 {
		fmt.Printf("エラー: Unkown\n")
		return errors.New("error")
	}
	data_size := uint16(data[3]) << 8 | uint16(data[4])
	data = readBinary(card, 5 + data_size)
	var attr[5] asn1.RawValue
	pos := 5
	for i := 0; i < 5; i++ {
		asn1.Unmarshal(data[pos:], &attr[i])
		pos += len(attr[i].FullBytes)
	}
	if c.String("form") == "json" {
		j, _ := json.MarshalIndent(map[string]string{
			"mynumber": string(mynum.Bytes),
			"header": fmt.Sprintf("% X", attr[0].Bytes),
			"name": string(attr[1].Bytes),
			"addr": string(attr[2].Bytes),
			"birthday": string(attr[3].Bytes),
			"sex": string(attr[4].Bytes),
		}, "", "  ")
		fmt.Printf("%s", j)
	}else{
		fmt.Printf("個人番号: %s\n", mynum.Bytes)
		fmt.Printf("謎ヘッダ: % X\n", attr[0].Bytes)
		fmt.Printf("氏名:     %s\n", attr[1].Bytes)
		fmt.Printf("住所:     %s\n", attr[2].Bytes)
		fmt.Printf("生年月日: %s\n", attr[3].Bytes)
		fmt.Printf("性別:     %s\n", attr[4].Bytes)
	}
	return nil
}

func readBinary(card *scard.Card, size uint16) []byte {
	var l uint8
	var apdu string
	var pos uint16
	pos = 0
	var res []byte

	for pos < size {
		if size - pos > 0xFF {
			l = 0xFF
		}else{
			l = uint8(size - pos)
		}
		apdu = fmt.Sprintf("00 B0 %02X %02X %02X",
			pos >> 8 & 0xFF, pos & 0xFF, l)
		sw1, sw2, data := tx(card, apdu)
		if sw1 != 0x90 || sw2 != 0x00 {
			return nil
		}
		res = append(res, data...)
		pos += uint16(len(data))
	}
	return res
}

func tx(card *scard.Card, apdu string) (uint8, uint8, []byte) {
	fmt.Printf(">> %v\n", apdu)
	cmd := ToBytes(apdu)
	res, err := card.Transmit(cmd)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return 0, 0, nil
	}

	for i := 0; i < len(res); i++ {
		if i % 0x10 == 0 {
			fmt.Print("<<")
		}
		fmt.Printf(" %02X", res[i])
		if i % 0x10 == 0x0f {
			fmt.Println()
		}
	}
	fmt.Println()

	l := len(res)
	if l == 2 {
		return res[0], res[1], nil
	}else if l > 2 {
		return res[l-2], res[l-1], res[:l-2]
	}
	return 0, 0, nil
}

func main() {
	app := cli.NewApp()
	app.Name = "jpki"
	app.Usage = "JPKI Util"
	app.Version = Version
	app.Author = "HAMANO Tsukasa"
	app.Email = "hamano@osstech.co.jp"
	app.Commands = []cli.Command {
		{
			Name: "auth_cert",
			Usage: "利用者証明用電子証明を表示",
			Action: showAuthCert,
			Flags: []cli.Flag {
				cli.StringFlag {
					Name: "pin",
					Usage: "暗証番号(4桁)",
				},
				cli.StringFlag {
					Name: "form",
					Usage: "出力形式(pem,ssh)",
				},
			},
		},
		{
			Name: "sign_cert",
			Usage: "署名用電子証明書を表示",
			Action: showSignCert,
		},
		{
			Name: "mynumber",
			Usage: "券面事項入力補助AP",
			Action: showMynumber,
			Flags: []cli.Flag {
				cli.StringFlag {
					Name: "pin",
					Usage: "暗証番号(4桁)",
				},
				cli.StringFlag {
					Name: "form",
					Usage: "出力形式(txt,json)",
				},
			},
		},
	}
	app.Run(os.Args)
}
