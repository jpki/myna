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
	//"github.com/ebfe/go.pcsclite/scard"
	"github.com/ianmcmahon/encoding_ssh"
	//reflect"
    //"github.com/vaughan0/go-ini"
)

var commonFlags = []cli.Flag {
	cli.BoolFlag {
		Name: "verbose, v",
		Usage: "詳細出力",
	},
}

func checkCard(c *cli.Context) error {
	reader := NewReader(c)
	defer reader.Finalize()
	reader.CheckCard()
	return nil
}

func showCert(c *cli.Context, efid string, pin []byte) error {
	reader := NewReader(c)
	if reader == nil {
		os.Exit(1)
	}
	defer reader.Finalize()
	card := reader.WaitForCard()
	status, _ := card.Status()
	fmt.Printf("Card Status: %s\n", status)
	aid := "D3 92 f0 00 26 01 00 00 00 01"
	apdu := "00 A4 04 0C" + " 0A " + aid
	reader.Tx(apdu)

	if pin != nil {
        //tx(card, "00 a4 02 0C 02 00 18") // VERIFY EF for AUTH
		reader.Tx("00 a4 02 0C 02 00 1B") // VERIFY EF for SIGN
		reader.Tx("00 20 00 80")
		apdu = "00 20 00 80 " + fmt.Sprintf("%02X % X", len(pin), pin)
		reader.Tx(apdu)
    }

	reader.Tx("00 A4 02 0C 02 " + efid)
	data := readBinary(reader, 4)
	if len(data) != 4 {
		fmt.Printf("エラー: Unkown\n")
		return errors.New("error")
	}
	data_size := uint16(data[2]) << 8 | uint16(data[3])
	data = readBinary(reader, 4 + data_size)

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

func showAuthCert(c *cli.Context) error {
	showCert(c, "00 0A", nil)
	return nil
}

func showAuthCACert(c *cli.Context) error {
	showCert(c, "00 0B", nil)
	return nil
}

func showSignCert(c *cli.Context) error {
	pin := c.String("pin")
	if len(pin) == 0 {
		fmt.Printf("署名用パスワード(6-16桁): ")
		input, _ := gopass.GetPasswdMasked()
		pin = string(input)
	}
	pass := []byte(strings.ToUpper(pin))

	if len(pin) < 6 || 16 < len(pin) {
		fmt.Printf("エラー: 署名用パスワード(6-16桁)を入力してください。\n")
		return nil
	}
	showCert(c, "00 01", pass)
	return nil
}

func showSignCACert(c *cli.Context) error {
	showCert(c, "00 02", nil)
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
	reader := NewReader(c)
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
	reader.Tx(apdu)
	reader.Tx("00 a4 02 0C 02 00 11") // EF for VERIFY
	reader.Tx("00 20 00 80")
	apdu = "00 20 00 80 " + fmt.Sprintf("%02X % X", len(pin), pin)
	reader.Tx(apdu)
	reader.Tx("00 A4 02 0C 02 00 01")
	data := readBinary(reader, 16)
	var mynum asn1.RawValue
	asn1.Unmarshal(data, &mynum)

	reader.Tx("00 A4 02 0C 02 00 02")
	data = readBinary(reader, 5)
	if len(data) != 5 {
		fmt.Printf("エラー: Unkown\n")
		return errors.New("error")
	}
	data_size := uint16(data[3]) << 8 | uint16(data[4])
	data = readBinary(reader, 5 + data_size)
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

func readBinary(reader *Reader, size uint16) []byte {
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
		sw1, sw2, data := reader.Tx(apdu)
		if sw1 != 0x90 || sw2 != 0x00 {
			return nil
		}
		res = append(res, data...)
		pos += uint16(len(data))
	}
	return res
}

func main() {
	cli.VersionFlag = cli.BoolFlag{
		Name: "version, V",
		Usage: "print version",
	}
	app := cli.NewApp()
	app.Name = "jinc"
	app.Usage = "個人番号カードユーティリティ"
	app.Author = "HAMANO Tsukasa"
	app.Email = "hamano@osstech.co.jp"
	app.Version = Version
	app.Commands = []cli.Command {
		{
			Name: "sign_cert",
			Usage: "署名用証明書を表示",
			Action: showSignCert,
			Flags: append(commonFlags, []cli.Flag {
				cli.StringFlag {
					Name: "pin",
					Usage: "署名用パスワード(6-16桁)",
				},
				cli.StringFlag {
					Name: "form",
					Usage: "出力形式(pem,ssh)",
				},
			}...),
		},
		{
			Name: "sign_ca_cert",
			Usage: "署名用CA証明書を表示",
			Action: showSignCACert,
		},
		{
			Name: "auth_cert",
			Usage: "利用者認証用証明書を表示",
			Action: showAuthCert,
			Flags: []cli.Flag {
				cli.StringFlag {
					Name: "form",
					Usage: "出力形式(pem,ssh)",
				},
			},
		},
		{
			Name: "auth_ca_cert",
			Usage: "利用者認証用CA証明書を表示",
			Action: showAuthCACert,
		},
		{
			Name: "mynumber",
			Usage: "券面事項入力補助AP",
			Action: showMynumber,
			Before: checkCard,
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
		{
			Name: "tool",
			Usage: "種々様々なツール",
			Subcommands: toolCommands,
		},
	}
	app.Run(os.Args)
}
