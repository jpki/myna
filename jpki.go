package main

import (
	"os"
	"fmt"
	"strings"
	"encoding/hex"
	//"github.com/ebfe/go.pcsclite/scard"
	"github.com/urfave/cli"
    //"github.com/vaughan0/go-ini"
)


func ShowAuthCert(c *cli.Context) error {
	fmt.Printf("show_auth_cert\n")
	reader := NewReader()
	if reader == nil {
		os.Exit(1)
	}
	defer reader.Finalize()
	fmt.Printf("Using %s\n", reader.name)
	card := reader.GetCard()
	fmt.Printf("Card: %s\n", card)
	status, _ := card.Status()
	fmt.Printf("Status: %s\n", status)
	return nil
}

func ShowSignCert(c *cli.Context) error {
	fmt.Printf("sign_cert\n")
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

func ShowMynumber(c *cli.Context) error {
	reader := NewReader()
	if reader == nil {
		os.Exit(1)
	}
	defer reader.Finalize()
	card := reader.GetCard()
	fmt.Printf("Card: %s\n", card)
	status, _ := card.Status()
	fmt.Printf("Status: %s\n", status)
	aid := "D3 92 10 00 31 00 01 01 04 08"
	apdu := ToBytes("00 a4 04 0c" + "0A" + aid)
	fmt.Printf("APDU: %v\n", apdu)
	res, _ := card.Transmit(apdu)
	fmt.Printf("res: %v\n", ToHexString(res))
	return nil
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
			Name:    "show_auth_cert",
			Usage: "利用者証明用電子証明を表示",
			Action: ShowAuthCert,
		},
		{
			Name:    "show_sign_cert",
			Usage: "署名用電子証明書を表示",
			Action: ShowSignCert,
		},
		{
			Name: "show_mynumber",
			Usage: "券面事項入力補助AP",
			Action: ShowMynumber,
		},
	}
	app.Run(os.Args)
}
