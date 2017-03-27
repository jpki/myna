package main

import "github.com/jpki/myna/libmyna"

import (
	"os"
	"fmt"
	"errors"
	"strings"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"github.com/urfave/cli"
	"github.com/howeyc/gopass"
	"github.com/ianmcmahon/encoding_ssh"
)

var commonFlags = []cli.Flag {
	cli.BoolFlag {
		Name: "debug, d",
		Usage: "詳細出力",
	},
}

func main() {
	app := cli.NewApp()
	app.Name = "myna"
	app.Usage = "マイナクライアント"
	app.Author = "HAMANO Tsukasa"
	app.Email = "hamano@osstech.co.jp"
	app.Version = libmyna.Version
	app.Commands = []cli.Command {
		{
			Name: "test",
			Usage: "動作確認",
			Action: testCard,
			Flags: commonFlags,
		},
		{
			Name: "card",
			Usage: "券面事項入力補助AP",
			Action: showCardInfo,
			Before: checkCard,
			Flags: append(commonFlags, []cli.Flag {
				cli.StringFlag {
					Name: "pin",
					Usage: "暗証番号(4桁)",
				},
				cli.StringFlag {
					Name: "form",
					Usage: "出力形式(txt,json)",
				},
			}...),
		},
		{
			Name: "pin_status",
			Usage: "PINステータス",
			Action: showPinStatus,
			Before: checkCard,
			Flags: commonFlags,
		},
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
			Flags: commonFlags,
		},
		{
			Name: "auth_cert",
			Usage: "利用者認証用証明書を表示",
			Action: showAuthCert,
			Flags: append(commonFlags, []cli.Flag {
				cli.StringFlag {
					Name: "form",
					Usage: "出力形式(pem,ssh)",
				},
			}...),
		},
		{
			Name: "auth_ca_cert",
			Usage: "利用者認証用CA証明書を表示",
			Action: showAuthCACert,
			Flags: commonFlags,
		},
		{
			Name: "auth_change_pin",
			Usage: "利用者認証用PINを変更",
			Flags: append(commonFlags, []cli.Flag {
				cli.StringFlag {
					Name: "pin",
					Usage: "暗証番号(4桁)",
				},
				cli.StringFlag {
					Name: "newpin",
					Usage: "新しい暗証番号(4桁)",
				},
			}...),
			Action: changeAuthPIN,
		},
		{
			Name: "sign",
			Usage: "署名用証明書で署名",
			Action: sign,
			Flags: append(commonFlags, []cli.Flag {
				cli.StringFlag {
					Name: "pin",
					Usage: "暗証番号(4桁)",
				},
				cli.StringFlag {
					Name: "in",
					Usage: "署名対象ファイル",
				},
			}...),
		},
		{
			Name: "tool",
			Usage: "種々様々なツール",
			Subcommands: toolCommands,
		},
	}
	app.Run(os.Args)
}

func checkCard(c *cli.Context) error {
	err := libmyna.CheckCard(c)
	if err != nil {
		return err
	}
	return nil
}

func testCard(c *cli.Context) error {
	err := libmyna.CheckCard(c)
	if err != nil {
		return err
	}
	fmt.Printf("マイナンバーカードです。\n")
	return nil
}

func showCert(c *cli.Context, efid string, pin []byte) error {
	reader := libmyna.NewReader(c)
	if reader == nil {
		os.Exit(1)
	}
	defer reader.Finalize()
	err := reader.WaitForCard()
	if err != nil {
		return err
	}
	//status, _ := card.Status()
	//fmt.Printf("Card Status: %s\n", status)
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
	data := reader.ReadBinary(4)
	if len(data) != 4 {
		fmt.Printf("エラー: Unkown\n")
		return errors.New("error")
	}
	data_size := uint16(data[2]) << 8 | uint16(data[3])
	data = reader.ReadBinary(4 + data_size)

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

func changeAuthPIN(c *cli.Context) error {
	reader := libmyna.NewReader(c)
	if reader == nil {
		os.Exit(1)
	}
	defer reader.Finalize()
	reader.WaitForCard()

	pin := c.String("pin")
	if len(pin) == 0 {
		fmt.Printf("認証用PIN(4桁): ")
		input, _ := gopass.GetPasswdMasked()
		pin = string(input)
	}

	newpin := c.String("newpin")
	if len(newpin) == 0 {
		fmt.Printf("新しい認証用PIN(4桁): ")
		input, _ := gopass.GetPasswdMasked()
		newpin = string(input)
	}

	reader.SelectAP("D3 92 f0 00 26 01 00 00 00 01")
	reader.SelectEF("00 18")
	apdu := "00 20 00 80"
	reader.Tx(apdu)
	apdu = "00 20 00 80 " + fmt.Sprintf("%02X % X", len(pin), pin)
	reader.Tx(apdu)
	apdu = "00 24 01 80 " + fmt.Sprintf("%02X % X", len(newpin), newpin)
	reader.Tx(apdu)
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

func showCardInfo(c *cli.Context) error {
	pin := []byte(c.String("pin"))
	if len(pin) == 0 {
		fmt.Printf("暗証番号(4桁): ")
		pin, _ = gopass.GetPasswdMasked()
	}
	if len(pin) != 4 {
		fmt.Printf("エラー: 暗証番号(4桁)を入力してください。\n")
		return nil
	}

	info, err := libmyna.GetCardInfo(c, string(pin))
	if err != nil {
		fmt.Printf("エラー: %s\n", err)
		os.Exit(1)
	}

	if c.String("form") == "json" {
		out, _ := json.MarshalIndent(info, "", "  ")
		fmt.Printf("%s", out)
	}else{
		fmt.Printf("個人番号: %s\n", info["number"])
		fmt.Printf("謎ヘッダ: %s\n", info["header"])
		fmt.Printf("氏名:     %s\n", info["name"])
		fmt.Printf("住所:     %s\n", info["address"])
		fmt.Printf("生年月日: %s\n", info["birth"])
		fmt.Printf("性別:     %s\n", info["sex"])
	}
	return nil
}

func showPinStatus(c *cli.Context) error {
	status, err := libmyna.GetPinStatus(c)
	if err != nil {
		return err
	}

	fmt.Printf("認証用PIN: のこり%d回\n", status["auth"])
	fmt.Printf("署名用PIN: のこり%d回\n", status["sign"])
	fmt.Printf("券面入力補助PIN: のこり%d回\n", status["card"])
	fmt.Printf("謎のPIN1: のこり%d回\n", status["unknown1"])
	fmt.Printf("謎のPIN2: のこり%d回\n", status["unknown2"])

	return nil
}

func sign(c *cli.Context) error {
	pin := c.String("pin")
	if len(pin) == 0 {
		fmt.Printf("署名用パスワード(6-16桁): ")
		input, _ := gopass.GetPasswdMasked()
		pin = string(input)
	}
	pass := strings.ToUpper(pin)

	if len(pin) < 6 || 16 < len(pin) {
		fmt.Printf("エラー: 署名用パスワード(6-16桁)を入力してください。\n")
		return nil
	}

	in := c.String("in")
	if in == "" {
		return errors.New("エラー: 署名対象ファイルを指定してください。")
	}

	err := libmyna.Sign(c, pass, in, "out.txt")
	if err != nil {
		fmt.Printf("エラー: %s\n", err)
		os.Exit(1)
	}
	return nil
}
