package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/howeyc/gopass"
	"github.com/ianmcmahon/encoding_ssh"
	"github.com/jpki/myna/libmyna"
	"github.com/urfave/cli"
	"os"
	"regexp"
	"strings"
)

var appFlags = []cli.Flag{
	cli.BoolFlag{
		Name:  "debug, d",
		Usage: "詳細出力",
	},
}

var appCommands = []cli.Command{
	{
		Name:   "test",
		Usage:  "動作確認",
		Action: testCard,
	},
	{
		Name:   "card",
		Usage:  "券面事項入力補助AP",
		Action: showCardInfo,
		Before: checkCard,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "pin",
				Usage: "暗証番号(4桁)",
			},
			cli.StringFlag{
				Name:  "form",
				Usage: "出力形式(txt,json)",
			},
		},
	},
	{
		Name:        "cert",
		Usage:       "証明書を表示",
		Subcommands: certCommands,
	},
	{
		Name:   "pin_status",
		Usage:  "PINステータス",
		Action: showPinStatus,
		Before: checkCard,
	},
	{
		Name:   "sign",
		Usage:  "CMS署名",
		Action: sign,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "pin",
				Usage: "署名用パスワード(6-16桁)",
			},
			cli.StringFlag{
				Name:  "in,i",
				Usage: "署名対象ファイル",
			},
			cli.StringFlag{
				Name:  "out,o",
				Usage: "署名対象ファイル",
			},
		},
	},
	{
		Name:        "change_pin",
		Usage:       "PIN変更",
		Subcommands: changePinCommands,
	},
	{
		Name:        "misc",
		Usage:       "種々様々なツール",
		Subcommands: toolCommands,
	},
}

func main() {
	app := cli.NewApp()
	app.Name = "myna"
	app.Usage = "マイナクライアント"
	app.Author = "HAMANO Tsukasa"
	app.Email = "hamano@osstech.co.jp"
	app.Version = libmyna.Version
	app.Flags = appFlags
	app.Commands = appCommands
	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: %s\n", err)
		os.Exit(1)
	}
}

var certFormFlag = cli.StringFlag{
	Name:  "form",
	Usage: "出力形式(text,pem,der,ssh)",
}

var certCommands = []cli.Command{
	{
		Name:   "auth",
		Usage:  "利用者認証用証明書を表示",
		Action: showAuthCert,
		Flags: []cli.Flag{
			certFormFlag,
		},
	},
	{
		Name:   "auth_ca",
		Usage:  "利用者認証用CA証明書を表示",
		Action: showAuthCACert,
		Flags: []cli.Flag{
			certFormFlag,
		},
	},
	{
		Name:   "sign",
		Usage:  "署名用証明書を表示",
		Action: showSignCert,
		Flags: []cli.Flag{
			certFormFlag,
			cli.StringFlag{
				Name:  "pin",
				Usage: "署名用パスワード(6-16桁)",
			},
		},
	},
	{
		Name:   "sign_ca",
		Usage:  "署名用CA証明書を表示",
		Action: showSignCACert,
		Flags: []cli.Flag{
			certFormFlag,
		},
	},
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

	//FindEF(c, "D3 92 10 00 31 00 01 01 01 00")
	//FindEF(c, "D3 92 10 00 31 00 01 01 04 01")
	//FindEF(c, "D3 92 10 00 31 00 01 01 04 02")
	//FindEF(c, "D3 92 10 00 31 00 01 01 04 08")
	return nil
}

func printCert(c *cli.Context, cert *x509.Certificate) {
	form := c.String("form")
	if form == "pem" {
		var block pem.Block
		block.Type = "CERTIFICATE"
		block.Bytes = cert.Raw
		pem.Encode(os.Stdout, &block)
	} else if form == "der" {
		fmt.Println("not implement yet")
		/*
			    fp, _ := os.Create("cert.der")
				defer fp.Close()
				fp.Write(data)
		*/
	} else if form == "ssh" {
		rsaPubkey := cert.PublicKey.(*rsa.PublicKey)
		sshPubkey, _ := ssh.EncodePublicKey(*rsaPubkey, "")
		fmt.Println(sshPubkey)
	} else {
		fmt.Printf("SerialNumber: %s\n", cert.SerialNumber)
		fmt.Printf("Subject: %s\n", libmyna.Name2String(cert.Subject))
		fmt.Printf("Issuer: %s\n", libmyna.Name2String(cert.Issuer))
		fmt.Printf("NotBefore: %s\n", cert.NotBefore)
		fmt.Printf("NotAfter: %s\n", cert.NotAfter)
		fmt.Printf("KeyUsage: %v\n", cert.KeyUsage)
	}
}

func showAuthCert(c *cli.Context) error {
	cert, err := libmyna.GetCert(c, "00 0A", "")
	if err != nil {
		return err
	}
	printCert(c, cert)
	return nil
}

func showAuthCACert(c *cli.Context) error {
	cert, err := libmyna.GetCert(c, "00 0B", "")
	if err != nil {
		return err
	}
	printCert(c, cert)
	return nil
}

func showSignCert(c *cli.Context) error {
	pin := c.String("pin")
	if len(pin) == 0 {
		fmt.Printf("署名用パスワード(6-16桁): ")
		input, _ := gopass.GetPasswdMasked()
		pin = string(input)
	}
	pass := strings.ToUpper(pin)
	match, _ := regexp.MatchString("^[A-Z0-9]{6,16}$", pass)
	if !match {
		return errors.New("署名用パスワード(6-16桁)を入力してください。")
	}
	cert, err := libmyna.GetCert(c, "00 01", pass)
	if err != nil {
		return err
	}
	printCert(c, cert)
	return nil
}

func showSignCACert(c *cli.Context) error {
	cert, err := libmyna.GetCert(c, "00 02", "")
	if err != nil {
		return err
	}
	printCert(c, cert)
	return nil
}

func showCardInfo(c *cli.Context) error {
	pin := c.String("pin")
	if len(pin) == 0 {
		fmt.Printf("暗証番号(4桁): ")
		input, _ := gopass.GetPasswdMasked()
		pin = string(input)
	}
	match, _ := regexp.MatchString("^\\d{4}$", pin)
	if !match {
		return errors.New("暗証番号(4桁)を入力してください。")
	}

	info, err := libmyna.GetCardInfo(c, pin)
	if err != nil {
		return err
	}

	if c.String("form") == "json" {
		out, _ := json.MarshalIndent(info, "", "  ")
		fmt.Printf("%s", out)
	} else {
		fmt.Printf("個人番号: %s\n", info["number"])
		fmt.Printf("謎ヘッダ: %s\n", info["header"])
		fmt.Printf("氏名:     %s\n", info["name"])
		fmt.Printf("住所:     %s\n", info["address"])
		fmt.Printf("生年月日: %s\n", info["birth"])
		fmt.Printf("性別:     %s\n", libmyna.ToISO5218String(info["sex"]))
	}
	return nil
}

func showPinStatus(c *cli.Context) error {
	status, err := libmyna.GetPinStatus(c)
	if err != nil {
		return err
	}

	fmt.Printf("券面入力補助PIN: のこり%d回\n", status["card"])
	fmt.Printf("認証用PIN: のこり%d回\n", status["auth"])
	fmt.Printf("署名用PIN: のこり%d回\n", status["sign"])
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
	match, _ := regexp.MatchString("^[A-Z0-9]{6,16}$", pass)
	if !match {
		return errors.New("署名用パスワード(6-16桁)を入力してください")
	}
	in := c.String("in")
	if in == "" {
		return errors.New("署名対象ファイルを指定してください")
	}

	out := c.String("out")
	if out == "" {
		return errors.New("出力ファイルを指定してください")
	}

	err := libmyna.Sign(c, pass, in, out)
	if err != nil {
		return err
	}
	return nil
}
