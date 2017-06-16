package main

import (
	"fmt"
	"github.com/howeyc/gopass"
	"github.com/jpki/myna/libmyna"
	"github.com/urfave/cli"
)

var changePinCommands = []cli.Command{
	{
		Name:  "card",
		Usage: "券面入力補助用PINを変更",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "pin",
				Usage: "現在の暗証番号(4桁)",
			},
			cli.StringFlag{
				Name:  "newpin",
				Usage: "新しい暗証番号(4桁)",
			},
		},
		Action: changePinCard,
	},
	{
		Name:  "auth",
		Usage: "認証用PINを変更",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "pin",
				Usage: "現在の暗証番号(4桁)",
			},
			cli.StringFlag{
				Name:  "newpin",
				Usage: "新しい暗証番号(4桁)",
			},
		},
		Action: changePinAuth,
	},
	{
		Name:  "sign",
		Usage: "署名用パスワードを変更",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "pin",
				Usage: "現在のパスワード",
			},
			cli.StringFlag{
				Name:  "newpin",
				Usage: "新しいパスワード",
			},
		},
		Action: changePinSign,
	},
}

func changePinCard(c *cli.Context) error {
	pin := c.String("pin")
	if len(pin) == 0 {
		fmt.Printf("現在の券面入力補助用PIN(4桁): ")
		input, _ := gopass.GetPasswdMasked()
		pin = string(input)
	}
	newpin := c.String("newpin")
	if len(newpin) == 0 {
		fmt.Printf("新しい券面入力補助用用PIN(4桁): ")
		input, _ := gopass.GetPasswdMasked()
		newpin = string(input)
	}
	err := libmyna.ChangePinCard(c, pin, newpin)
	if err != nil {
		return err
	}
	fmt.Printf("PINを変更しました")
	return nil
}

func changePinAuth(c *cli.Context) error {
	pin := c.String("pin")
	if len(pin) == 0 {
		fmt.Printf("現在の認証用PIN(4桁): ")
		input, _ := gopass.GetPasswdMasked()
		pin = string(input)
	}
	newpin := c.String("newpin")
	if len(newpin) == 0 {
		fmt.Printf("新しい認証用PIN(4桁): ")
		input, _ := gopass.GetPasswdMasked()
		newpin = string(input)
	}
	err := libmyna.ChangePinAuth(c, pin, newpin)
	if err != nil {
		return err
	}
	fmt.Printf("PINを変更しました")
	return nil
}

func changePinSign(c *cli.Context) error {
	pin := c.String("pin")
	if len(pin) == 0 {
		fmt.Printf("現在の署名用パスワード(6-16桁): ")
		input, _ := gopass.GetPasswdMasked()
		pin = string(input)
	}
	newpin := c.String("newpin")
	if len(newpin) == 0 {
		fmt.Printf("新しい署名用パスワード(6-16桁): ")
		input, _ := gopass.GetPasswdMasked()
		newpin = string(input)
	}
	err := libmyna.ChangePinSign(c, pin, newpin)
	if err != nil {
		return err
	}
	fmt.Printf("パスワードを変更しました")
	return nil
}
