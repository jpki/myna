package main

import "github.com/jpki/myna/libmyna"

import (
	"os"
	"fmt"
	"github.com/fullsailor/pkcs7"
	"github.com/urfave/cli"
	"github.com/howeyc/gopass"
)

var cmsCommands = []cli.Command {
	{
		Name: "sign",
		Usage: "sign",
		Action: sign,
		Flags: commonFlags,
	},
}

func sign(c *cli.Context) error {
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

	reader.SelectAP("D3 92 f0 00 26 01 00 00 00 01")
	apdu := ""	

	reader.SelectEF("00 18") // VERIFY AUTH EF
	apdu = "00 20 00 80"
	reader.Tx(apdu)
	apdu = "00 20 00 80 " + fmt.Sprintf("%02X % X", len(pin), pin)
	reader.Tx(apdu)

	reader.SelectEF("00 1b") // VERIFY SIGN EF
	apdu = "00 20 00 80"
	reader.Tx(apdu)
	apdu = "00 20 00 80 09 53 45 43 52 45 54 31 32 33"
	reader.Tx(apdu)

	reader.SelectEF("00 18") // VERIFY AUTH EF
	apdu = "00 20 00 80"
	reader.Tx(apdu)
	apdu = "00 20 00 80 " + fmt.Sprintf("%02X % X", len(pin), pin)
	reader.Tx(apdu)

	/*
	reader.SelectEF("00 1b") // VERIFY SIGN EF
	apdu = "00 20 00 80"
	reader.Tx(apdu)
	apdu = "00 20 00 80 09 53 45 43 52 45 54 31 32 33"
	reader.Tx(apdu)
*/
	content := []byte("Hello World")
	toBeSigned, _ := pkcs7.NewSignedData(content)
	signed, _ := toBeSigned.Finish()
	_ =signed
	reader.SelectEF("00 17") // SIGN AUTH EF
	//apdu = "80 2a 00 80 " + fmt.Sprintf("%02X % X", len(signed), signed)
	apdu = "80 2a 00 80 33 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 b0 68 c6 16 47 6d 89 6c 8b c7 10 4e 36 03 83 21 dc 84 b9 30 64 56 76 23 e0 68 39 61 64 00 84 2f 00"
	reader.Tx(apdu)

	reader.SelectEF("00 1A") // SIGN SIGN EF
	apdu = "80 2a 00 80 33 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 b0 68 c6 16 47 6d 89 6c 8b c7 10 4e 36 03 83 21 dc 84 b9 30 64 56 76 23 e0 68 39 61 64 00 84 2f 00"
	reader.Tx(apdu)

	reader.SelectEF("00 17") // SIGN AUTH EF
	apdu = "80 2a 00 80 33 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 b0 68 c6 16 47 6d 89 6c 8b c7 10 4e 36 03 83 21 dc 84 b9 30 64 56 76 23 e0 68 39 61 64 00 84 2f 00"
	reader.Tx(apdu)

	reader.SelectEF("00 1A") // SIGN SIGN EF
	apdu = "80 2a 00 80 33 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 b0 68 c6 16 47 6d 89 6c 8b c7 10 4e 36 03 83 21 dc 84 b9 30 64 56 76 23 e0 68 39 61 64 00 84 2f 00"
	reader.Tx(apdu)

	return nil
}
