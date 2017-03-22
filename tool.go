package main

import (
	//"os"
	"./driver"
	"fmt"
	"github.com/urfave/cli"
)

var toolCommands = []cli.Command {
	{
		Name: "beep_off",
		Usage: "Beep off for ACS Reader",
		Action: beepOff,
		Flags: commonFlags,
	},
	{
		Name: "pin_status",
		Usage: "PINステータス",
		Action: pinStatus,
		Before: checkCard,
		Flags: commonFlags,
	},
	{
		Name: "find_ap",
		Usage: "search AP",
		Action: findAP,
		Flags: commonFlags,
	},
}

func beepOff(c *cli.Context) error {
	reader := driver.NewReader(c)
	defer reader.Finalize()
	reader.WaitForCard()
	reader.Tx("FF 00 52 00 00")
	return nil
}

func pinStatus(c *cli.Context) error {
	reader := driver.NewReader(c)
	defer reader.Finalize()
	reader.WaitForCard()

	aid := "D3 92 f0 00 26 01 00 00 00 01" // 公的個人認証
	apdu := "00 A4 04 0C" + " 0A " + aid
	sw1, sw2, _:= reader.Tx(apdu)

	reader.Tx("00 a4 02 0C 02 00 18") // IEF for AUTH
	sw1, sw2, _ = reader.Tx("00 20 00 80")
	if (sw1 == 0x63) {
		fmt.Printf("認証用PIN: のこり%d回\n", sw2 - 0xC0)
	}
	reader.Tx("00 a4 02 0C 02 00 1B") // IEF for SIGN
	sw1, sw2, _ = reader.Tx("00 20 00 80")
	if (sw1 == 0x63) {
		fmt.Printf("署名用PIN: のこり%d回\n", sw2 - 0xC0)
	}

	aid = "D3 92 10 00 31 00 01 01 04 08" // 券面事項DF
	apdu = "00 A4 04 0C" + " 0A " + aid
	reader.Tx(apdu)
	reader.Tx("00 a4 02 0C 02 00 11") // IEF
	reader.Tx("00 20 00 80")
	sw1, sw2, _ = reader.Tx("00 20 00 80")
	if (sw1 == 0x63) {
		fmt.Printf("券面入力補助PIN: のこり%d回\n", sw2 - 0xC0)
	}

	aid = "D3 92 10 00 31 00 01 01 01 00" // 謎
	apdu = "00 A4 04 0C" + " 0A " + aid
	reader.Tx(apdu)
	reader.Tx("00 a4 02 0C 02 00 1C") // IEF
	reader.Tx("00 20 00 80")
	sw1, sw2, _ = reader.Tx("00 20 00 80")
	if (sw1 == 0x63) {
		fmt.Printf("謎のPIN1: のこり%d回\n", sw2 - 0xC0)
	}

	aid = "D3 92 10 00 31 00 01 01 04 01" // 住基?
	apdu = "00 A4 04 0C" + " 0A " + aid
	reader.Tx(apdu)
	reader.Tx("00 a4 02 0C 02 00 1C") // IEF
	reader.Tx("00 20 00 80")
	sw1, sw2, _ = reader.Tx("00 20 00 80")
	if (sw1 == 0x63) {
		fmt.Printf("謎のPIN2: のこり%d回\n", sw2 - 0xC0)
	}

	return nil
}

func findAP(c *cli.Context) error {
	var prefix = []byte{}

	reader := driver.NewReader(c)
	defer reader.Finalize()
	reader.WaitForCard()
	ret := findDF(reader, prefix)
	for _, ap := range ret {
		fmt.Printf("found ap: % X\n", ap)
	}
	return nil
}

func findDF(reader *driver.Reader, prefix []byte) [][]byte {
	var tmp [][]byte
	i := len(prefix)
	l := i + 1
	buf := append(prefix, 0)
	for n := 0; n<255; n++ {
		buf[i] = byte(n)
		apdu := "00 A4 04 0C " +
			fmt.Sprintf("%02X ", l) +
			fmt.Sprintf("% X", buf)
		sw1, sw2, _ := reader.Tx(apdu)
		if(sw1 == 0x90 && sw2 == 0x00){
			ret := findDF(reader, buf)
			if len(ret) == 0 {
				//fmt.Printf("found ap % X\n", buf)
				dup := make([]byte, len(buf))
				copy(dup, buf)
				tmp = append(tmp, dup)
			}else{
				tmp = append(tmp, ret...)
			}
		}
	}
	return tmp
}
