package main

import "github.com/jpki/myna/libmyna"

import (
	"fmt"
	"github.com/urfave/cli"
	_ "os"
)

var toolCommands = []cli.Command{
	{
		Name:   "beep_off",
		Usage:  "Beep off for ACS Reader",
		Action: beepOff,
	},
	{
		Name:   "find_ap",
		Usage:  "search AP",
		Action: findAP,
	},
}

func beepOff(c *cli.Context) error {
	reader := libmyna.NewReader(c)
	defer reader.Finalize()
	reader.WaitForCard()
	reader.Tx("FF 00 52 00 00")
	return nil
}

func findAP(c *cli.Context) error {
	var prefix = []byte{}

	reader := libmyna.NewReader(c)
	defer reader.Finalize()
	reader.WaitForCard()
	ret := findDF(reader, prefix)
	for _, ap := range ret {
		fmt.Printf("found ap: % X\n", ap)
	}
	return nil
}

func findDF(reader *libmyna.Reader, prefix []byte) [][]byte {
	var tmp [][]byte
	i := len(prefix)
	l := i + 1
	buf := append(prefix, 0)
	for n := 0; n < 255; n++ {
		buf[i] = byte(n)
		apdu := "00 A4 04 0C " +
			fmt.Sprintf("%02X ", l) +
			fmt.Sprintf("% X", buf)
		sw1, sw2, _ := reader.Tx(apdu)
		if sw1 == 0x90 && sw2 == 0x00 {
			ret := findDF(reader, buf)
			if len(ret) == 0 {
				//fmt.Printf("found ap % X\n", buf)
				dup := make([]byte, len(buf))
				copy(dup, buf)
				tmp = append(tmp, dup)
			} else {
				tmp = append(tmp, ret...)
			}
		}
	}
	return tmp
}

func FindEF(c *cli.Context, df string) {
	reader, err := libmyna.Ready(c)
	if err != nil {
		return
	}
	defer reader.Finalize()
	reader.SelectDF(df)
	for i := 0; i < 255; i++ {
		for j := 0; j < 255; j++ {
			ef := fmt.Sprintf("%02X %02X", i, j)
			sw1, _ := reader.SelectEF(ef)
			if sw1 == 0x90 {
				fmt.Printf("FOUND %s\n", ef)
				sw1, sw2, data := reader.Tx("00 20 00 80")
				fmt.Printf("-> %x, %x, % X\n", sw1, sw2, data)
			}
		}
	}
}
