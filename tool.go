package main

import (
	//"os"
	"fmt"
	"github.com/urfave/cli"
)

var toolCommands = []cli.Command {
	{
		Name: "beep_off",
		Usage: "Beep off for ACS Reader",
		Action: beepOff,
	},
	{
		Name: "find_ap",
		Usage: "search AP",
		Action: findAP,
		Flags: commonFlags,
	},
}

func beepOff(c *cli.Context) error {
	reader := NewReader(c)
	defer reader.Finalize()
	reader.WaitForCard()
	reader.Tx("FF 00 52 00 00")
	return nil
}

func findAP(c *cli.Context) error {
	//var prefix = []byte{0xD3, 0x92}
	var prefix = []byte{}

	reader := NewReader(c)
	defer reader.Finalize()
	reader.WaitForCard()
	ret := findDF(reader, prefix)
	for _, ap := range ret {
		fmt.Printf("found ap: % X\n", ap)
	}
	return nil
}

func findDF(reader *Reader, prefix []byte) [][]byte {
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
