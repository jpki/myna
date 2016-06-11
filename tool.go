package main

import (
	//"os"
	//"fmt"
	"github.com/urfave/cli"
)

var toolCommands = []cli.Command {
	{
		Name: "beep_off",
		Usage: "Beep off for ACS Reader",
		Action: beepOff,
	},
}

func beepOff(c *cli.Context) error {
	reader := NewReader()
	defer reader.Finalize()
	card := reader.WaitForCard()
	tx(card, "FF 00 52 00 00")
	return nil
}

