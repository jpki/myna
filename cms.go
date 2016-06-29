package main

import (
	//"os"
	//"fmt"
	"github.com/urfave/cli"
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
	reader := NewReader(c)
	defer reader.Finalize()
	reader.WaitForCard()
	return nil
}
