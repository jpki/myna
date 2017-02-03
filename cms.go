package main

import (
	"os"
	"fmt"
	"github.com/fullsailor/pkcs7"
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
	if reader == nil {
		os.Exit(1)
	}
	defer reader.Finalize()
	reader.WaitForCard()
	content := []byte("Hello World")
	toBeSigned, _ := pkcs7.NewSignedData(content)
	signed, _ := toBeSigned.Finish()
	fmt.Printf("%s\n", signed)
	return nil
}
