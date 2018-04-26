package cmd

import (
	_ "fmt"

	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var toolCmd = &cobra.Command{
	Use:   "tool",
	Short: "種々様々なツール",
}

var beepCmd = &cobra.Command{
	Use:   "beep",
	Short: "ACS Readerのbeep音を切り替えます",
}

var beepOnCmd = &cobra.Command{
	Use:   "on",
	Short: "beep音を有効化します",
	RunE:  beepOn,
}

func beepOn(cmd *cobra.Command, args []string) error {
	reader, err := libmyna.NewReader(&ctx)
	if reader == nil {
		return err
	}
	defer reader.Finalize()
	err = reader.Connect()
	if err != nil {
		return err
	}
	reader.Tx("FF 00 52 FF 00")
	return nil
}

var beepOffCmd = &cobra.Command{
	Use:   "off",
	Short: "beep音を無効化します",
	RunE:  beepOff,
}

func beepOff(cmd *cobra.Command, args []string) error {
	reader, err := libmyna.NewReader(&ctx)
	if reader == nil {
		return err
	}
	defer reader.Finalize()
	err = reader.Connect()
	if err != nil {
		return err
	}
	reader.Tx("FF 00 52 00 00")
	return nil
}

func init() {
	toolCmd.AddCommand(beepCmd)
	beepCmd.AddCommand(beepOnCmd)
	beepCmd.AddCommand(beepOffCmd)
}
