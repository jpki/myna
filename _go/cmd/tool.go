// +build tool

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var toolCmd = &cobra.Command{
	Use:   "tool",
	Short: "種々様々なツール",
}

var beepCmd = &cobra.Command{
	Use:   "beep on|off",
	Short: "ACS Readerのbeep音設定",
	Long: `ACS Readerのbeep音を切り替えます

 - on  ビープ音を有効化します
 - off ビープ音を無効化します
`,
	RunE: beep,
}

func beep(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		cmd.Help()
		return nil
	}

	if args[0] != "on" && args[0] != "off" {
		cmd.Help()
		return nil
	}

	reader, err := libmyna.NewReader()
	if reader == nil {
		return err
	}
	defer reader.Finalize()
	debug, _ := cmd.Flags().GetBool("debug")
	reader.SetDebug(debug)
	err = reader.Connect()
	if err != nil {
		return err
	}

	var apdu *libmyna.APDU
	if args[0] != "on" {
		apdu, _ = libmyna.NewAPDU("FF 00 52 FF 00")
	} else if args[0] != "off" {
		apdu, _ = libmyna.NewAPDU("FF 00 52 00 00")
	}
	reader.Trans(apdu)
	return nil
}

var findAPCmd = &cobra.Command{
	Use:   "find_ap",
	Short: "APを探索",
	RunE:  findAP,
}

func findAP(cmd *cobra.Command, args []string) error {
	var prefix = []byte{}

	reader, err := libmyna.NewReader()
	if reader == nil {
		return err
	}
	defer reader.Finalize()
	debug, _ := cmd.Flags().GetBool("debug")
	reader.SetDebug(debug)
	err = reader.Connect()
	if err != nil {
		return err
	}
	ret := findDF(reader, prefix)
	for _, ap := range ret {
		fmt.Printf("found ap: % X\n", ap)
	}
	return nil
}

func findDF(reader *libmyna.Reader, prefix []byte) [][]byte {
	var tmp [][]byte
	i := len(prefix)
	buf := append(prefix, 0)
	for n := 0; n < 255; n++ {
		buf[i] = byte(n)
		err := reader.SelectDF(libmyna.ToHexString(buf))
		if err == nil {
			fmt.Printf("FOUND: % X\n", buf)
			ret := findDF(reader, buf)
			if len(ret) == 0 {
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

/*
func findEF(c *cli.Context, df string) {
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
*/

func init() {
	toolCmd.AddCommand(beepCmd)

	toolCmd.AddCommand(findAPCmd)
	rootCmd.AddCommand(toolCmd)
}
