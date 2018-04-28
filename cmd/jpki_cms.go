package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var jpkiCmsCmd = &cobra.Command{
	Use:   "cms",
	Short: "CMS署名と検証を行います",
}

var jpkiCmsSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "CMS署名を行います",
	RunE:  jpkiCmsSign,
}

func jpkiCmsSign(cmd *cobra.Command, args []string) error {
	in, _ := cmd.Flags().GetString("in")
	if in == "" {
		cmd.Usage()
		return errors.New("署名対象ファイルを指定してください")
	}
	out, _ := cmd.Flags().GetString("out")
	if out == "" {
		cmd.Usage()
		return errors.New("出力ファイルを指定してください")
	}

	pin, _ := cmd.Flags().GetString("pin")
	if pin == "" {
		fmt.Printf("署名用パスワード(6-16桁): ")
		input, err := gopass.GetPasswdMasked()
		if err != nil {
			return nil
		}
		pin = string(input)
	}
	pin = strings.ToUpper(pin)

	err := libmyna.SignCmsJPKI(pin, in, out)
	if err != nil {
		return err
	}
	return nil
}

func init() {
	jpkiCmd.AddCommand(jpkiCmsCmd)
	jpkiCmsCmd.AddCommand(jpkiCmsSignCmd)
	jpkiCmsSignCmd.Flags().StringP(
		"pin", "p", "", "署名用パスワード(6-16桁)")
	jpkiCmsSignCmd.Flags().StringP(
		"in", "i", "", "署名対象ファイル")
	jpkiCmsSignCmd.Flags().StringP(
		"out", "o", "", "出力ファイル")
}
