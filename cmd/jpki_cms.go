package cmd

import (
	"errors"
	"fmt"
	"strings"

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

var jpkiCmsVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "CMS署名を検証します",
	RunE:  jpkiCmsVerify,
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

	pin, err := cmd.Flags().GetString("pin")
	if pin == "" {
		pin, err = inputPin("署名用パスワード(6-16桁): ")
		if err != nil {
			return nil
		}
	}
	pin = strings.ToUpper(pin)

	md, _ := cmd.Flags().GetString("md")
	form, _ := cmd.Flags().GetString("form")
	opts := libmyna.CmsSignOpts{md, form}
	err = libmyna.CmsSignJPKISign(pin, in, out, opts)
	return err
}

func jpkiCmsVerify(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		cmd.Usage()
		return errors.New("検証対象ファイルを指定してください")
	}

	err := libmyna.CmsVerifyJPKISign(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("Verification successful\n")
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
	jpkiCmsSignCmd.Flags().StringP(
		"md", "m", "sha1", "ダイジェストアルゴリズム(sha1|sha256|sha512)")
	jpkiCmsSignCmd.Flags().String("form", "pem", "出力形式(pem,der)")

	jpkiCmsCmd.AddCommand(jpkiCmsVerifyCmd)

}
