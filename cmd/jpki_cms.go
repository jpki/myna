package cmd

import (
	"errors"
	"fmt"
	"os"
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
	detached, _ := cmd.Flags().GetBool("detached")
	opts := libmyna.CmsSignOpts{md, form, detached}
	err = libmyna.CmsSignJPKISign(pin, in, out, opts)
	return err
}

func jpkiCmsVerify(cmd *cobra.Command, args []string) error {
	detached, _ := cmd.Flags().GetBool("detached")

	if len(args) != 1 {
		cmd.Usage()

		if detached {
			return errors.New("署名ファイルを指定してください")
		} else {
			return errors.New("検証対象ファイルを指定してください")
		}
	}

	form, _ := cmd.Flags().GetString("form")

	content, _ := cmd.Flags().GetString("content")
	if detached && content == "" {
		cmd.Usage()
		return errors.New("検証対象ファイルを-cで指定してください")
	} else if !detached && content != "" {
		fmt.Fprintf(os.Stderr,
			"警告: -c は --detached時のみ有効です。'%s'の内容は無視されます。\n", content)
	}

	opts := libmyna.CmsVerifyOpts{form, detached, content}
	err := libmyna.CmsVerifyJPKISign(args[0], opts)
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
	jpkiCmsSignCmd.Flags().StringP("form", "f", "der", "出力形式(pem,der)")
	jpkiCmsSignCmd.Flags().Bool("detached", false, "デタッチ署名 (Detached Signature)")

	jpkiCmsCmd.AddCommand(jpkiCmsVerifyCmd)
	jpkiCmsVerifyCmd.Flags().StringP("content", "c", "", "デタッチ署名の検証対象ファイル (--detached時のみ有効)")
	jpkiCmsVerifyCmd.Flags().Bool("detached", false, "デタッチ署名 (Detached Signature)")
	jpkiCmsVerifyCmd.Flags().StringP("form", "f", "der", "入力形式(pem,der)")
}
