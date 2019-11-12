package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/jpki/myna/libmyna"
	"github.com/spf13/cobra"
)

var textCmd = &cobra.Command{
	Use:   "text",
	Short: "券面入力補助AP",
}

var showMyNumberCmd = &cobra.Command{
	Use:     "mynumber",
	Short:   "券面入力補助APのマイナンバーを表示します",
	RunE:    showMyNumber,
	PreRunE: checkCard,
}

var showAttributesCmd = &cobra.Command{
	Use:     "attr",
	Short:   "券面入力補助APの4属性を表示します",
	RunE:    showAttributes,
	PreRunE: checkCard,
}

var showSignatureCmd = &cobra.Command{
	Use:     "signature",
	Short:   "券面入力補助APの署名値を表示します",
	RunE:    showSignature,
	PreRunE: checkCard,
}

var showCertificateCmd = &cobra.Command{
	Use:     "cert",
	Short:   "券面入力補助APの証明書を表示します",
	RunE:    showCertificate,
	PreRunE: checkCard,
}

var showBasicInfoCmd = &cobra.Command{
	Use:     "info",
	Short:   "券面入力補助APの基本情報を表示します",
	RunE:    showBasicInfo,
	PreRunE: checkCard,
}

func showMyNumber(cmd *cobra.Command, args []string) error {
	pin, err := cmd.Flags().GetString("pin")
	if pin == "" {
		pin, err = inputPin("暗証番号(4桁): ")
		if err != nil {
			return nil
		}
	}
	err = libmyna.Validate4DigitPin(pin)
	if err != nil {
		return err
	}

	mynumber, err := libmyna.GetMyNumber(pin)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", mynumber)
	return nil
}

func showAttributes(cmd *cobra.Command, args []string) error {
	pin, err := cmd.Flags().GetString("pin")
	if pin == "" {
		pin, err = inputPin("暗証番号(4桁): ")
		if err != nil {
			return nil
		}
	}
	err = libmyna.Validate4DigitPin(pin)
	if err != nil {
		return err
	}

	attr, err := libmyna.GetAttrInfo(pin)
	if err != nil {
		return err
	}

	form, _ := cmd.Flags().GetString("form")
	outputTextAttrs(attr, form)
	return nil
}

func outputTextAttrs(attr *libmyna.TextAttrs, form string) {
	switch form {
	case "json":
		obj := map[string]string{
			"header: ": attr.HeaderString(),
			"name":     attr.Name,
			"address":  attr.Address,
			"birth":    attr.Birth,
			"sex":      attr.SexString(),
		}
		out, _ := json.MarshalIndent(obj, "", "  ")
		fmt.Printf("%s", out)
	default:
		fmt.Printf("謎ヘッダ: %s\n", attr.HeaderString())
		fmt.Printf("氏名:     %s\n", attr.Name)
		fmt.Printf("住所:     %s\n", attr.Address)
		fmt.Printf("生年月日: %s\n", attr.Birth)
		fmt.Printf("性別:     %s\n", attr.SexString())
	}
}

func showSignature(cmd *cobra.Command, args []string) error {
	debug, _ := cmd.Flags().GetBool("debug")
	pin, err := cmd.Flags().GetString("pin")
	if pin == "" {
		pin, err = inputPin("暗証番号(4桁): ")
		if err != nil {
			return nil
		}
	}
	err = libmyna.Validate4DigitPin(pin)
	if err != nil {
		return err
	}
	reader, err := libmyna.NewReader(libmyna.Debug(debug))
	//reader.SetDebug(debug)
	if err != nil {
		return err
	}
	defer reader.Finalize()
	err = reader.Connect()
	if err != nil {
		return err
	}
	textAP, err := reader.SelectTextAP()
	if err != nil {
		return err
	}
	err = textAP.VerifyPin(pin)
	if err != nil {
		return err
	}
	signature, err := textAP.ReadSignature()
	fmt.Printf("MyNumHash: %X\n", signature.MyNumDigest)
	fmt.Printf("AttrsHash: %X\n", signature.AttrsDigest)
	fmt.Printf("Signature: %X\n", signature.Signature)
	return nil
}

func showCertificate(cmd *cobra.Command, args []string) error {
	return nil
}

func showBasicInfo(cmd *cobra.Command, args []string) error {
	return nil
}

func init() {
	textCmd.AddCommand(showMyNumberCmd)
	showMyNumberCmd.Flags().StringP("pin", "p", "", "暗証番号(4桁)")
	textCmd.AddCommand(showAttributesCmd)
	showAttributesCmd.Flags().StringP("pin", "p", "", "暗証番号(4桁)")
	showAttributesCmd.Flags().StringP("form", "f", "text", "出力形式(txt,json)")
	textCmd.AddCommand(showSignatureCmd)
	showSignatureCmd.Flags().StringP("pin", "p", "", "暗証番号(4桁)")
	textCmd.AddCommand(showCertificateCmd)
	showCertificateCmd.Flags().StringP("pin", "p", "", "暗証番号(4桁)")
	textCmd.AddCommand(showBasicInfoCmd)
	showBasicInfoCmd.Flags().StringP("pin", "p", "", "暗証番号(4桁)")
}
