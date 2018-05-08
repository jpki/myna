package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var cardCmd = &cobra.Command{
	Use:   "card",
	Short: "券面APおよび券面事項入力補助AP",
}

var showMyNumberCmd = &cobra.Command{
	Use:     "mynumber",
	Short:   "券面事項入力補助APのマイナンバーを表示します",
	RunE:    showMyNumber,
	PreRunE: checkCard,
}

var showAttributesCmd = &cobra.Command{
	Use:     "attr",
	Short:   "券面事項入力補助APの4属性を表示します",
	RunE:    showAttributes,
	PreRunE: checkCard,
}

var cardFrontPhotoCmd = &cobra.Command{
	Use:     "photo -o [output.jpg|-]",
	Short:   "券面APの顔写真を取得",
	RunE:    showCardFrontPhoto,
	PreRunE: checkCard,
}

func checkCard(cmd *cobra.Command, args []string) error {
	return libmyna.CheckCard()
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
	outputCardInputHelperAttrs(attr, form)
	return nil
}

func outputCardInputHelperAttrs(attr *libmyna.CardInputHelperAttrs, form string) {
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

func showCardFrontPhoto(cmd *cobra.Command, args []string) error {
	output, err := cmd.Flags().GetString("output")
	if output == "" {
		cmd.Usage()
		return nil
	}
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

	info, err := libmyna.GetCardFront(mynumber)
	if err != nil {
		return err
	}

	var file *os.File
	if output == "-" {
		file = os.Stdout
	} else {
		file, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		defer file.Close()
		if err != nil {
			return err
		}
	}

	file.Write(info.Photo)
	return nil
}

func init() {
	cardCmd.AddCommand(showMyNumberCmd)
	showMyNumberCmd.Flags().StringP("pin", "p", "", "暗証番号(4桁)")
	cardCmd.AddCommand(showAttributesCmd)
	showAttributesCmd.Flags().StringP("pin", "p", "", "暗証番号(4桁)")
	showAttributesCmd.Flags().StringP("form", "f", "text", "出力形式(txt,json)")
	cardCmd.AddCommand(cardFrontPhotoCmd)
	cardFrontPhotoCmd.Flags().StringP("pin", "p", "", "暗証番号(4桁)")
	cardFrontPhotoCmd.Flags().StringP("output", "o", "", "出力ファイル(JPEG2000)")
}
