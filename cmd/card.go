package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var cardCmd = &cobra.Command{
	Use:     "card",
	Short:   "券面事項を確認",
	RunE:    showCardInfo,
	PreRunE: checkCard,
}

func checkCard(cmd *cobra.Command, args []string) error {
	return libmyna.CheckCard()
}

func showCardInfo(cmd *cobra.Command, args []string) error {
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

	attr, err := libmyna.GetAttrInfo(pin)
	if err != nil {
		return err
	}

	form, _ := cmd.Flags().GetString("form")
	outputCardInputHelperAttrs(mynumber, attr, form)
	return nil
}

func outputCardInputHelperAttrs(mynumber string, attr *libmyna.CardInputHelperAttrs, form string) {
	switch form {
	case "json":
		obj := map[string]string{
			"mynumber": mynumber,
			"header: ": attr.HeaderString(),
			"name":     attr.Name,
			"address":  attr.Address,
			"birth":    attr.Birth,
			"sex":      attr.SexString(),
		}
		out, _ := json.MarshalIndent(obj, "", "  ")
		fmt.Printf("%s", out)
	default:
		fmt.Printf("個人番号: %s\n", mynumber)
		fmt.Printf("謎ヘッダ: %s\n", attr.HeaderString())
		fmt.Printf("氏名:     %s\n", attr.Name)
		fmt.Printf("住所:     %s\n", attr.Address)
		fmt.Printf("生年月日: %s\n", attr.Birth)
		fmt.Printf("性別:     %s\n", attr.SexString())
	}
}

func init() {
	cardCmd.Flags().String("pin", "", "暗証番号(4桁)")
	cardCmd.Flags().String("form", "text", "出力形式(txt,json)")
}
