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

	info, err := libmyna.GetAttrInfo(pin)
	if err != nil {
		return err
	}

	form, _ := cmd.Flags().GetString("form")
	switch form {
	case "json":
		info["mynumber"] = mynumber
		out, _ := json.MarshalIndent(info, "", "  ")
		fmt.Printf("%s", out)
	default:
		fmt.Printf("個人番号: %s\n", mynumber)
		fmt.Printf("謎ヘッダ: %s\n", info["header"])
		fmt.Printf("氏名:     %s\n", info["name"])
		fmt.Printf("住所:     %s\n", info["address"])
		fmt.Printf("生年月日: %s\n", info["birth"])
		fmt.Printf("性別:     %s\n", libmyna.ToISO5218String(info["sex"]))
	}
	return nil
}

func init() {
	cardCmd.Flags().String("pin", "", "暗証番号(4桁)")
	cardCmd.Flags().String("form", "text", "出力形式(txt,json)")
}
