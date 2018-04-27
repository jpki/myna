package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var cardCmd = &cobra.Command{
	Use:   "card",
	Short: "券面事項を確認",
	RunE:  showCardInfo,
}

func showCardInfo(cmd *cobra.Command, args []string) error {
	pin, _ := cmd.Flags().GetString("pin")
	if pin == "" {
		fmt.Printf("暗証番号(4桁): ")
		input, err := gopass.GetPasswdMasked()
		if err != nil {
			return nil
		}
		pin = string(input)
	}
	err := libmyna.Validate4DigitPin(pin)
	if err != nil {
		return err
	}
	info, err := libmyna.GetCardInfo(pin)
	if err != nil {
		return err
	}

	form, _ := cmd.Flags().GetString("form")
	switch form {
	case "json":
		out, _ := json.MarshalIndent(info, "", "  ")
		fmt.Printf("%s", out)
	default:
		fmt.Printf("個人番号: %s\n", info["number"])
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
