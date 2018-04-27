package cmd

import (
	"fmt"
	"os"

	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var pinCmd = &cobra.Command{
	Use:   "pin",
	Short: "PIN関連操作",
	Long: `PIN関連操作
`,
}

var pinStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "PINステータスを表示",
	RunE:  pinStatus,
}

func pinStatus(cmd *cobra.Command, args []string) error {
	status, err := libmyna.GetPinStatus(&ctx)
	if err != nil {
		return err
	}

	fmt.Printf("券面事項PIN(A):\tのこり%2d回\n",
		status["card_info_pin_a"])
	fmt.Printf("券面事項PIN(B):\tのこり%2d回\n",
		status["card_info_pin_b"])
	fmt.Printf("入力補助PIN:\tのこり%2d回\n",
		status["card_input_helper_pin"])
	fmt.Printf("入力補助PIN(A):\tのこり%2d回\n",
		status["card_input_helper_pin_a"])
	fmt.Printf("入力補助PIN(B):\tのこり%2d回\n",
		status["card_input_helper_pin_b"])
	fmt.Printf("JPKI認証用PIN:\tのこり%2d回\n", status["jpki_auth"])
	fmt.Printf("JPKI署名用PIN:\tのこり%2d回\n", status["jpki_sign"])
	/*
		fmt.Printf("謎のPIN1:\tのこり%d回\n", status["unknown1"])
		fmt.Printf("謎のPIN2:\tのこり%d回\n", status["unknown2"])
	*/
	return nil
}

var pinChangeCmd = &cobra.Command{
	Use:   "change",
	Short: "各種PINを変更",
}

var pinChangeCardCmd = &cobra.Command{
	Use:   "card",
	Short: "券面入力補助用PINを変更",
	RunE:  pinChangeCard,
}

func pinChangeCard(cmd *cobra.Command, args []string) error {
	pinName := "券面入力補助用PIN(4桁)"
	pin, _ := cmd.Flags().GetString("pin")
	if pin == "" {
		fmt.Printf("現在の%s: ", pinName)
		input, err := gopass.GetPasswdMasked()
		if err != nil {
			return nil
		}
		pin = string(input)
	}
	newpin, _ := cmd.Flags().GetString("newpin")
	if newpin == "" {
		fmt.Printf("新しい%s: ", pinName)
		input, err := gopass.GetPasswdMasked()
		if err != nil {
			return nil
		}
		newpin = string(input)
	}
	err := libmyna.ChangeCardInputHelperPin(&ctx, pin, newpin)
	if err != nil {
		return err
	}
	fmt.Printf("%sを変更しました", pinName)
	return nil
}

var pinChangeJPKIAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "JPKI認証用PINを変更",
	Long:  `JPKI認証用PINを変更します`,
	RunE:  pinChangeJPKIAuth,
}

func pinChangeJPKIAuth(cmd *cobra.Command, args []string) error {
	pinName := "JPKI認証用パスワード"
	pin, _ := cmd.Flags().GetString("pin")
	if pin == "" {
		fmt.Printf("現在の%s: ", pinName)
		input, err := gopass.GetPasswdMasked()
		if err != nil {
			return nil
		}
		pin = string(input)
	}
	newpin, _ := cmd.Flags().GetString("newpin")
	if newpin == "" {
		fmt.Printf("新しい%s: ", pinName)
		input, err := gopass.GetPasswdMasked()
		if err != nil {
			return nil
		}
		newpin = string(input)
	}
	err := libmyna.ChangeJPKIAuthPin(&ctx, pin, newpin)
	if err != nil {
		return err
	}
	fmt.Printf("%sを変更しました", pinName)
	return nil
}

var pinChangeJPKISignCmd = &cobra.Command{
	Use:   "sign",
	Short: "JPKI署名用パスワードを変更",
	Long:  `JPKI署名用パスワードを変更します`,
	RunE:  pinChangeJPKISign,
}

func pinChangeJPKISign(cmd *cobra.Command, args []string) error {
	pinName := "JPKI署名用パスワード"
	pin, _ := cmd.Flags().GetString("pin")
	if pin == "" {
		fmt.Printf("現在の%s: ", pinName)
		input, err := gopass.GetPasswdMasked()
		if err != nil {
			return nil
		}
		pin = string(input)
	}
	newpin, _ := cmd.Flags().GetString("newpin")
	if newpin == "" {
		fmt.Printf("新しい%s: ", pinName)
		input, err := gopass.GetPasswdMasked()
		if err != nil {
			return nil
		}
		newpin = string(input)
	}
	err := libmyna.ChangeJPKISignPin(&ctx, pin, newpin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: %s", err)
		return err
	}
	fmt.Printf("%sを変更しました", pinName)
	return nil
}

func init() {
	pinCmd.AddCommand(pinStatusCmd)
	pinCmd.AddCommand(pinChangeCmd)

	pinChangeCardCmd.Flags().String("pin", "", "現在の暗証番号(4桁)")
	pinChangeCardCmd.Flags().String("newpin", "", "新しい暗証番号(4桁)")
	pinChangeCmd.AddCommand(pinChangeCardCmd)

	pinChangeJPKIAuthCmd.Flags().String("pin", "", "現在の暗証番号(4桁)")
	pinChangeJPKIAuthCmd.Flags().String("newpin", "", "新しい暗証番号(4桁)")
	pinChangeCmd.AddCommand(pinChangeJPKIAuthCmd)

	pinChangeJPKISignCmd.Flags().String("pin", "", "現在のパスワード")
	pinChangeJPKISignCmd.Flags().String("newpin", "", "新しいパスワード")
	pinChangeCmd.AddCommand(pinChangeJPKISignCmd)
}
