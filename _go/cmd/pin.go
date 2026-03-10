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
}

var pinStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "PINステータスを表示",
	RunE:    pinStatus,
	PreRunE: checkCard,
}

func pinStatus(cmd *cobra.Command, args []string) error {
	status, err := libmyna.GetPinStatus()
	if err != nil {
		return err
	}

	if visual_pin_a, ok := status["visual_pin_a"]; ok {
		fmt.Printf("券面事項PIN(A):\tのこり%2d回\n", visual_pin_a)
	}
	if visual_pin_b, ok := status["visual_pin_b"]; ok {
		fmt.Printf("券面事項PIN(B):\tのこり%2d回\n", visual_pin_b)
	}
	if text_pin, ok := status["text_pin"]; ok {
		fmt.Printf("入力補助PIN:\tのこり%2d回\n", text_pin)
	}
	if text_pin_a, ok := status["text_pin_a"]; ok {
		fmt.Printf("入力補助PIN(A):\tのこり%2d回\n", text_pin_a)
	}
	if text_pin_b, ok := status["text_pin_b"]; ok {
		fmt.Printf("入力補助PIN(B):\tのこり%2d回\n", text_pin_b)
	}
	if jpki_auth, ok := status["jpki_auth"]; ok {
		fmt.Printf("JPKI認証用PIN:\tのこり%2d回\n", jpki_auth)
	}
	if jpki_sign, ok := status["jpki_sign"]; ok {
		fmt.Printf("JPKI署名用PIN:\tのこり%2d回\n", jpki_sign)
	}
	return nil
}

var pinChangeCmd = &cobra.Command{
	Use:   "change",
	Short: "各種PINを変更",
}

var pinChangeCardCmd = &cobra.Command{
	Use:   "card",
	Short: "券面入力補助用PINを変更",
	Long: `券面入力補助用PINを変更します
暗証番号は4桁の数字を入力してください
`,
	RunE: pinChangeCard,
}

func pinChangeCard(cmd *cobra.Command, args []string) error {
	fmt.Println(cmd.Long)
	pinName := "券面入力補助用PIN(4桁)"
	pin, err := cmd.Flags().GetString("pin")
	if pin == "" {
		pin, err = inputPin(fmt.Sprintf("現在の%s: ", pinName))
		if err != nil {
			return nil
		}
	}

	newpin, err := cmd.Flags().GetString("newpin")
	if newpin == "" {
		newpin, err = inputPin(fmt.Sprintf("新しい%s: ", pinName))
		if err != nil {
			return nil
		}
	}

	err = libmyna.ChangeCardInputHelperPin(pin, newpin)
	if err != nil {
		return err
	}
	fmt.Printf("%sを変更しました", pinName)
	return nil
}

var pinChangeJPKIAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "JPKI認証用PINを変更",
	Long: `JPKI認証用PINを変更します
暗証番号は4桁の数字を入力してください
`,
	RunE: pinChangeJPKIAuth,
}

func pinChangeJPKIAuth(cmd *cobra.Command, args []string) error {
	fmt.Println(cmd.Long)
	pinName := "JPKI認証用PIN(4桁)"
	pin, err := cmd.Flags().GetString("pin")
	if pin == "" {
		pin, err = inputPin(fmt.Sprintf("現在の%s: ", pinName))
		if err != nil {
			return nil
		}
	}

	newpin, _ := cmd.Flags().GetString("newpin")
	if newpin == "" {
		newpin, err = inputPin(fmt.Sprintf("新しい%s: ", pinName))
		if err != nil {
			return nil
		}
	}

	err = libmyna.ChangeJPKIAuthPin(pin, newpin)
	if err != nil {
		return err
	}
	fmt.Printf("%sを変更しました", pinName)
	return nil
}

var pinChangeJPKISignCmd = &cobra.Command{
	Use:   "sign",
	Short: "JPKI署名用パスワードを変更",
	Long: `JPKI署名用パスワードを変更します
パスワードに利用できる文字種は以下のとおり

ABCDEFGHIJKLMNOPQRSTUVWXYZ
0123456789

文字数は6文字から16文字まで
アルファベットは大文字のみ使うことができます。
小文字を入力した場合は、大文字に変換されます。
`,
	RunE: pinChangeJPKISign,
}

func pinChangeJPKISign(cmd *cobra.Command, args []string) error {
	fmt.Println(cmd.Long)
	pinName := "JPKI署名用パスワード(6-16文字)"
	pin, err := cmd.Flags().GetString("pin")
	if pin == "" {
		pin, err = inputPin(fmt.Sprintf("現在の%s: ", pinName))
		if err != nil {
			return nil
		}
	}
	newpin, err := cmd.Flags().GetString("newpin")
	if newpin == "" {
		newpin, err = inputPin(fmt.Sprintf("新しい%s: ", pinName))
		if err != nil {
			return nil
		}
	}
	err = libmyna.ChangeJPKISignPin(pin, newpin)
	if err != nil {
		return err
	}
	fmt.Printf("%sを変更しました", pinName)
	return nil
}

func inputPin(prompt string) (string, error) {
	input, err := gopass.GetPasswdPrompt(prompt, true, os.Stdin, os.Stderr)
	if err != nil {
		return "", err
	}
	pin := string(input)
	return pin, err
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

	pinChangeJPKISignCmd.Flags().String("pin", "", "現在のパスワード(6-16文字)")
	pinChangeJPKISignCmd.Flags().String("newpin", "", "新しいパスワード(6-16文字)")
	pinChangeCmd.AddCommand(pinChangeJPKISignCmd)
}
