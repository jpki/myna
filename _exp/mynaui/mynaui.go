package main

import (
	"fmt"
	"github.com/andlabs/ui"
	"github.com/jpki/myna/libmyna"
	"github.com/spf13/cobra"
	"os"
)

var window *ui.Window

var rootCmd = &cobra.Command{
	Use:   "mynaui",
	Short: fmt.Sprintf("マイナクライアント(GUI) - %s", libmyna.Version),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		libmyna.Debug, _ = cmd.Flags().GetBool("debug")
	},
	Run: func(cmd *cobra.Command, args []string) {
		err := ui.Main(uiMain)
		if err != nil {
			panic(err)
		}
	},
}

func main() {
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "デバッグ出力")
	rootCmd.Execute()
}

func uiMain() {
	label := ui.NewLabel("マイナクライアント")
	buttonCheck := ui.NewButton("動作確認")
	buttonCardInfo := ui.NewButton("券面事項確認")
	buttonCardInfo.OnClicked(onClickCardInfo)
	buttonShowCert := ui.NewButton("証明書表示")
	buttonShowCert.OnClicked(onClickShowCert)
	buttonSign := ui.NewButton("署名")
	buttonSign.OnClicked(onClickSign)
	buttonPinStatus := ui.NewButton("PINステータス")
	buttonPinStatus.OnClicked(onClickPinStatus)
	buttonQuit := ui.NewButton("終了")
	buttonQuit.OnClicked(onClickQuit)

	box := ui.NewVerticalBox()
	box.SetPadded(true)
	box.Append(label, true)
	box.Append(buttonCheck, true)
	box.Append(buttonCardInfo, true)
	box.Append(buttonShowCert, true)
	box.Append(buttonSign, true)
	box.Append(buttonPinStatus, true)
	box.Append(buttonQuit, true)
	window = ui.NewWindow("マイナクライアント", 1, 1, true)
	window.SetMargined(true)
	window.SetChild(box)
	buttonCheck.OnClicked(onClickCheck)

	/*
		button1.OnClicked(func(*ui.Button) {
		})
		button2.OnClicked(func(*ui.Button) {
			ui.OpenFile(window)
			//status.SetText("Button2")
		})
	*/
	window.OnClosing(func(*ui.Window) bool {
		ui.Quit()
		return true
	})
	window.Show()
}

func showPinPrompt() string {
	promptWindow := ui.NewWindow("暗証番号(4桁)", 1, 1, false)
	promptWindow.OnClosing(func(*ui.Window) bool {
		return true
	})
	box := ui.NewVerticalBox()
	box.SetPadded(true)

	entry := ui.NewEntry()
	var text string
	buttonAuth := ui.NewButton("認証")
	buttonAuth.OnClicked(func(*ui.Button) {
		text = entry.Text()
		promptWindow.Destroy()
	})
	box.Append(entry, true)
	box.Append(buttonAuth, true)

	promptWindow.SetChild(box)
	promptWindow.SetMargined(true)
	promptWindow.Show()
	fmt.Printf("text: %v\n", text)
	return text
}

func onClickCheck(b *ui.Button) {
	b.Disable()
	defer b.Enable()
	err := libmyna.CheckCard()
	if err != nil {
		ui.MsgBoxError(window, "エラー", err.Error())
		return
	}
	ui.MsgBox(window, "動作確認", "問題ありません。")
}

func onClickCardInfo(b *ui.Button) {
	b.Disable()
	defer b.Enable()

	pin := showPinPrompt()

	fmt.Printf("pin: %s\n", pin)
	/*
		err := libmyna.CheckCard(c)
		if err != nil {
			ui.MsgBoxError(window, "エラー", err.Error())
			return
		}
	*/
}

func onClickShowCert(b *ui.Button) {
	window.Disable()
	defer window.Enable()
	selectCertWindow := ui.NewWindow("証明書選択", 1, 1, false)
	selectCertWindow.OnClosing(func(*ui.Window) bool {
		return true
	})
	buttonShowAuthCert := ui.NewButton("認証用証明")
	buttonShowSignCert := ui.NewButton("署名用証明書")
	buttonShowAuthCACert := ui.NewButton("認証用CA証明")
	buttonShowSignCACert := ui.NewButton("署名用CA証明書")

	box := ui.NewVerticalBox()
	box.SetPadded(true)
	box.Append(buttonShowAuthCert, true)
	box.Append(buttonShowSignCert, true)
	box.Append(buttonShowAuthCACert, true)
	box.Append(buttonShowSignCACert, true)
	selectCertWindow.SetChild(box)
	selectCertWindow.SetMargined(true)
	selectCertWindow.Show()
}

func onClickSign(b *ui.Button) {
	os.Exit(0)
}

func onClickPinStatus(b *ui.Button) {
	b.Disable()
	defer b.Enable()
	status, err := libmyna.GetPinStatus()
	if err != nil {
		ui.MsgBoxError(window, "エラー", err.Error())
		return
	}
	var msg string
	msg += fmt.Sprintf("認証用PIN: のこり%d回\n", status["auth"])
	msg += fmt.Sprintf("署名用PIN: のこり%d回\n", status["sign"])
	msg += fmt.Sprintf("券面入力補助PIN: のこり%d回\n", status["card"])
	msg += fmt.Sprintf("謎のPIN1: のこり%d回\n", status["unknown1"])
	msg += fmt.Sprintf("謎のPIN2: のこり%d回", status["unknown2"])
	ui.MsgBox(window, "PINステータス", msg)
}

func onClickQuit(b *ui.Button) {
	ui.Quit()
}
