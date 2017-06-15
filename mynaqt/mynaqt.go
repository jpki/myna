package main

import (
	_ "bytes"
	_ "errors"
	"fmt"
	"github.com/jpki/myna/libmyna"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
	"github.com/urfave/cli"
	"os"
)

func main() {
	app := cli.NewApp()
	app.Name = "mynaqt"
	app.Description = "マイナクライアント(GUI)"
	app.Author = "HAMANO Tsukasa"
	app.Email = "hamano@osstech.co.jp"
	app.Version = libmyna.Version
	app.Action = mynaqt
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "詳細出力",
		},
	}
	app.Run(os.Args)
}

var ctx *cli.Context

func mynaqt(c *cli.Context) error {
	ctx = c
	app := widgets.NewQApplication(len(os.Args), os.Args)
	core.QCoreApplication_SetApplicationName(c.App.Name)
	core.QCoreApplication_SetApplicationVersion(c.App.Version)

	window := widgets.NewQMainWindow(nil, 0)
	window.SetWindowTitle(c.App.Description)
	window.SetMinimumSize2(500, 0)
	menu := window.MenuBar().AddMenu2("Menu")
	actionAbout := menu.AddAction("About")
	actionAbout.ConnectTriggered(func(checked bool) {
		NewAboutDialog().Show()
	})
	actionQuit := menu.AddAction("終了")
	actionQuit.ConnectTriggered(func(checked bool) {
		window.Close()
	})

	hBox := widgets.NewQHBoxLayout()
	vBox := widgets.NewQVBoxLayout()
	logoLabel := widgets.NewQLabel(nil, 0)
	logoData, err := Asset("usagi.png")
	if err != nil {
		return err
	}
	pixmap := gui.NewQPixmap()
	pixmap.LoadFromData(string(logoData), uint(len(logoData)),
		"PNG", core.Qt__AutoColor)
	logoLabel.SetPixmap(pixmap)

	hBox.AddWidget(logoLabel, 0, 0)
	hBox.AddLayout(vBox, 1)

	widget := widgets.NewQWidget(nil, 0)
	widget.SetLayout(hBox)

	buttonCardCheck := widgets.NewQPushButton2("動作確認", widget)
	buttonCardCheck.ConnectClicked(onCardCheck)
	vBox.AddWidget(buttonCardCheck, 0, 0)

	buttonCardInfo := widgets.NewQPushButton2("券面事項確認", widget)
	buttonCardInfo.ConnectClicked(onCardInfo)
	vBox.AddWidget(buttonCardInfo, 0, 0)

	buttonShowCert := widgets.NewQPushButton2("証明書表示", widget)
	buttonShowCert.ConnectClicked(onShowCert)
	vBox.AddWidget(buttonShowCert, 0, 0)

	buttonCmsSign := widgets.NewQPushButton2("CMS署名", widget)
	buttonCmsSign.ConnectClicked(onCmsSign)
	vBox.AddWidget(buttonCmsSign, 0, 0)

	buttonPinStatus := widgets.NewQPushButton2("PINステータス", widget)
	buttonPinStatus.ConnectClicked(onPinStatus)
	vBox.AddWidget(buttonPinStatus, 0, 0)

	window.SetCentralWidget(widget)
	window.Show()
	app.Exec()
	return nil
}

func onCardCheck(checked bool) {
	err := libmyna.CheckCard(ctx)
	if err != nil {
		widgets.QMessageBox_Warning(nil, "エラー", err.Error(),
			widgets.QMessageBox__Ok, 0)
	} else {
		widgets.QMessageBox_Information(nil, "動作確認", "正常です",
			widgets.QMessageBox__Close, 0)
	}
}

func onCardInfo(checked bool) {
	prompt := NewPinPromptDialog()
	rc := prompt.Exec()
	if rc != int(widgets.QDialog__Accepted) {
		return
	}

	pin := prompt.GetPin()
	info, err := libmyna.GetCardInfo(ctx, pin)
	if err != nil {
		widgets.QMessageBox_Warning(nil, "エラー", err.Error(),
			widgets.QMessageBox__Ok, 0)
		return
	}
	var msg string
	msg += fmt.Sprintf("個人番号: %s\n", info["number"])
	msg += fmt.Sprintf("氏名:     %s\n", info["name"])
	msg += fmt.Sprintf("住所:     %s\n", info["address"])
	msg += fmt.Sprintf("生年月日: %s\n", info["birth"])
	msg += fmt.Sprintf("性別:     %s", info["sex"])
	widgets.QMessageBox_Information(nil, "券面事項確認", msg,
		widgets.QMessageBox__Close, 0)
}

func onShowCert(checked bool) {
	dialog := NewSelectCertDialog()
	dialog.Show()
}

func onPinStatus(checked bool) {
	status, err := libmyna.GetPinStatus(ctx)
	if err != nil {
		widgets.QMessageBox_Warning(nil, "エラー", err.Error(),
			widgets.QMessageBox__Ok, 0)
		return
	}
	var msg string
	msg += fmt.Sprintf("認証用PIN: のこり%d回\n", status["auth"])
	msg += fmt.Sprintf("署名用PIN: のこり%d回\n", status["sign"])
	msg += fmt.Sprintf("券面入力補助PIN: のこり%d回\n", status["card"])
	msg += fmt.Sprintf("謎のPIN1: のこり%d回\n", status["unknown1"])
	msg += fmt.Sprintf("謎のPIN2: のこり%d回", status["unknown2"])
	widgets.QMessageBox_Information(nil, "PINステータス", msg,
		widgets.QMessageBox__Ok, 0)
}

func onCmsSign(checked bool) {
	dialog := NewCmsSignDialog()
	dialog.Show()
}
