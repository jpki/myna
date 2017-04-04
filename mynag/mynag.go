package main

import "github.com/jpki/myna/libmyna"

import (
	"crypto/x509"
	_ "errors"
	"fmt"
	"github.com/mattn/go-gtk/gdkpixbuf"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
	"github.com/urfave/cli"
	"os"
	"strings"
)

func main() {
	app := cli.NewApp()
	app.Name = "mynag"
	app.Usage = "マイナクライアント(GUI)"
	app.Author = "HAMANO Tsukasa"
	app.Email = "hamano@osstech.co.jp"
	app.Version = libmyna.Version
	app.Action = mynag
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "詳細出力",
		},
	}
	app.Run(os.Args)
}

func mynag(c *cli.Context) error {
	gtk.Init(&os.Args)
	window := gtk.NewWindow(gtk.WINDOW_TOPLEVEL)
	window.SetPosition(gtk.WIN_POS_CENTER)
	window.SetTitle(c.App.Usage)
	window.SetIconName("application-certificate")
	window.Connect("destroy", func(ctx *glib.CallbackContext) {
		gtk.MainQuit()
	})

	// create menu
	menu := gtk.NewMenuBar()
	menuHelp := gtk.NewMenuItemWithMnemonic("Menu")
	menu.Append(menuHelp)

	menuSub := gtk.NewMenu()
	menuHelp.SetSubmenu(menuSub)
	menuItemAbout := gtk.NewMenuItemWithMnemonic("About")
	menuItemAbout.Connect("activate", onAbout, c)
	menuSub.Append(menuItemAbout)

	menuItemQuit := gtk.NewMenuItemWithMnemonic("Quit")
	menuItemQuit.Connect("activate", onQuit, c)
	menuSub.Append(menuItemQuit)

	// create button box
	boxButton := gtk.NewVBox(false, 1)
	buttonTest := gtk.NewToggleButtonWithLabel("動作確認")
	buttonTest.Clicked(onTest, c)
	boxButton.Add(buttonTest)

	buttonCardInfo := gtk.NewToggleButtonWithLabel("券面事項確認")
	buttonCardInfo.Clicked(onCardInfo, c)
	boxButton.Add(buttonCardInfo)

	buttonShowCert := gtk.NewToggleButtonWithLabel("証明書表示")
	buttonShowCert.Clicked(onShowCert, c)
	boxButton.Add(buttonShowCert)

	buttonSign := gtk.NewToggleButtonWithLabel("署名")
	buttonSign.Clicked(onSign, c)
	boxButton.Add(buttonSign)

	buttonPinStatus := gtk.NewToggleButtonWithLabel("PINステータス")
	buttonPinStatus.Clicked(onPinStatus, c)
	boxButton.Add(buttonPinStatus)

	// create hbox
	hbox := gtk.NewHBox(false, 1)
	//dir, _ := filepath.Split(os.Args[0])
	//imagefile := filepath.Join(dir, "usagi.png")
	//imageLogo := gtk.NewImageFromFile(imagefile)
	imageData, _ := Asset("usagi.png")
	imageBuf, _ := gdkpixbuf.NewPixbufFromData(imageData)
	imageLogo := gtk.NewImageFromPixbuf(imageBuf)
	hbox.Add(imageLogo)
	hbox.Add(boxButton)

	// create main box
	boxMain := gtk.NewVBox(false, 1)
	boxMain.PackStart(menu, false, false, 0)
	boxMain.Add(hbox)

	window.Add(boxMain)
	//window.SetSizeRequest(400, 400)
	window.ShowAll()
	gtk.Main()
	return nil
}

func onAbout(ctx *glib.CallbackContext) {
	c := ctx.Data().(*cli.Context)
	dialog := gtk.NewAboutDialog()
	dialog.SetName("About")
	dialog.SetProgramName(c.App.Name)
	dialog.SetAuthors([]string{c.App.Author})
	//dialog.SetLicense("ライセンス")
	dialog.SetWrapLicense(true)
	dialog.Run()
	dialog.Destroy()
}

func onQuit(ctx *glib.CallbackContext) {
	_ = ctx.Data().(*cli.Context)
	gtk.MainQuit()
}

func showErrorMsg(msg string) {
	dialog := gtk.NewMessageDialog(
		nil,
		gtk.DIALOG_MODAL,
		gtk.MESSAGE_INFO,
		gtk.BUTTONS_OK,
		msg)
	dialog.Response(func() {
		dialog.Destroy()
	})
	dialog.Run()
}

func showMsg(msg string) {
	dialog := gtk.NewMessageDialog(
		nil,
		gtk.DIALOG_MODAL,
		gtk.MESSAGE_INFO,
		gtk.BUTTONS_OK,
		msg)
	dialog.Response(func() {
		dialog.Destroy()
	})
	dialog.Run()
}

func onTest(ctx *glib.CallbackContext) {
	c := ctx.Data().(*cli.Context)
	err := libmyna.CheckCard(c)
	var msg string
	if err != nil {
		msg = err.Error()
	} else {
		msg = "正常です。"
	}
	showErrorMsg(msg)
}

func popupPrompt(title string) string {
	dialog := gtk.NewDialog()
	dialog.SetTitle(title)
	vbox := dialog.GetVBox()
	label := gtk.NewLabel(title)
	vbox.Add(label)
	pinEntry := gtk.NewEntry()
	pinEntry.SetVisibility(false)
	pinEntry.Connect("activate", func() {
		dialog.Hide()
		dialog.Response(gtk.RESPONSE_OK)
	})
	vbox.Add(pinEntry)
	dialog.AddButton(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL)
	dialog.AddButton(gtk.STOCK_OK, gtk.RESPONSE_OK)
	dialog.SetDefaultResponse(gtk.RESPONSE_OK)
	dialog.ShowAll()
	res := dialog.Run()
	pin := pinEntry.GetText()
	dialog.Destroy()
	if res == gtk.RESPONSE_OK {
		return pin
	} else {
		return ""
	}
}

func popupPinPrompt() string {
	return popupPrompt("暗証番号(4桁)")
}

func popupPasswordPrompt() string {
	pass := popupPrompt("署名用パスワード(6-16桁)")
	if len(pass) < 6 || 16 < len(pass) {
		showErrorMsg("署名用パスワード(6-16桁)を入力してください。")
		return ""
	}
	return strings.ToUpper(pass)
}

func onCardInfo(ctx *glib.CallbackContext) {
	c := ctx.Data().(*cli.Context)
	err := libmyna.CheckCard(c)
	if err != nil {
		showErrorMsg(err.Error())
		return
	}
	pin := popupPinPrompt()
	if pin == "" {
		return
	}
	info, _ := libmyna.GetCardInfo(c, pin)
	var msg string
	msg += fmt.Sprintf("個人番号: %s\n", info["number"])
	msg += fmt.Sprintf("氏名:     %s\n", info["name"])
	msg += fmt.Sprintf("住所:     %s\n", info["address"])
	msg += fmt.Sprintf("生年月日: %s\n", info["birth"])
	msg += fmt.Sprintf("性別:     %s", info["sex"])
	showMsg(msg)
}

func onPinStatus(ctx *glib.CallbackContext) {
	c := ctx.Data().(*cli.Context)
	status, _ := libmyna.GetPinStatus(c)
	var msg string
	msg += fmt.Sprintf("認証用PIN: のこり%d回\n", status["auth"])
	msg += fmt.Sprintf("署名用PIN: のこり%d回\n", status["sign"])
	msg += fmt.Sprintf("券面入力補助PIN: のこり%d回\n", status["card"])
	msg += fmt.Sprintf("謎のPIN1: のこり%d回\n", status["unknown1"])
	msg += fmt.Sprintf("謎のPIN2: のこり%d回", status["unknown2"])
	showMsg(msg)
}

func onShowCert(ctx *glib.CallbackContext) {
	c := ctx.Data().(*cli.Context)
	rc := selectCert()
	var title string
	var ef string
	var pin string
	switch rc {
	case 0:
		// キャンセル
		return
	case 1:
		title = "認証用証明書"
		ef = "00 0A"
	case 2:
		title = "署名用証明書"
		ef = "00 01"
		pin = popupPasswordPrompt()
		if pin == "" {
			return
		}
	case 3:
		title = "認証用CA証明書"
		ef = "00 0B"
	case 4:
		title = "署名用CA証明書"
		ef = "00 02"
	}
	cert, err := libmyna.GetCert(c, ef, pin)
	if err != nil {
		showErrorMsg(err.Error())
		return
	}
	popupCertDialog(title, cert)
}

func popupCertDialog(title string, cert *x509.Certificate) {
	dialog := gtk.NewDialog()
	defer dialog.Destroy()
	dialog.SetTitle(title)
	vbox := dialog.GetVBox()

	vbox.PackStart(gtk.NewLabel("Subject: "), false, false, 10)
	subjectEntry := gtk.NewEntry()
	subjectEntry.SetText(libmyna.Name2String(cert.Subject))
	subjectEntry.SetWidthChars(64)
	vbox.PackStart(subjectEntry, false, false, 10)
	vbox.PackStart(gtk.NewLabel("Issuer: "), false, false, 10)
	issuerEntry := gtk.NewEntry()
	issuerEntry.SetText(libmyna.Name2String(cert.Issuer))
	issuerEntry.SetWidthChars(64)
	vbox.PackStart(issuerEntry, false, false, 10)
	dialog.AddButton(gtk.STOCK_OK, gtk.RESPONSE_OK)
	dialog.ShowAll()
	dialog.Run()
}

func selectCert() int {
	dialog := gtk.NewDialog()
	defer dialog.Destroy()
	dialog.SetTitle("証明書選択")
	vbox := dialog.GetVBox()
	radio1 := gtk.NewRadioButtonWithLabel(nil, "認証用証明書")
	radio2 := gtk.NewRadioButtonWithLabel(radio1.GetGroup(), "署名用証明書")
	radio3 := gtk.NewRadioButtonWithLabel(radio1.GetGroup(), "認証用CA証明書")
	radio4 := gtk.NewRadioButtonWithLabel(radio1.GetGroup(), "署名用CA証明書")

	vbox.PackStart(radio1, false, false, 10)
	vbox.PackStart(radio2, false, false, 10)
	vbox.PackStart(radio3, false, false, 10)
	vbox.PackStart(radio4, false, false, 10)

	dialog.AddButton(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL)
	dialog.AddButton(gtk.STOCK_OK, gtk.RESPONSE_OK)
	dialog.SetDefaultResponse(gtk.RESPONSE_OK)
	dialog.ShowAll()
	res := dialog.Run()
	if res == gtk.RESPONSE_OK {
		if radio1.GetActive() {
			return 1
		} else if radio2.GetActive() {
			return 2
		} else if radio3.GetActive() {
			return 3
		} else if radio4.GetActive() {
			return 4
		} else {
			return 0
		}
	} else {
		return 0
	}
}

func onSign(ctx *glib.CallbackContext) {
	//c := ctx.Data().(*cli.Context)
	showErrorMsg("署名")
}
