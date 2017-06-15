package main

import (
	"github.com/therecipe/qt/widgets"
	"regexp"
	"strings"
)

type PromptDialog struct {
	*widgets.QDialog
	input *widgets.QLineEdit
}

func NewPinPromptDialog() *PromptDialog {
	dialog := widgets.NewQDialog(nil, 0)
	dialog.SetModal(true)
	dialog.SetWindowTitle("暗証番号入力")
	layout := widgets.NewQVBoxLayout()

	label := widgets.NewQLabel2("暗証番号(4桁)を入力してください", nil, 0)
	layout.AddWidget(label, 0, 0)

	input := widgets.NewQLineEdit(nil)
	input.SetPlaceholderText("暗証番号(4桁)")
	input.SetEchoMode(widgets.QLineEdit__Password)
	layout.AddWidget(input, 0, 0)

	buttonBox := widgets.NewQDialogButtonBox(nil)
	closeButton := widgets.NewQPushButton2("閉じる", nil)
	closeButton.ConnectClicked(func(bool) { dialog.Close() })

	okButton := widgets.NewQPushButton2("OK", nil)
	okButton.ConnectClicked(func(bool) {
		pin := input.Text()
		match, _ := regexp.MatchString("^\\d{4}$", pin)
		if !match {
			label.SetStyleSheet("color: red")
			return
		}
		dialog.Accept()
		dialog.Close()
	})

	buttonBox.AddButton(closeButton, widgets.QDialogButtonBox__RejectRole)
	buttonBox.AddButton(okButton, widgets.QDialogButtonBox__AcceptRole)

	layout.AddWidget(buttonBox, 0, 0)
	dialog.SetLayout(layout)
	return &PromptDialog{dialog, input}
}

func NewPasswordPromptDialog() *PromptDialog {
	dialog := widgets.NewQDialog(nil, 0)
	dialog.SetModal(true)
	dialog.SetWindowTitle("パスワード入力")
	layout := widgets.NewQVBoxLayout()

	label := widgets.NewQLabel2("パスワード(6-16桁)を入力してください", nil, 0)
	layout.AddWidget(label, 0, 0)

	input := widgets.NewQLineEdit(nil)
	input.SetPlaceholderText("パスワード(6-16桁)")
	input.SetEchoMode(widgets.QLineEdit__Password)
	layout.AddWidget(input, 0, 0)

	buttons := widgets.NewQDialogButtonBox(nil)
	closeButton := widgets.NewQPushButton2("閉じる", nil)
	closeButton.ConnectClicked(func(bool) { dialog.Close() })

	okButton := widgets.NewQPushButton2("OK", nil)
	okButton.ConnectClicked(func(bool) {
		pin := strings.ToUpper(input.Text())
		match, _ := regexp.MatchString("^[a-zA-Z0-9]{6,16}$", pin)
		if !match {
			label.SetStyleSheet("color: red")
			return
		}
		dialog.Accept()
		dialog.Close()
	})

	buttons.AddButton(closeButton, widgets.QDialogButtonBox__RejectRole)
	buttons.AddButton(okButton, widgets.QDialogButtonBox__AcceptRole)

	layout.AddWidget(buttons, 0, 0)
	dialog.SetLayout(layout)
	return &PromptDialog{dialog, input}
}

func (d *PromptDialog) GetPin() string {
	return strings.ToUpper(d.input.Text())
}
