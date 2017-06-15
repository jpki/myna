package main

import (
	"crypto/x509"
	"github.com/jpki/myna/libmyna"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/widgets"
)

type SelectCertDialog struct {
	*widgets.QDialog
}

func NewSelectCertDialog() *SelectCertDialog {
	windowFlag := core.Qt__Window | core.Qt__WindowCloseButtonHint
	dialog := widgets.NewQDialog(nil, windowFlag)
	dialog.SetModal(true)
	dialog.SetMinimumSize2(300, 300)
	dialog.SetWindowTitle("証明書選択")

	radio1 := widgets.NewQRadioButton2("認証用証明書", nil)
	radio2 := widgets.NewQRadioButton2("署名用証明書", nil)
	radio3 := widgets.NewQRadioButton2("認証用CA証明書", nil)
	radio4 := widgets.NewQRadioButton2("署名用CA証明書", nil)
	radio1.SetChecked(true)

	layout := widgets.NewQVBoxLayout()
	layout.AddWidget(radio1, 0, 0)
	layout.AddWidget(radio2, 0, 0)
	layout.AddWidget(radio3, 0, 0)
	layout.AddWidget(radio4, 0, 0)

	group := widgets.NewQButtonGroup(nil)
	group.AddButton(radio1, 1)
	group.AddButton(radio2, 2)
	group.AddButton(radio3, 3)
	group.AddButton(radio4, 4)

	buttons := widgets.NewQDialogButtonBox(nil)
	closeButton := widgets.NewQPushButton2("閉じる", nil)
	closeButton.ConnectClicked(func(bool) { dialog.Close() })

	showButton := widgets.NewQPushButton2("表示", nil)
	showButton.ConnectClicked(func(bool) {
		id := group.CheckedId()
		var name string
		var ef string
		var password string
		if id == 1 {
			name = "認証用証明書"
			ef = "00 0A"
		} else if id == 2 {
			name = "署名用証明書"
			ef = "00 01"
			prompt := NewPasswordPromptDialog()
			rc := prompt.Exec()
			if rc != int(widgets.QDialog__Accepted) {
				return
			}
			password = prompt.GetPin()
		} else if id == 3 {
			name = "認証用CA証明書"
			ef = "00 0B"
		} else if id == 4 {
			name = "署名用CA証明書"
			ef = "00 02"
		} else {
			return
		}

		cert, err := libmyna.GetCert(ctx, ef, password)
		if err != nil {
			widgets.QMessageBox_Warning(nil, "エラー", err.Error(),
				widgets.QMessageBox__Ok, 0)
			return
		}
		certDialog := NewShowCertDialog(name, cert)
		certDialog.Show()
	})

	buttons.AddButton(closeButton, widgets.QDialogButtonBox__RejectRole)
	buttons.AddButton(showButton, widgets.QDialogButtonBox__AcceptRole)
	layout.AddWidget(buttons, 0, 0)
	dialog.SetLayout(layout)
	return &SelectCertDialog{dialog}
}

type ShowCertDialog struct {
	*widgets.QDialog
}

func NewShowCertDialog(name string, cert *x509.Certificate) *ShowCertDialog {
	if cert == nil {
		widgets.QMessageBox_Warning(nil, "エラー", "証明書がみつかりません",
			widgets.QMessageBox__Ok, 0)
		return nil
		/*
			data, _ := ioutil.ReadFile("../test.pem")
			block, _ := pem.Decode(data)
			cert, _ = x509.ParseCertificate(block.Bytes)
		*/
	}

	windowFlag := core.Qt__Window | core.Qt__WindowCloseButtonHint
	dialog := widgets.NewQDialog(nil, windowFlag)
	dialog.SetModal(true)
	dialog.SetWindowTitle("証明書ビューア: " + name)
	dialog.SetMinimumSize2(600, 400)

	layout := widgets.NewQVBoxLayout()
	labelSubject := widgets.NewQLabel2("発行先", nil, 0)
	layout.AddWidget(labelSubject, 0, 0)
	textSubject := widgets.NewQLineEdit(dialog)
	textSubject.SetReadOnly(true)
	textSubject.SetText(libmyna.Name2String(cert.Subject))
	textSubject.AdjustSize()
	layout.AddWidget(textSubject, 0, 0)

	labelIssuer := widgets.NewQLabel2("発行元", nil, 0)
	layout.AddWidget(labelIssuer, 0, 0)
	textIssuer := widgets.NewQLineEdit(nil)
	textIssuer.SetReadOnly(true)
	textIssuer.SetText(libmyna.Name2String(cert.Issuer))
	layout.AddWidget(textIssuer, 0, 0)

	labelNotBefore := widgets.NewQLabel2("発行日", nil, 0)
	layout.AddWidget(labelNotBefore, 0, 0)
	textNotBefore := widgets.NewQLineEdit(nil)
	textNotBefore.SetReadOnly(true)
	textNotBefore.SetText(cert.NotBefore.Local().String())
	layout.AddWidget(textNotBefore, 0, 0)

	labelNotAfter := widgets.NewQLabel2("有効期限", nil, 0)
	layout.AddWidget(labelNotAfter, 0, 0)
	textNotAfter := widgets.NewQLineEdit(nil)
	textNotAfter.SetReadOnly(true)
	textNotAfter.SetText(cert.NotAfter.Local().String())
	layout.AddWidget(textNotAfter, 0, 0)

	buttons := widgets.NewQDialogButtonBox(nil)
	closeButton := widgets.NewQPushButton2("閉じる", nil)
	closeButton.ConnectClicked(func(bool) { dialog.Close() })
	buttons.AddButton(closeButton, widgets.QDialogButtonBox__RejectRole)
	layout.AddWidget(buttons, 0, 0)

	dialog.SetLayout(layout)
	return &ShowCertDialog{dialog}
}
