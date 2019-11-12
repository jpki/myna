package main

import (
	"github.com/jpki/myna/libmyna"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/widgets"
)

type CmsSignDialog struct {
	*widgets.QDialog
}

func NewCmsSignDialog() *CmsSignDialog {
	windowFlag := core.Qt__Window | core.Qt__WindowCloseButtonHint
	dialog := widgets.NewQDialog(nil, windowFlag)
	dialog.SetModal(true)
	dialog.SetMinimumSize2(500, 0)
	dialog.SetWindowTitle("CMS署名")

	layout := widgets.NewQVBoxLayout()
	layout.AddWidget(widgets.NewQLabel2("入力ファイル", nil, 0), 0, 0)

	row := widgets.NewQHBoxLayout()
	inputFileEdit := widgets.NewQLineEdit(nil)
	outputFileEdit := widgets.NewQLineEdit(nil)
	inputFileEdit.SetReadOnly(true)
	inputFileEdit.SetSizePolicy2(
		widgets.QSizePolicy__Expanding,
		widgets.QSizePolicy__Ignored)
	row.AddWidget(inputFileEdit, 0, 0)
	inputFileButton := widgets.NewQPushButton2("選択", nil)
	inputFileButton.ConnectClicked(func(bool) {
		dialog := widgets.NewQFileDialog2(nil, "入力ファイル", "", "")
		dialog.SetFileMode(widgets.QFileDialog__ExistingFile)
		rc := dialog.Exec()
		if rc != int(widgets.QDialog__Accepted) {
			return
		}
		filename := dialog.SelectedFiles()[0]
		inputFileEdit.SetText(filename)
		if outputFileEdit.Text() == "" {
			outputFileEdit.SetText(filename + ".p7s")
		}
	})
	row.AddWidget(inputFileButton, 0, 0)
	layout.AddLayout(row, 0)

	layout.AddWidget(widgets.NewQLabel2("出力ファイル", nil, 0), 0, 0)
	row = widgets.NewQHBoxLayout()
	outputFileEdit.SetReadOnly(true)
	outputFileEdit.SetSizePolicy2(
		widgets.QSizePolicy__Expanding,
		widgets.QSizePolicy__Ignored)
	row.AddWidget(outputFileEdit, 0, 0)
	outputFileButton := widgets.NewQPushButton2("選択", nil)
	outputFileButton.ConnectClicked(func(bool) {
		dialog := widgets.NewQFileDialog2(nil, "出力ファイル", "", "")
		dialog.SetAcceptMode(widgets.QFileDialog__AcceptSave)
		rc := dialog.Exec()
		if rc != int(widgets.QDialog__Accepted) {
			return
		}
		filename := dialog.SelectedFiles()[0]
		outputFileEdit.SetText(filename)
	})
	row.AddWidget(outputFileButton, 0, 0)
	layout.AddLayout(row, 0)

	buttons := widgets.NewQDialogButtonBox(nil)
	closeButton := widgets.NewQPushButton2("閉じる", nil)
	closeButton.ConnectClicked(func(bool) { dialog.Close() })
	signButton := widgets.NewQPushButton2("署名", nil)
	signButton.ConnectClicked(func(bool) {
		if inputFileEdit.Text() == "" {
			widgets.QMessageBox_Warning(nil, "エラー",
				"入力ファイルを選択してください",
				widgets.QMessageBox__Ok, 0)
			return
		}
		if outputFileEdit.Text() == "" {
			widgets.QMessageBox_Warning(nil, "エラー",
				"出力ファイルを選択してください",
				widgets.QMessageBox__Ok, 0)
			return
		}
		prompt := NewPasswordPromptDialog()
		rc := prompt.Exec()
		if rc != int(widgets.QDialog__Accepted) {
			return
		}
		password := prompt.GetPin()
		err := libmyna.Sign(ctx, password,
			inputFileEdit.Text(), outputFileEdit.Text())
		if err != nil {
			widgets.QMessageBox_Warning(nil, "エラー", err.Error(),
				widgets.QMessageBox__Ok, 0)
			return
		}
		widgets.QMessageBox_Information(nil, "CMS署名",
			"正常に署名しました",
			widgets.QMessageBox__Ok, 0)
		return
		dialog.Close()
	})
	buttons.AddButton(signButton, widgets.QDialogButtonBox__AcceptRole)
	buttons.AddButton(closeButton, widgets.QDialogButtonBox__RejectRole)
	layout.AddWidget(buttons, 0, 0)
	dialog.SetLayout(layout)
	return &CmsSignDialog{dialog}
}
