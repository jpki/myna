package main

import (
	"fmt"
	"github.com/jpki/myna/libmyna"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

type AboutDialog struct {
	*widgets.QDialog
}

func NewAboutDialog() *AboutDialog {
	windowFlag := core.Qt__Window | core.Qt__WindowCloseButtonHint
	dialog := widgets.NewQDialog(nil, windowFlag)
	dialog.SetModal(true)
	dialog.SetMinimumSize2(400, 0)
	dialog.SetWindowTitle("マイナクライアント(GUI版)について")
	layout := widgets.NewQVBoxLayout()
	// add logo
	logoLabel := widgets.NewQLabel(nil, 0)
	logoData, err := Asset("usagi.png")
	if err != nil {
		return nil
	}
	pixmap := gui.NewQPixmap()
	pixmap.LoadFromData(string(logoData), uint(len(logoData)),
		"PNG", core.Qt__AutoColor)
	logoLabel.SetPixmap(pixmap)
	layout.AddWidget(logoLabel, 0, core.Qt__AlignCenter)

	// add version
	label := widgets.NewQLabel2(
		fmt.Sprintf("mynaqt %s", libmyna.Version), nil, 0)
	layout.AddWidget(label, 0, core.Qt__AlignCenter)

	// add url
	url := "https://github.com/jpki/myna"
	urlButton := widgets.NewQPushButton2(url, nil)
	urlButton.ConnectClicked(func(bool) {
		gui.QDesktopServices_OpenUrl(core.NewQUrl3(url, 0))
	})
	layout.AddWidget(urlButton, 0, 0)

	label = widgets.NewQLabel2(
		`
このソフトウェアはMITライセンスで開発されています。
Qt は LGPLライセンス
かわいいウサギのイラストはいらすとやの著作物です`, nil, 0)
	layout.AddWidget(label, 0, 0)
	buttons := widgets.NewQDialogButtonBox(nil)
	closeButton := widgets.NewQPushButton2("閉じる", nil)
	closeButton.ConnectClicked(func(bool) { dialog.Close() })
	buttons.AddButton(closeButton, widgets.QDialogButtonBox__RejectRole)
	layout.AddWidget(buttons, 0, 0)
	dialog.SetLayout(layout)
	return &AboutDialog{dialog}
}
