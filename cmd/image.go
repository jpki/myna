package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var imageCmd = &cobra.Command{
	Use:   "image",
	Short: "券面確認AP",
}

var cardFrontPhotoCmd = &cobra.Command{
	Use:     "photo -o [output.jpg|-]",
	Short:   "券面確認APの顔写真を取得",
	RunE:    showCardFrontPhoto,
	PreRunE: checkCard,
}

func showCardFrontPhoto(cmd *cobra.Command, args []string) error {
	output, err := cmd.Flags().GetString("output")
	if output == "" {
		cmd.Usage()
		return nil
	}
	pin, err := cmd.Flags().GetString("pin")
	if pin == "" {
		pin, err = inputPin("暗証番号(4桁): ")
		if err != nil {
			return nil
		}
	}
	err = libmyna.Validate4DigitPin(pin)
	if err != nil {
		return err
	}

	mynumber, err := libmyna.GetMyNumber(pin)
	if err != nil {
		return err
	}

	info, err := libmyna.GetImageInfo(mynumber)
	if err != nil {
		return err
	}

	var file *os.File
	if output == "-" {
		file = os.Stdout
	} else {
		file, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		defer file.Close()
		if err != nil {
			return err
		}
	}

	file.Write(info.Photo)
	return nil
}

func init() {
	imageCmd.AddCommand(cardFrontPhotoCmd)
	cardFrontPhotoCmd.Flags().StringP("pin", "p", "", "暗証番号(4桁)")
	cardFrontPhotoCmd.Flags().StringP("output", "o", "", "出力ファイル(JPEG2000)")
}
