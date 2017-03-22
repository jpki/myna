package driver

import (
	"fmt"
	"errors"
	"strings"
	"github.com/urfave/cli"
	"encoding/hex"
)

func Check(c *cli.Context) error {
	reader := NewReader(c)
	if reader == nil {
		return errors.New("リーダーが見つかりません。")
	}
	defer reader.Finalize()
	_, err := reader.CheckCard()
	return err
}

func Hello() error {
	fmt.Printf("Hello World\n")
	return nil
}

func ToBytes(s string) []byte {
	b, _ := hex.DecodeString(strings.Replace(s, " ", "", -1))
	return b
}
