package libmyna

import (
	"errors"
	"regexp"
)

func Validate4DigitPin(pin string) error {
	match, _ := regexp.MatchString("^\\d{4}$", pin)
	if !match {
		return errors.New("暗証番号(4桁)を入力してください。")
	}
	return nil
}
