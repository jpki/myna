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

func ValidateJPKISignPassword(pass string) error {
	if len(pass) < 4 || 16 < len(pass) {
		return errors.New("パスワードの長さが正しくありません")
	}
	match, _ := regexp.MatchString("^[A-Z0-9]+$", pass)
	if !match {
		return errors.New("パスワードの文字種が不正です")
	}
	return nil
}
