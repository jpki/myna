package libmyna

import (
	"encoding/hex"
	"strconv"
	"strings"
)

func ToBytes(s string) []byte {
	b, _ := hex.DecodeString(strings.Replace(s, " ", "", -1))
	return b
}

func ToHexString(b []byte) string {
	s := hex.EncodeToString(b)
	return s
}

func ToISO5218String(value string) string {
	n, err := strconv.Atoi(value)
	if err != nil {
		return "エラー"
	}
	if n == 1 {
		return "男性"
	} else if n == 2 {
		return "女性"
	} else if n == 9 {
		return "適用不能"
	} else {
		return "不明"
	}
}
