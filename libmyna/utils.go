package libmyna

import (
	"encoding/hex"
	"errors"
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

func ReadASN1Length(data []byte) (int, int, error) {
	tagsize := 1
	if len(data) < 2 {
		return 0, 0, errors.New("few data size")
	}
	if data[0]&0x1f == 0x1f {
		tagsize++
		if len(data) < 2 || data[1]&0x80 != 0 {
			return 0, 0, errors.New("unexpected tag size")
		}
	}

	offset := tagsize
	if offset >= len(data) {
		return 0, 0, errors.New("few data size")
	}

	b := data[offset]

	offset++
	var length int
	if b&0x80 == 0 {
		length = int(b)
	} else {
		lol := int(b & 0x7f)
		length = 0
		for i := 0; i < lol; i++ {
			if offset >= len(data) {
				return 0, 0, errors.New("truncated tag or length")
			}
			b = data[offset]
			offset++
			length <<= 8
			length |= int(b)
		}
	}

	return offset, length, nil
}
