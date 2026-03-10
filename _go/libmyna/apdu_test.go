package libmyna

import (
	_ "fmt"
	"reflect"
	"testing"
)

var invalidAPDU = []string{
	"",
	"FF",
	"FF FF",
	"FF FF FF",
}

func TestNewAPDUInvalid(t *testing.T) {
	for _, s := range invalidAPDU {
		_, err := NewAPDU(s)
		if err == nil {
			t.Errorf("NewAPDU should fail: %s", s)
		}
	}
}

var validAPDU = []string{
	"00 00 00 00",
	"FF FF FF FF",
}

func TestNewAPDU(t *testing.T) {
	for _, s := range validAPDU {
		apdu, err := NewAPDU(s)
		if err != nil {
			t.Error(err)
		}
		if s != apdu.ToString() {
			t.Errorf("%s != %s", s, apdu.ToString())
		}
	}
}

var validAPDUCase1 = [][]byte{
	{0x00, 0x00, 0x00, 0x00},
}

func TestNewAPDUCase1(t *testing.T) {
	for _, cmd := range validAPDUCase1 {
		apdu := NewAPDUCase1(cmd[0], cmd[1], cmd[2], cmd[3])
		if !reflect.DeepEqual(cmd, apdu.cmd) {
			t.Errorf("% X != % X", cmd, apdu.cmd)
		}
	}
}
