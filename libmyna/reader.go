package libmyna

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ebfe/scard"
)

type Reader struct {
	ctx   *scard.Context
	name  string
	card  *scard.Card
	debug bool
}

func NewReader() (*Reader, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, err
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		return nil, err
	}

	if len(readers) == 0 {
		return nil, fmt.Errorf("リーダーが見つかりません")
	}

	if len(readers) >= 2 {
		fmt.Fprintf(os.Stderr,
			"警告: 複数のリーダーが見つかりました。最初のものを使います\n")
	}

	reader := new(Reader)
	reader.ctx = ctx
	reader.name = readers[0]
	reader.card = nil
	return reader, nil
}

func (self *Reader) SetDebug(debug bool) {
	self.debug = debug
}

func (self *Reader) Finalize() {
	self.ctx.Release()
}

func (self *Reader) GetCard() *scard.Card {
	card, _ := self.ctx.Connect(
		self.name, scard.ShareExclusive, scard.ProtocolAny)
	self.card = card
	return card
}

func (self *Reader) Connect() error {
	rs := make([]scard.ReaderState, 1)
	rs[0].Reader = self.name
	rs[0].CurrentState = scard.StateUnaware // no need
	var err error
	for i := 0; i < 5; i++ {
		err = self.ctx.GetStatusChange(rs, -1)
		if err != nil {
			return err
		}

		if rs[0].EventState&scard.StatePresent != 0 {
			card, e := self.ctx.Connect(
				self.name, scard.ShareExclusive, scard.ProtocolAny)
			if e == nil {
				self.card = card
				return nil
			} else {
				err = e
			}
		}
		fmt.Fprintf(os.Stderr, "connecting...\n")
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return err
	}
	return errors.New("カードが見つかりません")
}

func (self *Reader) SelectCardInfoAP() (*CardInfoAP, error) {
	err := self.SelectDF("D3 92 10 00 31 00 01 01 04 02")
	ap := CardInfoAP{self}
	return &ap, err
}

func (self *Reader) SelectCardInputHelperAP() (*CardInputHelperAP, error) {
	err := self.SelectDF("D3 92 10 00 31 00 01 01 04 08")
	ap := CardInputHelperAP{self}
	return &ap, err
}

func (self *Reader) SelectJPKIAP() (*JPKIAP, error) {
	err := self.SelectDF("D3 92 f0 00 26 01 00 00 00 01")
	ap := JPKIAP{self}
	return &ap, err
}

func (self *Reader) SelectDF(id string) error {
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Select DF\n")
	}
	bid := ToBytes(id)
	apdu := "00 A4 04 0C" + fmt.Sprintf(" %02X % X", len(bid), bid)
	sw1, sw2, _ := self.Tx(apdu)
	if sw1 == 0x90 && sw2 == 0x00 {
		return nil
	} else {
		return NewAPDUError(sw1, sw2)
	}
}

func (self *Reader) SelectEF(id string) error {
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Select EF\n")
	}
	bid := ToBytes(id)
	apdu := fmt.Sprintf("00 A4 02 0C %02X % X", len(bid), bid)
	sw1, sw2, _ := self.Tx(apdu)
	if sw1 == 0x90 && sw2 == 0x00 {
		return nil
	} else {
		return NewAPDUError(sw1, sw2)
	}
}

func (self *Reader) LookupPin() int {
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Lookup PIN\n")
	}
	sw1, sw2, _ := self.Tx("00 20 00 80")
	if sw1 == 0x63 {
		return int(sw2 & 0x0F)
	} else {
		return -1
	}
}

func (self *Reader) Verify(pin string) error {
	var apdu string
	if pin == "" {
		return errors.New("PINが空です")
	}
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Verify PIN\n")
	}
	bpin := []byte(pin)
	apdu = fmt.Sprintf("00 20 00 80 %02X % X", len(bpin), bpin)
	sw1, sw2, _ := self.Tx(apdu)
	if sw1 == 0x90 && sw2 == 0x00 {
		return nil
	} else if sw1 == 0x63 {
		counter := int(sw2 & 0x0F)
		if counter == 0 {
			return errors.New("暗証番号が間違っています。ブロックされました")
		}
		return fmt.Errorf("暗証番号が間違っています。のこり%d回", counter)
	} else if sw1 == 0x69 && sw2 == 0x84 {
		return errors.New("暗証番号がブロックされています。")
	} else {
		return fmt.Errorf("暗証番号が間違っています SW1=%02X SW2=%02X",
			sw1, sw2)
	}
}

func (self *Reader) ChangePin(pin string) bool {
	var apdu string
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Change PIN\n")
	}
	bpin := []byte(pin)
	apdu = fmt.Sprintf("00 24 01 80 %02X % X", len(bpin), bpin)
	sw1, sw2, _ := self.Tx(apdu)
	if sw1 == 0x90 && sw2 == 0x00 {
		return true
	} else {
		return false
	}
}

func dumpBinary(bin []byte) {
	for i := 0; i < len(bin); i++ {
		if i%0x10 == 0 {
			fmt.Fprintf(os.Stderr, ">")
		}
		fmt.Fprintf(os.Stderr, " %02X", bin[i])
		if i%0x10 == 0x0f {
			fmt.Fprintln(os.Stderr)
		}
	}
	fmt.Fprintln(os.Stderr)
}

func (self *Reader) Tx(apdu string) (uint8, uint8, []byte) {
	card := self.card
	cmd := ToBytes(apdu)
	if self.debug {
		if cmd[0] == 0x00 && cmd[1] == 0x20 {
			len := int(cmd[4])
			mask := strings.Repeat(" XX", len)
			fmt.Fprintf(os.Stderr, "< % X XX%s\n", cmd[:4], mask)
		} else {
			fmt.Fprintf(os.Stderr, "< % X\n", cmd)
		}
	}
	res, err := card.Transmit(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "err: %s\n", err)
		return 0, 0, nil
	}

	if self.debug {
		dumpBinary(res)
	}

	l := len(res)
	if l == 2 {
		return res[0], res[1], nil
	} else if l > 2 {
		return res[l-2], res[l-1], res[:l-2]
	}
	return 0, 0, nil
}

func (self *Reader) ReadBinary(size uint16) []byte {
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Read Binary\n")
	}

	var l uint8
	var apdu string
	var pos uint16
	pos = 0
	var res []byte

	for pos < size {
		if size-pos > 0xFF {
			l = 0
		} else {
			l = uint8(size - pos)
		}
		apdu = fmt.Sprintf("00 B0 %02X %02X %02X",
			pos>>8&0xFF, pos&0xFF, l)
		sw1, sw2, data := self.Tx(apdu)
		if sw1 != 0x90 || sw2 != 0x00 {
			return nil
		}
		res = append(res, data...)
		pos += uint16(len(data))
	}
	return res
}

func (self *Reader) Signature(data []byte) ([]byte, error) {
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Signature\n")
	}

	apdu := fmt.Sprintf("80 2a 00 80 %02X % X 00", len(data), data)
	sw1, sw2, res := self.Tx(apdu)
	if sw1 == 0x90 && sw2 == 0x00 {
		return res, nil
	} else {
		return nil, fmt.Errorf("署名エラー(%0X, %0X)", sw1, sw2)
	}
}
