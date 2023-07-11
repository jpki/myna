package libmyna

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ebfe/scard"
)

type Reader struct {
	ctx   *scard.Context
	name  string
	card  *scard.Card
	debug bool
}

func Debug(d bool) func(*Reader) {
	return func(r *Reader) {
		r.debug = d
	}
}

var OptionDebug = Debug(false)

func NewReader(opts ...func(*Reader)) (*Reader, error) {
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
	for _, opt := range opts {
		opt(reader)
	}
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
	rs[0].CurrentState = scard.StateUnaware

	for true {
		err := self.ctx.GetStatusChange(rs, -1)
		if err != nil {
			return err
		}
		rs[0].CurrentState = rs[0].EventState
		if rs[0].EventState&scard.StatePresent != scard.StatePresent {
			continue
		}
		card, err := self.ctx.Connect(
			self.name, scard.ShareExclusive, scard.ProtocolAny)
		if err != nil {
			return err
		} else {
			self.card = card
			break
		}
	}
	return nil
}

func (self *Reader) SelectVisualAP() (*VisualAP, error) {
	err := self.SelectDF("D3921000310001010402")
	ap := VisualAP{self}
	return &ap, err
}

func (self *Reader) SelectTextAP() (*TextAP, error) {
	err := self.SelectDF("D3921000310001010408")
	ap := TextAP{self}
	return &ap, err
}

func (self *Reader) SelectJPKIAP() (*JPKIAP, error) {
	err := self.SelectDF("D392F000260100000001")
	ap := JPKIAP{self}
	return &ap, err
}

func (self *Reader) SelectDF(id string) error {
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Select DF\n")
	}
	bid := ToBytes(id)
	apdu := NewAPDUCase3(0x00, 0xA4, 0x04, 0x0C, bid)
	sw1, sw2, _ := self.Trans(apdu)
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
	apdu := NewAPDUCase3(0x00, 0xA4, 0x02, 0x0C, bid)
	sw1, sw2, _ := self.Trans(apdu)
	if sw1 == 0x90 && sw2 == 0x00 {
		return nil
	} else {
		return NewAPDUError(sw1, sw2)
	}
}

func (self *Reader) LookupPin() int {
	apdu := NewAPDUCase1(0x00, 0x20, 0x00, 0x80)
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Lookup PIN\n")
	}
	sw1, sw2, _ := self.Trans(apdu)
	if sw1 == 0x63 {
		return int(sw2 & 0x0F)
	} else {
		return -1
	}
}

func (self *Reader) Verify(pin string) error {
	if pin == "" {
		return errors.New("PINが空です")
	}
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Verify PIN\n")
	}
	bpin := []byte(pin)
	apdu := NewAPDUCase3(0x00, 0x20, 0x00, 0x80, bpin)
	sw1, sw2, _ := self.Trans(apdu)
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
	if self.debug {
		fmt.Fprintf(os.Stderr, "# Change PIN\n")
	}
	bpin := []byte(pin)
	apdu := NewAPDUCase3(0x00, 0x24, 0x01, 0x80, bpin)
	sw1, sw2, _ := self.Trans(apdu)
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

func (self *Reader) Trans(apdu *APDU) (uint8, uint8, []byte) {
	card := self.card
	cmd := apdu.cmd
	if self.debug {
		if len(cmd) > 4 && cmd[0] == 0x00 && cmd[1] == 0x20 {
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
	var pos uint16
	pos = 0
	var res []byte

	for pos < size {
		if size-pos > 0xFF {
			l = 0
		} else {
			l = uint8(size - pos)
		}
		apdu := NewAPDUCase2(0x00, 0xB0, uint8(pos>>8&0xFF), uint8(pos&0xFF), l)
		sw1, sw2, data := self.Trans(apdu)
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

	apdu := NewAPDUCase4(0x80, 0x2A, 0x00, 0x80, data, 0)
	sw1, sw2, res := self.Trans(apdu)
	if sw1 == 0x90 && sw2 == 0x00 {
		return res, nil
	} else {
		return nil, fmt.Errorf("署名エラー(%0X, %0X)", sw1, sw2)
	}
}
