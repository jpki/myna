package libmyna

import (
	"errors"
	"fmt"
	"github.com/ebfe/scard"
	"github.com/urfave/cli"
	"os"
	"time"
)

type Reader struct {
	ctx  *scard.Context
	c    *cli.Context
	name string
	card *scard.Card
}

func NewReader(c *cli.Context) *Reader {
	ctx, err := scard.EstablishContext()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return nil
	}

	readers, err := ctx.ListReaders()
	if err != nil || len(readers) == 0 {
		return nil
	}
	if len(readers) >= 2 {
		fmt.Fprintf(os.Stderr,
			"警告: 複数のリーダーが見つかりました。最初のものを使います\n")
	}

	reader := new(Reader)
	reader.ctx = ctx
	reader.c = c
	reader.name = readers[0]
	reader.card = nil
	return reader
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

func (self *Reader) WaitForCard() error {
	rs := make([]scard.ReaderState, 1)
	rs[0].Reader = self.name
	rs[0].CurrentState = scard.StateUnaware
	for i := 0; i < 3; i++ {
		err := self.ctx.GetStatusChange(rs, -1)
		if err != nil {
			return fmt.Errorf("エラー: %s\n", err)
		}
		if rs[0].EventState&scard.StatePresent != 0 {
			card, err := self.ctx.Connect(
				self.name, scard.ShareExclusive, scard.ProtocolAny)
			if err != nil {
				return err
			}
			self.card = card
			return nil
		}
		fmt.Fprintf(os.Stderr, "wait for card...\n")
		time.Sleep(1 * time.Second)
	}
	return errors.New("カードが見つかりません")
}

func (self *Reader) SelectAP(aid string) bool {
	return self.SelectDF(aid)
}

func (self *Reader) SelectCardAP() bool {
	return self.SelectDF("D3 92 10 00 31 00 01 01 04 08")
}

func (self *Reader) SelectJPKIAP() bool {
	return self.SelectDF("D3 92 f0 00 26 01 00 00 00 01")
}

func (self *Reader) SelectDF(id string) bool {
	if self.c.GlobalBool("debug") {
		fmt.Fprintf(os.Stderr, "# Select DF\n")
	}
	bid := ToBytes(id)
	apdu := "00 A4 04 0C" + fmt.Sprintf(" %02X % X", len(bid), bid)
	sw1, sw2, _ := self.Tx(apdu)
	if sw1 == 0x90 && sw2 == 0x00 {
		return true
	} else {
		return false
	}
}

func (self *Reader) SelectEF(id string) (uint8, uint8) {
	if self.c.GlobalBool("debug") {
		fmt.Fprintf(os.Stderr, "# Select EF\n")
	}
	bid := ToBytes(id)
	apdu := fmt.Sprintf("00 A4 02 0C %02X % X", len(bid), bid)
	sw1, sw2, _ := self.Tx(apdu)
	return sw1, sw2
}

func (self *Reader) LookupPin() int {
	if self.c.GlobalBool("debug") {
		fmt.Fprintf(os.Stderr, "# Lookup PIN\n")
	}
	sw1, sw2, _ := self.Tx("00 20 00 80")
	if sw1 == 0x63 {
		return int(sw2 & 0x0F)
	} else {
		return -1
	}
}

func (self *Reader) Verify(pin string) (uint8, uint8) {
	var apdu string
	if pin == "" {
		if self.c.GlobalBool("debug") {
			fmt.Fprintf(os.Stderr, "# Lookup PIN\n")
		}
		apdu = "00 20 00 80"
		sw1, sw2, _ := self.Tx(apdu)
		return sw1, sw2
	} else {
		if self.c.GlobalBool("debug") {
			fmt.Fprintf(os.Stderr, "# Verify PIN\n")
		}
		bpin := []byte(pin)
		apdu = fmt.Sprintf("00 20 00 80 %02X % X", len(bpin), bpin)
		sw1, sw2, _ := self.Tx(apdu)
		return sw1, sw2
	}
}

func (self *Reader) ChangePin(pin string) bool {
	var apdu string
	if self.c.GlobalBool("debug") {
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
			fmt.Println()
		}
	}
	fmt.Println()
}

func (self *Reader) Tx(apdu string) (uint8, uint8, []byte) {
	card := self.card
	if self.c.GlobalBool("debug") {
		fmt.Fprintf(os.Stderr, "< %v\n", apdu)
	}
	cmd := ToBytes(apdu)
	res, err := card.Transmit(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "err: %s\n", err)
		return 0, 0, nil
	}

	if self.c.GlobalBool("debug") {
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
	if self.c.GlobalBool("debug") {
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
	if self.c.GlobalBool("debug") {
		fmt.Fprintf(os.Stderr, "# Signature ")
	}

	apdu := fmt.Sprintf("80 2a 00 80 %02X % X 00", len(data), data)
	sw1, sw2, res := self.Tx(apdu)
	if sw1 == 0x90 && sw2 == 0x00 {
		return res, nil
	} else {
		return nil, fmt.Errorf("署名エラー(%0X, %0X)", sw1, sw2)
	}
}
