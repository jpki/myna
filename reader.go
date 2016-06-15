package main

import (
	"os"
	"fmt"
	"time"
	"github.com/urfave/cli"
	"github.com/ebfe/go.pcsclite/scard"
)

type Reader struct {
	ctx *scard.Context
	c *cli.Context
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
		fmt.Fprintf(os.Stderr, "エラー: リーダーが見つかりません。\n")
		return nil
	}
	if len(readers) >= 2 {
		fmt.Fprintf(os.Stderr,
			"警告: 複数のリーダーが見つかりました。最初のものを使います。\n")
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

func (self *Reader) CheckCard() {
	self.WaitForCard()
	aid := "D3 92 f0 00 26 01 00 00 00 01"
	apdu := "00 A4 04 0C" + " 0A " + aid
	sw1, sw2, _ := self.Tx(apdu)
	if sw1 == 0x90 && sw2 == 0x00 {
		return
	}

	fmt.Fprintf(os.Stderr, "これは個人番号カードではありません。\n")
	os.Exit(1)
}

func (self *Reader) GetCard() *scard.Card {
	card, _ := self.ctx.Connect(
		self.name, scard.SHARE_EXCLUSIVE, scard.PROTOCOL_ANY)
	self.card = card
	return card
}

func (self *Reader) WaitForCard() *scard.Card {
	rs := make([]scard.ReaderState, 1)
	rs[0].Reader = self.name
	rs[0].CurrentState = scard.STATE_UNAWARE
	for {
		fmt.Fprintf(os.Stderr, "wait for card:\n")
		err := self.ctx.GetStatusChange(rs, scard.INFINITE)
		if err != nil {
			fmt.Fprintf(os.Stderr, "エラー: %s\n", err)
			return nil
		}
		if rs[0].EventState&scard.STATE_PRESENT != 0 {
			card, _ := self.ctx.Connect(
				self.name, scard.SHARE_EXCLUSIVE, scard.PROTOCOL_ANY)
			self.card = card
			return card
		}
		time.Sleep(1 * time.Second)
	}
	panic("unreachable")
}

func (self *Reader) Tx(apdu string) (uint8, uint8, []byte) {
	card := self.card
	if self.c.Bool("verbose") {
		fmt.Printf(">> %v\n", apdu)
	}
	cmd := ToBytes(apdu)
	res, err := card.Transmit(cmd)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return 0, 0, nil
	}

	if self.c.Bool("verbose") {
		for i := 0; i < len(res); i++ {
			if i % 0x10 == 0 {
				fmt.Print("<<")
			}
			fmt.Printf(" %02X", res[i])
			if i % 0x10 == 0x0f {
				fmt.Println()
			}
		}
		fmt.Println()
	}

	l := len(res)
	if l == 2 {
		return res[0], res[1], nil
	}else if l > 2 {
		return res[l-2], res[l-1], res[:l-2]
	}
	return 0, 0, nil
}

