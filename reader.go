package main

import (
	"os"
	"fmt"
	"time"
	"github.com/ebfe/go.pcsclite/scard"
)

type Reader struct {
	ctx *scard.Context
	name string
}

func NewReader() *Reader {
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
	reader.name = readers[0]
	return reader
}

func (self *Reader) Finalize() {
	self.ctx.Release()
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
			return card
		}
		time.Sleep(1 * time.Second)
	}
	panic("unreachable")
}
