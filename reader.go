package main

import (
	"os"
	"fmt"
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

func (self *Reader) GetCard() *scard.Card {
	fmt.Printf("GetCard\n")
	card, err := self.ctx.Connect(self.name, scard.SHARE_EXCLUSIVE, scard.PROTOCOL_ANY)
	fmt.Printf("err: %s\n", err)
	return card
}

type Card struct {
}
