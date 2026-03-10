package cmd

import (
	"fmt"

	"github.com/ebfe/scard"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "リーダーの動作確認",
	Long:  "カードリーダーの動作確認を行います",
	RunE:  test,
}

func test(cmd *cobra.Command, args []string) error {
	fmt.Printf("SCardEstablishContext: ")
	ctx, err := scard.EstablishContext()
	if err != nil {
		fmt.Printf("NG %s", err)
		return nil
	}
	defer ctx.Release()
	fmt.Printf("OK\n")

	fmt.Printf("SCardListReaders: ")
	readers, err := ctx.ListReaders()
	if err != nil {
		fmt.Printf("NG %s", err)
		return nil
	}
	fmt.Printf("OK\n")

	for i, reader := range readers {
		fmt.Printf("  Reader %d: %s\n", i, reader)
	}

	if testStatusChange(ctx, readers[0]); err != nil {
		return nil
	}

	if err = testCard(ctx, readers[0]); err != nil {
		return nil
	}

	err = testReleaseContext(ctx)
	return err
}

func testStatusChange(ctx *scard.Context, reader string) error {
	fmt.Printf("SCardGetStatusChange: ")
	rs := make([]scard.ReaderState, 1)
	rs[0].Reader = reader
	err := ctx.GetStatusChange(rs, -1)
	if err != nil {
		fmt.Printf("NG %s", err)
		return nil
	}
	fmt.Printf("OK\n")
	printEventState(rs[0].EventState)
	return nil
}

func testCard(ctx *scard.Context, reader string) error {
	fmt.Printf("SCardConnect: ")
	card, err := ctx.Connect(reader, scard.ShareExclusive, scard.ProtocolAny)
	if err != nil {
		fmt.Printf("NG %s", err)
		return nil
	}
	fmt.Printf("OK\n")

	fmt.Printf("SCardStatus: ")
	cs, err := card.Status()
	if err != nil {
		fmt.Printf("NG %s", err)
		return nil
	}
	fmt.Printf("OK\n")

	printCardState(cs)
	return nil
}

func testReleaseContext(ctx *scard.Context) error {
	fmt.Printf("SCardReleaseContext: ")
	err := ctx.Release()
	if err != nil {
		fmt.Printf("NG %s", err)
		return nil
	}
	fmt.Printf("OK\n")
	return nil
}

var eventStateFlags = [][]interface{}{
	[]interface{}{scard.StateIgnore, "STATE_IGNORE"},
	[]interface{}{scard.StateChanged, "STATE_CHANGED"},
	[]interface{}{scard.StateUnknown, "STATE_UNKNOWN"},
	[]interface{}{scard.StateUnavailable, "STATE_UNAVAILABLE"},
	[]interface{}{scard.StateEmpty, "STATE_EMPTY"},
	[]interface{}{scard.StatePresent, "STATE_PRESENT"},
	[]interface{}{scard.StateAtrmatch, "STATE_ATRMATCH"},
	[]interface{}{scard.StateExclusive, "STATE_EXCLUSIVE"},
	[]interface{}{scard.StateInuse, "STATE_INUSE"},
	[]interface{}{scard.StateMute, "STATE_MUTE"},
	[]interface{}{scard.StateUnpowered, "STATE_UNPOWERED"},
}

func printEventState(eventState scard.StateFlag) {
	fmt.Printf("  EventState: 0x%08x\n", eventState)
	for _, flag := range eventStateFlags {
		if eventState&flag[0].(scard.StateFlag) != 0 {
			fmt.Printf("    %s\n", flag[1])
		}
	}
}

func printCardState(cs *scard.CardStatus) {
	fmt.Printf("  Reader: %s\n", cs.Reader)
	fmt.Printf("  State: 0x%08x\n", cs.State)
	fmt.Printf("  ActiveProtocol: %d\n", cs.ActiveProtocol)
	fmt.Printf("  Atr: % 02X\n", cs.Atr)
}

func init() {
}
