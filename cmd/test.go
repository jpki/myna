package cmd

import (
	"fmt"

	"github.com/ebfe/scard"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "動作確認",
	RunE:  test,
}

func test(cmd *cobra.Command, args []string) error {
	fmt.Printf("SCardEstablishContext: ")
	ctx, err := scard.EstablishContext()
	if err != nil {
		fmt.Printf("NG\n")
		fmt.Printf("%s\n", err)
		return nil
	}
	defer ctx.Release()
	fmt.Printf("OK\n")

	fmt.Printf("SCardListReaders: ")
	readers, err := ctx.ListReaders()
	if err != nil {
		fmt.Printf("NG\n")
		fmt.Printf("%s\n", err)
		return nil
	}
	fmt.Printf("OK\n")

	for i, reader := range readers {
		fmt.Printf("  Reader %d: %s\n", i, reader)
	}

	fmt.Printf("SCardGetStatusChange: ")
	rs := make([]scard.ReaderState, 1)
	rs[0].Reader = readers[0]
	err = ctx.GetStatusChange(rs, -1)
	if err != nil {
		fmt.Printf("NG\n")
		fmt.Printf("%s\n", err)
		return nil
	}
	fmt.Printf("OK\n")
	fmt.Printf("  EventState: 0x%08x\n", rs[0].EventState)

	if rs[0].EventState&scard.StateIgnore != 0 {
		fmt.Printf("    IGNORE\n")
	}
	if rs[0].EventState&scard.StateChanged != 0 {
		fmt.Printf("    CHANGED\n")
	}
	if rs[0].EventState&scard.StateUnknown != 0 {
		fmt.Printf("    UNKNOWN\n")
	}
	if rs[0].EventState&scard.StateUnavailable != 0 {
		fmt.Printf("    UNAVAILABLE\n")
	}
	if rs[0].EventState&scard.StateEmpty != 0 {
		fmt.Printf("    EMPTY\n")
	}
	if rs[0].EventState&scard.StatePresent != 0 {
		fmt.Printf("    PRESENT\n")
	}
	if rs[0].EventState&scard.StateAtrmatch != 0 {
		fmt.Printf("    ATRMATCH\n")
	}
	if rs[0].EventState&scard.StateExclusive != 0 {
		fmt.Printf("    EXCLUSIVE\n")
	}
	if rs[0].EventState&scard.StateInuse != 0 {
		fmt.Printf("    INUSE\n")
	}
	if rs[0].EventState&scard.StateMute != 0 {
		fmt.Printf("    MUTE\n")
	}
	if rs[0].EventState&scard.StateUnpowered != 0 {
		fmt.Printf("    UNPOWERED\n")
	}

	fmt.Printf("SCardConnect: ")
	card, err := ctx.Connect(readers[0], scard.ShareExclusive, scard.ProtocolAny)
	if err != nil {
		fmt.Printf("NG\n")
		fmt.Printf("%s\n", err)
		return nil
	}
	fmt.Printf("OK\n")

	fmt.Printf("SCardStatus: ")
	cs, err := card.Status()
	if err != nil {
		fmt.Printf("NG\n")
		fmt.Printf("%s\n", err)
		return nil
	}
	fmt.Printf("OK\n")

	fmt.Printf("  Reader: %s\n", cs.Reader)
	fmt.Printf("  State: 0x%08x\n", cs.State)
	fmt.Printf("  ActiveProtocol: %d\n", cs.ActiveProtocol)
	fmt.Printf("  Atr: % 02X\n", cs.Atr)

	fmt.Printf("SCardReleaseContext: ")

	err = ctx.Release()
	if err != nil {
		fmt.Printf("NG\n")
		fmt.Printf("%s\n", err)
		return nil
	}
	fmt.Printf("OK\n")
	return nil
}

func init() {
}
