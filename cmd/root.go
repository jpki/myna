package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var rootCmd = &cobra.Command{
	Use:          "myna",
	Version:      libmyna.Version,
	Short:        "マイナクライアント",
	Long:         `マイナンバーカード・ユーティリティ・JPKI署名ツール`,
	SilenceUsage: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		libmyna.Debug, _ = cmd.Flags().GetBool("debug")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.EnableCommandSorting = false
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "デバッグ出力")
	rootCmd.AddCommand(cardCmd)
	rootCmd.AddCommand(jpkiCmd)
	rootCmd.AddCommand(pinCmd)
	rootCmd.AddCommand(testCmd)
}
