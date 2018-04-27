package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var ctx libmyna.Context

var rootCmd = &cobra.Command{
	Use:          "myna",
	Version:      libmyna.Version,
	Short:        "マイナクライアント",
	Long:         `マイナンバーカード・ユーティリティ・JPKI署名ツール`,
	SilenceUsage: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		ctx.Debug, _ = cmd.Flags().GetBool("debug")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		//fmt.Fprintf(os.Stderr, "エラー: %s\n", err)
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.hoge.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	cobra.EnableCommandSorting = false
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "デバッグ出力")
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(pinCmd)
}
