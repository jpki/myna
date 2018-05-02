package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/ianmcmahon/encoding_ssh"
	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var jpkiCmd = &cobra.Command{
	Use:   "jpki",
	Short: "公的個人認証関連コマンド",
	Long: `公的個人認証関連コマンド
各種証明書の取得や署名・検証を行います
`,
}

var jpkiCertCmd = &cobra.Command{
	Use:   "cert auth|sign|authca|signca",
	Short: "JPKI証明書を表示",
	Long: `公的個人認証の証明書を表示します。

 - auth   利用者認証用証明書
 - authca 利用者認証用CA証明書
 - sign   電子署名用証明書
 - signca 電子署名用CA証明書

署名用証明書を取得する場合のみパスワードが必要です。
`,
	RunE: jpkiCert,
}

func jpkiCert(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		cmd.Help()
		return nil
	}
	var cert *x509.Certificate
	var err error
	var pin string
	switch strings.ToUpper(args[0]) {
	case "AUTH":
		cert, err = libmyna.GetJPKIAuthCert()
	case "AUTHCA":
		cert, err = libmyna.GetJPKIAuthCACert()
	case "SIGN":
		pin, err = cmd.Flags().GetString("pin")
		if pin == "" {
			pin, err = inputPin("署名用パスワード(6-16桁): ")
			if err != nil {
				return nil
			}
		}
		pin = strings.ToUpper(pin)

		cert, err = libmyna.GetJPKISignCert(pin)
	case "SIGNCA":
		cert, err = libmyna.GetJPKISignCACert()
	default:
		cmd.Usage()
		return nil
	}
	if err != nil {
		return err
	}

	err = outputCert(cert, cmd)
	if err != nil {
		return err
	}
	return nil
}

func outputCert(cert *x509.Certificate, cmd *cobra.Command) error {
	form, _ := cmd.Flags().GetString("form")
	switch form {
	case "text":
		printCertText(cert)
	case "pem":
		printCertPem(cert)
	case "der":
		os.Stdout.Write(cert.Raw)
	case "ssh":
		printCertSsh(cert)
	default:
		cmd.Usage()
		return nil
	}
	return nil
}

func printCertPem(cert *x509.Certificate) {
	var block pem.Block
	block.Type = "CERTIFICATE"
	block.Bytes = cert.Raw
	pem.Encode(os.Stdout, &block)
}

func printCertSsh(cert *x509.Certificate) {
	rsaPubkey := cert.PublicKey.(*rsa.PublicKey)
	sshPubkey, _ := ssh.EncodePublicKey(*rsaPubkey, "")
	fmt.Println(sshPubkey)
}

func printCertText(cert *x509.Certificate) {
	fmt.Printf("SerialNumber: %s\n", cert.SerialNumber)
	fmt.Printf("Subject: %s\n", libmyna.Name2String(cert.Subject))
	fmt.Printf("Issuer: %s\n", libmyna.Name2String(cert.Issuer))
	fmt.Printf("NotBefore: %s\n", cert.NotBefore)
	fmt.Printf("NotAfter: %s\n", cert.NotAfter)
	fmt.Printf("KeyUsage: %v\n", cert.KeyUsage)
}

func init() {
	jpkiCmd.AddCommand(jpkiCertCmd)
	jpkiCertCmd.Flags().StringP(
		"form", "f", "text", "出力形式(text|pem|der|ssh)")
	jpkiCertCmd.Flags().StringP(
		"pin", "p", "", "パスワード(署名用証明書のみ)")
}
