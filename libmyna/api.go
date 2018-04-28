// High-Level API

package libmyna

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/mozilla-services/pkcs7"
)

var Debug bool

func CheckCard() error {
	reader, err := NewReader()
	if err != nil {
		return err
	}
	defer reader.Finalize()
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return err
	}

	err = reader.SelectJPKIAP()
	if err != nil {
		return errors.New("個人番号カードではありません")
	}

	err = reader.SelectEF("00 06")
	if err != nil {
		return errors.New("トークン情報を取得できません")
	}

	var data []byte
	data = reader.ReadBinary(0x20)
	token := string(bytes.TrimRight(data, " "))
	if token == "JPKIAPICCTOKEN2" {
		return nil
	} else if token == "JPKIAPICCTOKEN" {
		return errors.New("これは住基カードですね?")
	} else {
		return fmt.Errorf("不明なトークン情報: %s", token)
	}
}

// 券面入力補助APのマイナンバーを取得します
func GetMyNumber(pin string) (string, error) {
	reader, err := NewReader()
	if err != nil {
		return "", err
	}
	defer reader.Finalize()
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return "", err
	}
	reader.SelectCardInputHelperAP()
	reader.SelectEF("00 11") // 券面入力補助PIN
	err = reader.Verify(pin)
	if err != nil {
		return "", err
	}
	reader.SelectEF("00 01")
	data := reader.ReadBinary(16)
	var mynumber asn1.RawValue
	asn1.Unmarshal(data[1:], &mynumber)
	return string(mynumber.Bytes), nil
}

// 券面入力補助APの4属性情報を取得します
func GetAttrInfo(pin string) (map[string]string, error) {
	reader, err := NewReader()
	if err != nil {
		return nil, err
	}
	defer reader.Finalize()
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return nil, err
	}

	reader.SelectCardInputHelperAP()
	reader.SelectEF("00 11") // 券面入力補助PIN
	err = reader.Verify(pin)
	if err != nil {
		return nil, err
	}

	reader.SelectEF("00 02")

	// TODO: ファイルサイズがわからないのでDERデータの先頭5オクテット
	// を読んで調べているが、FCIなどでファイルサイズを調べる方法があれ
	// ばこんなことしなくても良い。
	data := reader.ReadBinary(5)
	if len(data) != 5 {
		return nil, errors.New("Error at ReadBinary()")
	}

	var data_size uint16
	var pos uint16
	if data[2]&0x80 == 0 {
		// データ長が1オクテット
		data_size = uint16(data[2])
		pos = 3
	} else {
		//データ長が2オクテット
		data_size = uint16(data[3])<<8 | uint16(data[4])
		pos = 5
	}

	data = reader.ReadBinary(pos + data_size)
	var attr [5]asn1.RawValue
	for i := 0; i < 5; i++ {
		asn1.Unmarshal(data[pos:], &attr[i])
		pos += uint16(len(attr[i].FullBytes))
	}

	info := map[string]string{
		"header":  fmt.Sprintf("% X", attr[0].Bytes),
		"name":    string(attr[1].Bytes),
		"address": string(attr[2].Bytes),
		"birth":   string(attr[3].Bytes),
		"sex":     string(attr[4].Bytes),
	}
	return info, nil
}

func ChangeCardInputHelperPin(pin string, newpin string) error {
	err := Validate4DigitPin(pin)
	if err != nil {
		return err
	}

	err = Validate4DigitPin(newpin)
	if err != nil {
		return err
	}

	reader, err := NewReader()
	if err != nil {
		return err
	}
	defer reader.Finalize()
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return err
	}

	reader.SelectCardInputHelperAP()
	reader.SelectEF("00 11") // 券面入力補助PIN IEF

	err = reader.Verify(pin)
	if err != nil {
		return err
	}

	res := reader.ChangePin(newpin)
	if !res {
		return errors.New("PINの変更に失敗しました")
	}
	return nil
}

func ChangeJPKIAuthPin(pin string, newpin string) error {
	err := Validate4DigitPin(pin)
	if err != nil {
		return err
	}

	err = Validate4DigitPin(newpin)
	if err != nil {
		return err
	}

	reader, err := NewReader()
	if err != nil {
		return err
	}
	defer reader.Finalize()
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return err
	}

	reader.SelectJPKIAP()
	reader.SelectEF("00 18")

	err = reader.Verify(pin)
	if err != nil {
		return err
	}

	res := reader.ChangePin(newpin)
	if !res {
		return errors.New("PINの変更に失敗しました")
	}
	return nil
}

func ChangeJPKISignPin(pin string, newpin string) error {
	pin = strings.ToUpper(pin)
	err := ValidateJPKISignPassword(pin)
	if err != nil {
		return err
	}

	newpin = strings.ToUpper(newpin)
	err = ValidateJPKISignPassword(newpin)
	if err != nil {
		return err
	}

	reader, err := NewReader()
	if err != nil {
		return err
	}
	defer reader.Finalize()
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return err
	}

	reader.SelectJPKIAP()
	reader.SelectEF("00 1B") // IEF for SIGN

	err = reader.Verify(pin)
	if err != nil {
		return err
	}

	res := reader.ChangePin(newpin)
	if !res {
		return errors.New("PINの変更に失敗しました")
	}
	return nil
}

func GetJPKICert(efid string, pin string) (*x509.Certificate, error) {
	reader, err := NewReader()
	if err != nil {
		return nil, err
	}
	defer reader.Finalize()
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return nil, err
	}
	err = reader.SelectJPKIAP()
	if err != nil {
		return nil, err
	}
	err = reader.SelectEF(efid)
	if err != nil {
		return nil, err
	}

	if pin != "" {
		reader.SelectEF("00 1B") // VERIFY EF for SIGN
		err = reader.Verify(pin)
		if err != nil {
			return nil, err
		}
	}

	reader.SelectEF(efid)
	data := reader.ReadBinary(4)
	if len(data) != 4 {
		return nil, errors.New("ReadBinary: invalid length")
	}
	data_size := uint16(data[2])<<8 | uint16(data[3])
	data = reader.ReadBinary(4 + data_size)
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func GetJPKIAuthCert() (*x509.Certificate, error) {
	return GetJPKICert("00 0A", "")
}

func GetJPKIAuthCACert() (*x509.Certificate, error) {
	return GetJPKICert("00 0B", "")
}

func GetJPKISignCert(pass string) (*x509.Certificate, error) {
	return GetJPKICert("00 01", pass)
}

func GetJPKISignCACert() (*x509.Certificate, error) {
	return GetJPKICert("00 02", "")
}

/*
func CmsSignJPKISignOld(pin string, in string, out string) error {
	rawContent, err := ioutil.ReadFile(in)
	if err != nil {
		return err
	}

	toBeSigned, err := pkcs7.NewSignedData(rawContent)
	if err != nil {
		return err
	}

	// 署名用証明書の取得
	cert, err := GetJPKISignCert(pin)
	if err != nil {
		return err
	}
	attrs, hashed, err := toBeSigned.HashAttributes(crypto.SHA1, pkcs7.SignerInfoConfig{})
	if err != nil {
		return err
	}

	ias, err := pkcs7.Cert2issuerAndSerial(cert)
	if err != nil {
		return err
	}

	reader, err := NewReader()
	if err != nil {
		return err
	}
	defer reader.Finalize()
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return err
	}

	reader.SelectJPKIAP()
	reader.SelectEF("00 1B") // IEF for SIGN
	err = reader.Verify(pin)
	if err != nil {
		return err
	}

	reader.SelectEF("00 1A") // Select SIGN EF
	digestInfo := makeDigestInfo(hashed)

	signature, err := reader.Signature(digestInfo)
	if err != nil {
		return err
	}

	oidDigestAlgorithmSHA1 := asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidEncryptionAlgorithmRSA := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	signerInfo := pkcs7.SignerInfo{
		AuthenticatedAttributes:   attrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: oidDigestAlgorithmSHA1},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEncryptionAlgorithmRSA},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	toBeSigned.AddSignerInfo(cert, signerInfo)
	signed, err := toBeSigned.Finish()
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(out, signed, 0664)
	if err != nil {
		return err
	}
	return nil
}
*/

type JPKISignSigner struct {
	pin    string
	pubkey crypto.PublicKey
}

func (self JPKISignSigner) Public() crypto.PublicKey {
	return self.pubkey
}

func (self JPKISignSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	digestInfo := makeDigestInfo(opts.HashFunc(), digest)
	reader, err := NewReader()
	if err != nil {
		return nil, err
	}
	defer reader.Finalize()
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return nil, err
	}
	reader.SelectJPKIAP()
	reader.SelectEF("00 1B") // IEF for SIGN
	err = reader.Verify(self.pin)
	if err != nil {
		return nil, err
	}

	reader.SelectEF("00 1A") // Select SIGN EF
	signature, err = reader.Signature(digestInfo)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func GetDigestOID(md string) (asn1.ObjectIdentifier, error) {
	switch strings.ToUpper(md) {
	case "SHA1":
		return pkcs7.OIDDigestAlgorithmSHA1, nil
	case "SHA256":
		return pkcs7.OIDDigestAlgorithmSHA256, nil
	case "SHA384":
		return pkcs7.OIDDigestAlgorithmSHA384, nil
	case "SHA512":
		return pkcs7.OIDDigestAlgorithmSHA512, nil
	default:
		return nil, fmt.Errorf("サポートされていないハッシュアルゴリズムです: %s", md)
	}
}

func CmsSignJPKISign(pin string, in string, out string, hash string) error {
	digest, err := GetDigestOID(hash)

	content, err := ioutil.ReadFile(in)
	if err != nil {
		return err
	}

	// 署名用証明書の取得
	cert, err := GetJPKISignCert(pin)
	if err != nil {
		return err
	}

	privkey := JPKISignSigner{pin, cert.PublicKey}

	toBeSigned, err := pkcs7.NewSignedData(content)
	toBeSigned.SetDigestAlgorithm(digest)
	err = toBeSigned.AddSigner(cert, privkey, pkcs7.SignerInfoConfig{})
	if err != nil {
		return err
	}

	signed, err := toBeSigned.Finish()
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(out, signed, 0664)
	if err != nil {
		return err
	}

	return nil
}
