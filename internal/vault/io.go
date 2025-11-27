package vault

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func EncodeBytes(data string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte(data)))
}

func DecodeString(data []byte) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if nil != err {
		return "", err
	}

	return string(decoded), nil
}

func ReadString(fp *os.File) (string, error) {
	var byteBuffer bytes.Buffer
	readBuffer := make([]byte, 1)

	for {
		read, err := fp.Read(readBuffer)

		if 0 < read {
			if '\n' == readBuffer[0] {
				return DecodeString(byteBuffer.Bytes())
			}

			byteBuffer.WriteByte(readBuffer[0])
			continue
		}

		if io.EOF == err {
			if 0 < byteBuffer.Len() {
				return DecodeString(byteBuffer.Bytes())
			}

			return "", io.EOF
		}

		if nil == err {
			err = fmt.Errorf("no error, but read 0 bytes")
		}

		return "", err
	}
}

func WriteString(fp *os.File, data string) error {
	_, err := fp.Write(append(EncodeBytes(data), '\n'))
	if nil != err {
		return err
	}

	return nil
}
