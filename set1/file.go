package set1

import (
	"encoding/base64"
	"io/ioutil"
)

func ReadBase64File(fileName string) []byte {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}

	n, _ := base64.StdEncoding.Decode(b[:], b)

	return b[:n]
}
