package vault

import (
	"log"
)

func Die(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
