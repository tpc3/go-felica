package main

import (
	"log"
	"time"

	"github.com/ebfe/scard"
	"github.com/tpc3/go-felica/felica_pcsc"
)

func main() {
	ctx, err := scard.EstablishContext()
	if err != nil {
		log.Panic("Failed to make context", err)
	}
	defer ctx.Release()

	readers, err := ctx.ListReaders()
	if err != nil {
		log.Panic("Failed to list readers")
	}
	if len(readers) != 1 {
		log.Panic("Invalid number of reader: ", len(readers))
	}

	for {
		log.Print("Waiting for card...")

		var rawCard *scard.Card
		for rawCard == nil {
			err := ctx.GetStatusChange([]scard.ReaderState{
				{
					Reader:       readers[0],
					CurrentState: scard.StateEmpty,
				},
			}, -1)
			if err != nil {
				log.Panic("failed to wait card: ", err)
			}
			rawCard, err = ctx.Connect(readers[0], scard.ShareExclusive, scard.ProtocolT1)
			if err != nil {
				log.Print("failed to connect card: ", err)
			}
		}

		log.Print("card connected")

		validCard := true

		cardType, err := felica_pcsc.GetData(rawCard, felica_pcsc.DataTypeCardType)
		if err != nil {
			log.Panic("Failed to get card type: ", err)
		}
		log.Printf("card type: %x", cardType)
		if cardType[0] != 0x04 {
			validCard = false
		}

		uid, err := felica_pcsc.GetData(rawCard, felica_pcsc.DataTypeUID)
		if err != nil {
			log.Panic("Failed to get uid: ", err)
		}
		log.Printf("card uid: %x", uid)
		// if cardType[0] != 0x04 {
		// 	validCard = false
		// }

		if validCard {
			masterKey := [24]byte([]byte("xNhAMv2J4bAW86Nddq8WDizc"))

			_, err = felica_pcsc.NewCard(rawCard, func(CKV [2]byte) *[24]byte {
				if CKV[0] == 0x00 && CKV[1] == 0x00 {
					return &masterKey
				}
				return nil
			})
			if err != nil {
				log.Print("card NG: ", err)
			} else {
				log.Print("card OK")
			}
		}

		err = ctx.GetStatusChange([]scard.ReaderState{
			{
				Reader:       readers[0],
				CurrentState: scard.StatePresent,
			},
		}, 10*time.Second)
		if err != nil {
			log.Print("wait disconnect NG")
		}

		err = rawCard.Disconnect(scard.ResetCard)
		if err != nil {
			log.Print("disconnect NG")
		}

		log.Print("end")
	}
}
