package felica_pcsc

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ebfe/scard"
	"github.com/tpc3/go-felica/felica"
)

var ErrNoResponse = errors.New("no response from card")
var ErrUnknown = errors.New("unknown error")
var ErrMasterKeyNil = errors.New("master key is nil")
var ErrMacNotMatched = errors.New("mac_a didn't matched")

type FeliCaLiteS struct {
	felica.FeliCaLiteS
	Card *scard.Card
}

func GetData(card *scard.Card, dataType felica.DataType) ([]byte, error) {
	command := []byte{0xFF, 0xCA, byte(dataType), 0x00, 0x00}
	resp, err := card.Transmit(command)
	if err != nil {
		return nil, err
	}
	if resp[len(resp)-2] == 0x90 && resp[len(resp)-1] == 0x00 {
		return resp[:len(resp)-2], nil
	} else if resp[len(resp)-2] == 0x64 && resp[len(resp)-1] == 0x01 {
		return nil, ErrNoResponse
	} else {
		return resp, fmt.Errorf("%w: %x", ErrUnknown, resp)
	}
}

// Return MasterKey from CKV
// returning nil results ErrMasterKeyNil
type MasterKeyProvider func([2]byte) *[24]byte

// If masterKeyProvider is nil, MAC check skipped
func NewCard(card *scard.Card, masterKeyProvider MasterKeyProvider) (*FeliCaLiteS, error) {
	c := FeliCaLiteS{
		Card: card,
	}

	err := c.SetService(felica.ServiceRW)
	if err != nil {
		return nil, fmt.Errorf("failed to set service: %w", err)
	}

	_, err = rand.Read(c.RC[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate RC: %w", err)
	}

	err = c.Write([]felica.Block{{
		Address: 0x80,
		Data:    c.RC,
	}})
	if err != nil {
		return nil, fmt.Errorf("failed to write RC: %w", err)
	}

	resp, err := c.Read([]byte{felica.AddressID, felica.AddressCKV, felica.AddressMAC_A})
	if err != nil {
		return nil, fmt.Errorf("failed to read ID: %w", err)
	}

	c.ID = resp[0].Data

	if masterKeyProvider != nil {
		masterKey := masterKeyProvider(([2]byte)(resp[1].Data[:2]))

		if masterKey == nil {
			return &c, ErrMasterKeyNil
		}

		c.GenCardKey(masterKey)

		c.GenSessionKey()

		mac := c.GenReadMac(resp)

		if mac != [8]byte(resp[2].Data[:8]) {
			return &c, ErrMacNotMatched
		}
	}

	return &c, nil
}

func (c *FeliCaLiteS) Read(address []byte) ([]felica.Block, error) {
	blockList := make([]byte, 0, len(address)*2)
	for _, v := range address {
		blockList = append(blockList, 0x80)
		blockList = append(blockList, v)
	}
	command := []byte{0xFF, 0xB0, 0x80, byte(len(address)), byte(len(blockList))}
	command = append(command, blockList...)
	command = append(command, 0x00)
	resp, err := c.Card.Transmit(command)
	if err != nil {
		return nil, err
	}
	if resp[len(resp)-2] == 0x90 && resp[len(resp)-1] == 0x00 {
		res := make([]felica.Block, 0, len(address))
		for i := 0; i < len(address); i++ {
			res = append(res, felica.Block{
				Address: address[i],
				Data:    ([16]byte)(resp[i*16 : (i+1)*16]),
			})
		}
		return res, nil
	} else if resp[len(resp)-2] == 0x64 && resp[len(resp)-1] == 0x01 {
		return nil, ErrNoResponse
	} else {
		return nil, fmt.Errorf("%w: %x", ErrUnknown, resp)
	}
}

// address length: 1-3
func (c *FeliCaLiteS) ReadWithMac(address []byte) ([]felica.Block, error) {
	resp, err := c.Read(append(address, felica.AddressMAC_A))
	if err != nil {
		return nil, err
	}
	mac := c.GenReadMac(resp)
	if bytes.Equal(mac[:], resp[len(resp)-1].Data[:8]) {
		return resp, nil
	} else {
		return resp, ErrMacNotMatched
	}
}

func (c *FeliCaLiteS) Write(data []felica.Block) error {
	blockList := make([]byte, 0, len(data)*2)
	dataArr := make([]byte, 0, len(data)*16)
	for _, v := range data {
		blockList = append(blockList, 0x80)
		blockList = append(blockList, v.Address)
		for _, v := range v.Data {
			dataArr = append(dataArr, v)
		}
	}
	command := []byte{0xFF, 0xD6, 0x80, byte(len(data)), byte(len(blockList) + len(dataArr))}
	command = append(command, blockList...)
	command = append(command, dataArr...)
	command = append(command, 0x00)
	resp, err := c.Card.Transmit(command)
	if err != nil {
		return err
	}
	if resp[len(resp)-2] == 0x90 && resp[len(resp)-1] == 0x00 {
		// success
		return nil
	} else if resp[len(resp)-2] == 0x64 && resp[len(resp)-1] == 0x01 {
		return ErrNoResponse
	} else {
		return fmt.Errorf("%w: %x", ErrUnknown, resp)
	}
}

func (c *FeliCaLiteS) WriteWithMac(data felica.Block) error {
	resp, err := c.ReadWithMac([]byte{felica.AddressWCNT})
	if err != nil {
		return err
	}
	macRaw := c.GenWriteMac([3]byte(resp[0].Data[:3]), data)
	var macPadd [16]byte
	copy(macPadd[:], macRaw[:])
	return c.Write([]felica.Block{data, {
		Address: felica.AddressMAC_A,
		Data:    macPadd,
	}})
}

func (c *FeliCaLiteS) SetService(service uint16) error {
	command := []byte{0xFF, 0xA4, 0x00, 0x01, 0x02}
	command = binary.LittleEndian.AppendUint16(command, service)
	resp, err := c.Card.Transmit(command)
	if err != nil {
		return err
	}
	if resp[len(resp)-2] == 0x90 && resp[len(resp)-1] == 0x00 {
		// success
		return nil
	} else if resp[len(resp)-2] == 0x64 && resp[len(resp)-1] == 0x01 {
		return ErrNoResponse
	} else {
		return fmt.Errorf("%w: %x", ErrUnknown, resp)
	}
}

func (c *FeliCaLiteS) Command(command []byte) ([]byte, error) {
	base := []byte{0xFF, 0xFE, 0x00, 0x00, byte(len(command))}
	return c.Card.Transmit(append(base, command...))
}
