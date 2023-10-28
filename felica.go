package felica

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/ebfe/scard"
)

var ErrNoResponse = errors.New("no response from card")
var ErrUnknown = errors.New("unknown error")
var ErrMasterKeyNil = errors.New("master key is nil")
var ErrMacNotMatched = errors.New("mac_a didn't matched")

type Card struct {
	Card *scard.Card
	CK   [16]byte
	SK   [16]byte
	RC   [16]byte
	ID   [16]byte
}

type Block struct {
	Address byte
	Data    [16]byte
}

const (
	AddressS_PAD0    byte = 0x00
	AddressS_PAD1    byte = 0x01
	AddressS_PAD2    byte = 0x02
	AddressS_PAD3    byte = 0x03
	AddressS_PAD4    byte = 0x04
	AddressS_PAD5    byte = 0x05
	AddressS_PAD6    byte = 0x06
	AddressS_PAD7    byte = 0x07
	AddressS_PAD8    byte = 0x08
	AddressS_PAD9    byte = 0x09
	AddressS_PAD10   byte = 0x0a
	AddressS_PAD11   byte = 0x0b
	AddressS_PAD12   byte = 0x0c
	AddressS_PAD13   byte = 0x0d
	AddressREG       byte = 0x0e
	AddressRC        byte = 0x80
	AddressMAC       byte = 0x81
	AddressID        byte = 0x82
	AddressD_ID      byte = 0x83
	AddressSER_C     byte = 0x84
	AddressSYS_C     byte = 0x85
	AddressCKV       byte = 0x86
	AddressCK        byte = 0x87
	AddressMC        byte = 0x88
	AddressWCNT      byte = 0x90
	AddressMAC_A     byte = 0x91
	AddressSTATE     byte = 0x92
	AddressCRC_CHECK byte = 0xa0
)

type DataType byte

const (
	DataTypeUID          DataType = 0x00
	DataTypeID           DataType = 0xF0
	DataTypeCardName     DataType = 0xF1
	DataTypeCardType     DataType = 0xF3
	DataTypeCardTypeName DataType = 0xF4
)

func GetData(card *scard.Card, dataType DataType) ([]byte, error) {
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
func NewFelicaCard(card *scard.Card, masterKeyProvider MasterKeyProvider) (*Card, error) {
	c := Card{
		Card: card,
	}

	err := c.SetService(ServiceRW)
	if err != nil {
		return nil, fmt.Errorf("failed to set service: %w", err)
	}

	_, err = rand.Read(c.RC[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate RC: %w", err)
	}

	err = c.Write([]Block{{
		Address: 0x80,
		Data:    c.RC,
	}})
	if err != nil {
		return nil, fmt.Errorf("failed to write RC: %w", err)
	}

	resp, err := c.Read([]byte{AddressID, AddressCKV, AddressMAC_A})
	if err != nil {
		return nil, fmt.Errorf("failed to read ID: %w", err)
	}

	c.ID = resp[0].Data

	if masterKeyProvider != nil {
		masterKey := masterKeyProvider(([2]byte)(resp[1].Data[:2]))

		if masterKey == nil {
			return &c, ErrMasterKeyNil
		}

		c.CK = c.GenCardKey(masterKey)

		c.SK = c.GenSessionKey()

		mac := c.GenReadMac(resp)

		if mac != [8]byte(resp[2].Data[:8]) {
			return &c, ErrMacNotMatched
		}
	}

	return &c, nil
}

func (c *Card) Read(address []byte) ([]Block, error) {
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
		res := make([]Block, 0, len(address))
		for i := 0; i < len(address); i++ {
			res = append(res, Block{
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
func (c *Card) ReadWithMac(address []byte) ([]Block, error) {
	resp, err := c.Read(append(address, AddressMAC_A))
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

func (c *Card) Write(data []Block) error {
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

func (c *Card) WriteWithMac(data Block) error {
	resp, err := c.ReadWithMac([]byte{AddressWCNT})
	if err != nil {
		return err
	}
	macRaw := c.GenWriteMac([3]byte(resp[0].Data[:3]), data)
	var macPadd [16]byte
	copy(macPadd[:], macRaw[:])
	return c.Write([]Block{data, {
		Address: AddressMAC_A,
		Data:    macPadd,
	}})
}

const (
	ServiceRW = 0x0009
	ServiceRO = 0x000b
)

func (c *Card) SetService(service uint16) error {
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

func (c *Card) Command(command []byte) ([]byte, error) {
	base := []byte{0xFF, 0xFE, 0x00, 0x00, byte(len(command))}
	return c.Card.Transmit(append(base, command...))
}

// Generate CK with ID
func (c *Card) GenCardKey(masterKey *[24]byte) [16]byte {
	cipher, err := des.NewTripleDESCipher(masterKey[:])
	if err != nil {
		log.Panic("Failed to make cipher")
	}
	L := make([]byte, des.BlockSize)
	cipher.Encrypt(L, make([]byte, 8))

	LMSB := L[0] & (1 << 7)
	for i := 0; i < len(L)-1; i++ {
		L[i] = L[i] << 1
		L[i] = L[i] & (L[i+1] >> 7)
	}
	L[len(L)-1] = L[len(L)-1] << 1
	if LMSB != 0 {
		L[len(L)-1] = L[len(L)-1] ^ 0x1b
	}
	ID := c.ID
	M1 := ID[:8]
	M2 := ID[8:]
	xor(M2, L)
	C1 := make([]byte, des.BlockSize)
	cipher.Encrypt(C1, M1)
	T1 := make([]byte, des.BlockSize)
	cipher.Encrypt(T1, M1)
	M1[0] = M1[0] ^ 0x80
	C2 := make([]byte, des.BlockSize)
	cipher.Encrypt(C2, M1)
	T2 := make([]byte, des.BlockSize)
	xor(C2, M2)
	cipher.Encrypt(T2, C2)
	return ([16]byte)(append(T1, T2...))
}

// Generate SK with CK and RC
func (c *Card) GenSessionKey() (res [16]byte) {
	ck := c.CK
	reverse(ck[:])
	k := append(ck[8:], ck[:8]...)
	k = append(k, ck[8:]...)
	cipher, err := des.NewTripleDESCipher(k)
	if err != nil {
		log.Panic("Failed to make cipher")
	}
	rc := c.RC
	reverse(rc[:8])
	data1 := rc[:8]
	data2 := make([]byte, 8)
	cipher.Encrypt(data2, data1)
	for i := 0; i < 8; i++ {
		res[7-i] = data2[i]
	}
	reverse(rc[8:])
	xor(data2, rc[8:])
	cipher.Encrypt(data1, data2)
	for i := 0; i < 8; i++ {
		res[15-i] = data1[i]
	}
	return res
}

// Generate MAC from readed data with SK and RC
func (c *Card) GenReadMac(blocks []Block) [8]byte {
	data := make([][8]byte, 1, (len(blocks)*2-1)+1)
	data[0] = [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	for i, v := range blocks {
		data[0][2*i] = v.Address
		data[0][2*i+1] = 0x00
	}
	for _, v := range blocks {
		if v.Address == AddressMAC_A {
			break
		}
		data = append(data, [8]byte(v.Data[:8]))
		data = append(data, [8]byte(v.Data[8:]))
	}
	return c.GenMac(data)
}

// Generate MAC for write data with SK and RC
func (c *Card) GenWriteMac(wcnt [3]byte, block Block) [8]byte {
	data := [][8]byte{
		{wcnt[0], wcnt[1], wcnt[2], 0x00, block.Address, 0x00, 0x91, 0x00},
		[8]byte(block.Data[:8]),
		[8]byte(block.Data[8:]),
	}
	return c.GenMac(data)
}

// Generate MAC with SK and RC
func (c *Card) GenMac(data [][8]byte) [8]byte {
	sk := c.SK
	reverse(sk[:])
	k := append(sk[8:], sk[:8]...)
	k = append(k, sk[8:]...)
	cipher, err := des.NewTripleDESCipher(k)
	if err != nil {
		log.Panic("Failed to make cipher")
	}
	rc := c.RC
	data1 := ([8]byte)(rc[:8])
	var data2 [8]byte
	reverse(data1[:])
	for _, v := range data {
		reverse(v[:])
		xor(data1[:], v[:])
		cipher.Encrypt(data2[:], data1[:])
		data1 = data2
	}
	reverse(data1[:])
	return (data1)
}

func xor(a []byte, b []byte) {
	for i := 0; i < len(a); i++ {
		a[i] = a[i] ^ b[i]
	}
}

func reverse(s []byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
