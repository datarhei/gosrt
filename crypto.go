// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"

	"github.com/benburkert/openpgp/aes/keywrap"
	"golang.org/x/crypto/pbkdf2"
)

type crypto struct {
	salt      []byte
	keyLength int

	evenSEK []byte
	oddSEK  []byte
}

func newCrypto(keyLength int) (*crypto, error) {
	// 3.2.2.  Key Material
	switch keyLength {
	case 16:
	case 24:
	case 32:
	default:
		return nil, fmt.Errorf("Invalid key size, must be either 16, 24, or 32")
	}

	c := &crypto{
		keyLength: keyLength,
	}

	// 3.2.2.  Key Material: "The only valid length of salt defined is 128 bits."
	c.salt = make([]byte, 16)
	if err := c.prng(c.salt); err != nil {
		return nil, fmt.Errorf("Can't generate salt: %w", err)
	}

	c.evenSEK = make([]byte, c.keyLength)
	if err := c.prng(c.evenSEK); err != nil {
		return nil, fmt.Errorf("Can't generate even key: %w", err)
	}

	c.oddSEK = make([]byte, c.keyLength)
	if err := c.prng(c.oddSEK); err != nil {
		return nil, fmt.Errorf("Can't generate odd key: %w", err)
	}

	return c, nil
}

func (c *crypto) UnmarshalKM(km *cifKM, passphrase string) error {
	if len(km.salt) != 0 {
		copy(c.salt, km.salt)
	}

	kek := c.calculateKEK(passphrase)

	unwrap, err := keywrap.Unwrap(kek, km.wrap)
	if err != nil {
		return err
	}

	n := 1
	if km.keyBasedEncryption == evenAndOddKey {
		n = 2
	}

	if len(unwrap) != n*c.keyLength {
		return fmt.Errorf("The unwrapped key has the wrong length")
	}

	if km.keyBasedEncryption == evenKeyEncrypted {
		copy(c.evenSEK, unwrap)
	} else if km.keyBasedEncryption == oddKeyEncrypted {
		copy(c.oddSEK, unwrap)
	} else {
		copy(c.evenSEK, unwrap[:c.keyLength])
		copy(c.oddSEK, unwrap[c.keyLength:])
	}

	return nil
}

func (c *crypto) MarshalKM(km *cifKM, passphrase string, key packetEncryption) error {
	if key == unencryptedPacket || key.IsValid() == false {
		return fmt.Errorf("Invalid key for encryption. Must be even or odd or both")
	}

	km.s = 0
	km.version = 1
	km.packetType = 2
	km.sign = 0x2029
	km.keyBasedEncryption = key // even or odd key
	km.keyEncryptionKeyIndex = 0
	km.cipher = 2
	km.authentication = 0
	km.streamEncapsulation = 2
	km.sLen = 16
	km.kLen = uint16(c.keyLength)

	if len(km.salt) != 16 {
		km.salt = make([]byte, 16)
	}
	copy(km.salt, c.salt)

	n := 1
	if key == evenAndOddKey {
		n = 2
	}

	w := make([]byte, n*c.keyLength)

	if key == evenKeyEncrypted {
		copy(w, c.evenSEK)
	} else if key == oddKeyEncrypted {
		copy(w, c.oddSEK)
	} else {
		copy(w[:c.keyLength], c.evenSEK)
		copy(w[c.keyLength:], c.oddSEK)
	}

	kek := c.calculateKEK(passphrase)

	wrap, err := keywrap.Wrap(kek, w)
	if err != nil {
		return err
	}

	if len(km.wrap) != len(wrap) {
		km.wrap = make([]byte, len(wrap))
	}

	copy(km.wrap, wrap)

	return nil
}

func (c *crypto) EncryptOrDecryptPayload(data []byte, key packetEncryption, packetSequenceNumber uint32) error {
	// 6.1.2.  AES Counter
	//    0   1   2   3   4   5  6   7   8   9   10  11  12  13  14  15
	// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	// |                   0s                  |      psn      |  0   0|
	// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	//                            XOR
	// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	// |                    MSB(112, Salt)                     |
	// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	//
	// psn    (32 bit): packet sequence number
	// ctr    (16 bit): block counter, all zeros
	// nonce (112 bit): 14 most significant bytes of the salt
	//
	// CTR = (MSB(112, Salt) XOR psn) << 16

	ctr := make([]byte, 16)

	binary.BigEndian.PutUint32(ctr[10:], packetSequenceNumber)

	for i := range ctr[:14] {
		ctr[i] ^= c.salt[i]
	}

	var sek []byte
	if key == evenKeyEncrypted {
		sek = c.evenSEK
	} else if key == oddKeyEncrypted {
		sek = c.oddSEK
	} else {
		return fmt.Errorf("Invalid SEK selected. Must be either even or odd")
	}

	// 6.2.2.  Encrypting the Payload
	// 6.3.2.  Decrypting the Payload
	block, err := aes.NewCipher(sek)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, ctr)
	stream.XORKeyStream(data, data)

	return nil
}

func (c *crypto) calculateKEK(passphrase string) []byte {
	// 6.1.4.  Key Encrypting Key (KEK)
	return pbkdf2.Key([]byte(passphrase), c.salt[8:], 2048, c.keyLength, sha1.New)
}

func (c *crypto) prng(p []byte) error {
	n, err := rand.Read(p)
	if err != nil {
		return err
	}

	if n != len(p) {
		return fmt.Errorf("Random byte sequence is too short")
	}

	return nil
}
