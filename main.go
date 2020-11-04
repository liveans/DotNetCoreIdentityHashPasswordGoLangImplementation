package netcoreIdentityHashingAlgorithm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

type KeyDerivationPrfEnum uint

const(
	HMACSHA1 KeyDerivationPrfEnum		= 0
	HMACSHA256 KeyDerivationPrfEnum		= 1
	HMACSHA512 KeyDerivationPrfEnum 	= 2
)

var (
	prf KeyDerivationPrfEnum	= HMACSHA256
	iterCount 					= 10000
	formatMarker 				= 0x01
	requestedLength		     	= 256 / 8
	saltLength 					= 128 / 8
	includeHeaderInfo 			= true
)

func writeNetworkByteOrder(buffer []byte, offset int, value uint) []byte {
	buffer[offset] = byte((value & 0xFF000000) >> 24)
	buffer[offset + 1] = byte((value & 0xFF0000) >> 16)
	buffer[offset + 2] = byte((value & 0xFF00) >> 8)
	buffer[offset + 3] = byte(value & 0xFF)
	return buffer
}

func readNetworkByteOrder(buffer []byte, offset int) uint {
	return ((uint(buffer[offset]) & 0xFF) << 24) | ((uint(buffer[offset + 1]) & 0xFF00) << 16) | (uint(buffer[offset + 2]) << 8) | (uint(buffer[offset + 3]))
}

func fillByteArray(len int) []byte {
	token := make([]byte, len)
	rand.Read(token)
	return token
}

func HashPassword(password string) (string, error) {
	if len(password) <= 0 {
		return "", fmt.Errorf("Argument can not be empty!")
	}
	salt := fillByteArray(saltLength)
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(prf))
	subkey := pbkdf2.Key([]byte(password), salt, iterCount, requestedLength, sha256.New)
	headerByteLength := 1
	if includeHeaderInfo {
		headerByteLength = 13
	}

	outputBytes := make([]byte, headerByteLength + len(salt) + len(subkey))

	outputBytes[0] = byte(formatMarker)

	if includeHeaderInfo {
		outputBytes = writeNetworkByteOrder(outputBytes, 1, uint(prf))
		outputBytes = writeNetworkByteOrder(outputBytes, 5, uint(iterCount))
		outputBytes = writeNetworkByteOrder(outputBytes, 9, uint(saltLength))
	}
	count := headerByteLength
	for i := 0; i < saltLength; i++ {
		outputBytes[count] = salt[i]
		count++
	}
	count = headerByteLength + saltLength
	for i := 0; i < len(subkey); i++ {
		outputBytes[count] = subkey[i]
		count++
	}

	return b64.StdEncoding.EncodeToString(outputBytes), nil
}

func VerifyPassword(hashedPassword string, enteredPassword string) error {
	if len(hashedPassword) <= 0 || len(enteredPassword) <= 0 {
		return fmt.Errorf("Arguments can not be empty!")
	}
	decodedHashedPassword, err := b64.StdEncoding.DecodeString(hashedPassword)
	if err != nil {
		return err
	}

	verifyMarker := decodedHashedPassword[0]
	if byte(formatMarker) != verifyMarker {
		return fmt.Errorf("Can't verified mark!")
	}

	if includeHeaderInfo {
		sha := readNetworkByteOrder(decodedHashedPassword, 1)
		if KeyDerivationPrfEnum(sha) != prf {
			return fmt.Errorf("Algorithm not verified!")
		}

		iterCountRead := readNetworkByteOrder(decodedHashedPassword, 5)
		if int(iterCountRead) != iterCount {
			return fmt.Errorf("Iteration count not verified!")
		}

		saltLen := readNetworkByteOrder(decodedHashedPassword, 9)
		if int(saltLen) != saltLength {
			return fmt.Errorf("Salt Length count not verified!")
		}
	}

	headerByteLength := 1
	if includeHeaderInfo {
		headerByteLength = 13
	}

	salt := make([]byte, saltLength)
	copy(salt, decodedHashedPassword[headerByteLength:headerByteLength + saltLength])
	subKeyLength := len(decodedHashedPassword) - headerByteLength - len(salt)
	if requestedLength != subKeyLength {
		return fmt.Errorf("SubKeyLength is not verified")
	}

	expectedSubKey := make([]byte, subKeyLength)
	copy(expectedSubKey, decodedHashedPassword[headerByteLength + saltLength:headerByteLength + saltLength + subKeyLength])
	actualSubKey := pbkdf2.Key([]byte(enteredPassword), salt, iterCount, subKeyLength, sha256.New)
	if bytes.Compare(actualSubKey, expectedSubKey) != 0 {
		return fmt.Errorf("Passwords are not equal!")
	}

	return nil
}