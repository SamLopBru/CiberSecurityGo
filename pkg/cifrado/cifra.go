// cifra/cifra.go
package cifrado

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/twofish"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

type salsaStream struct {
	nonce []byte
	key   [32]byte
}

func (s *salsaStream) XORKeyStream(dst, src []byte) {
	salsa20.XORKeyStream(dst, src, s.nonce, &s.key)
}

func newSalsa(key, nonce []byte) (s *salsaStream, e error) {
	if len(key) != 32 {
		e = errors.New("salsa20: la clave debe tener 32 bytes")
		return
	}
	if (len(nonce) != 8) && (len(nonce) != 24) {
		e = errors.New("salsa20: el nonce debe ser de 8 o 24 bytes")
		return
	}

	s = new(salsaStream)
	s.nonce = make([]byte, len(nonce), len(nonce))

	for i := 0; i < len(key); i++ {
		s.key[i] = key[i]
	}

	for i := 0; i < len(nonce); i++ {
		s.nonce[i] = nonce[i]
	}
	return s, e
}

// EncryptData cifra datos usando el algoritmo especificado
func EncryptData(data []byte, keyStr string, algorithm string, useCompression bool) ([]byte, error) {
	// Generamos el hash de la clave e IV
	h := sha256.New()
	h.Reset()
	_, err := h.Write([]byte(keyStr))
	if err != nil {
		return nil, err
	}
	key := h.Sum(nil)

	h.Reset()
	_, err = h.Write([]byte("<inicializar>"))
	if err != nil {
		return nil, err
	}
	iv := h.Sum(nil)

	// Creamos el cifrador según el algoritmo
	var S cipher.Stream
	switch algorithm {
	case "AES128":
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:16])

	case "AES256":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:16])

	case "DES":
		block, err := des.NewCipher(key[:8])
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:8])

	case "TDES":
		block, err := des.NewTripleDESCipher(key[:24])
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:8])

	case "RC4":
		c, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		S = c

	case "BLOWFISH":
		block, err := blowfish.NewCipher(key)
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:8])

	case "TWOFISH":
		block, err := twofish.NewCipher(key)
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:16])

	case "SALSA20":
		c, err := newSalsa(key, iv[:24])
		if err != nil {
			return nil, err
		}
		S = c
		useCompression = false // Salsa20 no es compatible con compresión

	default:
		return nil, errors.New("algoritmo no soportado")
	}

	// Procesamos los datos
	var outputBuf bytes.Buffer
	var enc cipher.StreamWriter
	enc.S = S
	enc.W = &outputBuf

	var writer io.WriteCloser
	if useCompression {
		writer = zlib.NewWriter(enc)
	} else {
		writer = enc
	}

	_, err = writer.Write(data)
	if err != nil {
		return nil, err
	}
	writer.Close()

	return outputBuf.Bytes(), nil
}

// DecryptData descifra datos usando el algoritmo especificado
func DecryptData(encryptedData []byte, keyStr string, algorithm string, useCompression bool) ([]byte, error) {
	// Generamos el hash de la clave e IV
	h := sha256.New()
	h.Reset()
	_, err := h.Write([]byte(keyStr))
	if err != nil {
		return nil, err
	}
	key := h.Sum(nil)

	h.Reset()
	_, err = h.Write([]byte("<inicializar>"))
	if err != nil {
		return nil, err
	}
	iv := h.Sum(nil)

	// Creamos el descifrador según el algoritmo
	var S cipher.Stream
	switch algorithm {
	case "AES128":
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:16])

	case "AES256":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:16])

	case "DES":
		block, err := des.NewCipher(key[:8])
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:8])

	case "TDES":
		block, err := des.NewTripleDESCipher(key[:24])
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:8])

	case "RC4":
		c, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		S = c

	case "BLOWFISH":
		block, err := blowfish.NewCipher(key)
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:8])

	case "TWOFISH":
		block, err := twofish.NewCipher(key)
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, iv[:16])

	case "SALSA20":
		c, err := newSalsa(key, iv[:24])
		if err != nil {
			return nil, err
		}
		S = c
		useCompression = false // Salsa20 no es compatible con compresión

	default:
		return nil, errors.New("algoritmo no soportado")
	}

	// Procesamos los datos
	inputBuf := bytes.NewReader(encryptedData)
	var dec cipher.StreamReader
	dec.S = S
	dec.R = inputBuf

	var reader io.Reader
	if useCompression {
		zlibReader, err := zlib.NewReader(dec)
		if err != nil {
			return nil, err
		}
		defer zlibReader.Close() // Ahora usamos variable específica
		reader = zlibReader
	} else {
		reader = dec
	}

	return io.ReadAll(reader) // Cambiamos ioutil.ReadAll por io.ReadAll en Go moderno
}
