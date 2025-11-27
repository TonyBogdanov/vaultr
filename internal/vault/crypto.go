package vault

import (
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "fmt"
  "io"

  "golang.org/x/crypto/argon2"
)

type CypherVersion struct {
  version      byte
  saltLen      int
  nonceLen     int
  dekLen       uint32
  keyLen       uint32
  argonTime    uint32
  argonMemory  uint32
  argonThreads uint8
}

var FastCiphers = []CypherVersion{
  {
    version:      1,
    saltLen:      16,
    nonceLen:     12,
    dekLen:       32,
    keyLen:       24,
    argonTime:    5,
    argonMemory:  32 * 1024,
    argonThreads: 4,
  },
}

var SlowCiphers = []CypherVersion{
  {
    version:      1,
    saltLen:      16,
    nonceLen:     12,
    dekLen:       32,
    keyLen:       32,
    argonTime:    10,
    argonMemory:  512 * 1024,
    argonThreads: 4,
  },
}

func GenerateDEK() (string, error) {
  dek := make([]byte, 64)
  _, err := rand.Read(dek)

  if err != nil {
    return "", err
  }

  return string(dek), nil
}

func Encrypt(password, data string, ciphers []CypherVersion) (string, error) {
  // we need inputs in bytes
  passwordBytes := []byte(password)
  dataBytes := []byte(data)

  // use latest available cipher
  ci := ciphers[len(ciphers)-1]

  // generate salt
  salt := make([]byte, ci.saltLen)
  if _, err := io.ReadFull(rand.Reader, salt); nil != err {
    return "", err
  }

  // derive key with Argon2id
  key := argon2.IDKey(passwordBytes, salt, ci.argonTime, ci.argonMemory, ci.argonThreads, ci.keyLen)

  // create AES-GCM
  block, err := aes.NewCipher(key)
  if nil != err {
    return "", err
  }

  aead, err := cipher.NewGCM(block)
  if nil != err {
    return "", err
  }

  // nonce
  nonce := make([]byte, ci.nonceLen)
  if _, err := io.ReadFull(rand.Reader, nonce); nil != err {
    return "", err
  }

  // encrypt (AEAD.Seal appends tag automatically)
  ct := aead.Seal(nil, nonce, dataBytes, nil)

  // assemble output: version|salt|nonce|ciphertext
  encrypted := make([]byte, 1+ci.saltLen+ci.nonceLen+len(ct))
  encrypted[0] = ci.version

  copy(encrypted[1:1+ci.saltLen], salt)
  copy(encrypted[1+ci.saltLen:1+ci.saltLen+ci.nonceLen], nonce)
  copy(encrypted[1+ci.saltLen+ci.nonceLen:], ct)

  // zero key material (best-effort)
  for i := range key {
    key[i] = 0
  }

  return string(encrypted), nil
}

func Decrypt(password, data string, ciphers []CypherVersion) (string, error) {
  // we need inputs in bytes
  passwordBytes := []byte(password)
  dataBytes := []byte(data)

  // cannot process empty data
  if 0 == len(dataBytes) {
    return "", fmt.Errorf("data is empty")
  }

  // pick the correct cipher the data was encoded with
  var ci CypherVersion
  for _, _ci := range ciphers {
    if _ci.version == dataBytes[0] {
      ci = _ci
      break
    }
  }

  if 0 == ci.version {
    return "", fmt.Errorf("data uses unsupported cipher version: %d", dataBytes[0])
  }

  if len(dataBytes) < 1+ci.saltLen+ci.nonceLen {
    return "", fmt.Errorf("data is too short")
  }

  salt := dataBytes[1 : 1+ci.saltLen]
  nonce := dataBytes[1+ci.saltLen : 1+ci.saltLen+ci.nonceLen]
  ct := dataBytes[1+ci.saltLen+ci.nonceLen:]

  // derive key with same params
  key := argon2.IDKey(passwordBytes, salt, ci.argonTime, ci.argonMemory, ci.argonThreads, ci.keyLen)

  block, err := aes.NewCipher(key)
  if nil != err {
    return "", err
  }

  aead, err := cipher.NewGCM(block)
  if nil != err {
    return "", err
  }

  // open will return error if auth fails (wrong password or tampering)
  decrypted, err := aead.Open(nil, nonce, ct, nil)

  // zero key material
  for i := range key {
    key[i] = 0
  }

  if nil != err {
    return "", fmt.Errorf("bad credentials") // wrong password or tampering, do not disclose which one
  }

  return string(decrypted), nil
}
