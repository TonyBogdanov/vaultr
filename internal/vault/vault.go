package vault

import (
  "fmt"
  "io"
  "os"
  "sort"
)

type Vault struct {
  path      string
  dek       string
  passwords []string
  entries   map[string]string
}

func NewVault(path string) *Vault {
  return &Vault{
    path: path,
  }
}

func (v *Vault) Initialize() error {
  dek, err := GenerateDEK()
  if nil != err {
    return err
  }

  v.dek = dek
  v.passwords = []string{}
  v.entries = map[string]string{}

  return nil
}

func (v *Vault) Authenticate(password string) error {
  for _, encrypted := range v.passwords {
    dek, err := Decrypt(password, encrypted, SlowCiphers)

    if nil == err {
      v.dek = dek
      return nil
    }
  }

  return fmt.Errorf("bad credentials")
}

func (v *Vault) Read() error {
  fp, err := os.OpenFile(v.path, os.O_RDONLY, os.ModePerm)
  if nil != err {
    return err
  }

  defer func(fp *os.File) {
    Die(fp.Close())
  }(fp)

  v.passwords = []string{}
  v.entries = map[string]string{}

  for {
    password, err := ReadString(fp)
    if io.EOF == err || (nil == err && "" == password) {
      break
    }

    if nil != err {
      return err
    }

    v.passwords = append(v.passwords, password)
  }

  for {
    key, err := ReadString(fp)
    if io.EOF == err {
      break
    }

    if nil != err {
      return err
    }

    value, err := ReadString(fp)
    if nil != err {
      return err
    }

    v.entries[key] = value
  }

  return nil
}

func (v *Vault) Write() error {
  fp, err := os.OpenFile(v.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
  if nil != err {
    return err
  }

  defer func(fp *os.File) {
    Die(fp.Close())
  }(fp)

  for _, password := range v.passwords {
    if err = WriteString(fp, password); nil != err {
      return err
    }
  }

  if err = WriteString(fp, ""); nil != err {
    return err
  }

  keys := make([]string, 0, len(v.entries))
  for key := range v.entries {
    keys = append(keys, key)
  }

  sort.Strings(keys)
  for _, key := range keys {
    if err = WriteString(fp, key); nil != err {
      return err
    }

    if err = WriteString(fp, v.entries[key]); nil != err {
      return err
    }
  }

  return nil
}

func (v *Vault) AddPassword(password string) error {
  encrypted, err := Encrypt(password, v.dek, SlowCiphers)
  if nil != err {
    return err
  }

  v.passwords = append(v.passwords, encrypted)
  return nil
}

func (v *Vault) RemovePassword(password string) error {
  if 1 == len(v.passwords) {
    return fmt.Errorf("cannot remove last password")
  }

  for i, encrypted := range v.passwords {
    _, ok := Decrypt(password, encrypted, SlowCiphers)

    if nil == ok {
      v.passwords = append(v.passwords[:i], v.passwords[i+1:]...)
      return nil
    }
  }

  return fmt.Errorf("bad credentials")
}

func (v *Vault) SetValue(key, value string) error {
  encrypted, err := Encrypt(v.dek, value, FastCiphers)
  if nil != err {
    return err
  }

  v.entries[key] = encrypted
  return nil
}

func (v *Vault) RemoveValue(key string) error {
  _, found := v.entries[key]
  if !found {
    return fmt.Errorf("key not found")
  }

  delete(v.entries, key)
  return nil
}

func (v *Vault) GetValue(key string) (string, error) {
  value, found := v.entries[key]
  if !found {
    return "", fmt.Errorf("key not found")
  }

  decrypted, err := Decrypt(v.dek, value, FastCiphers)
  if nil != err {
    return "", err
  }

  return decrypted, nil
}

func (v *Vault) GetValues() (map[string]string, error) {
  result := map[string]string{}

  for key := range v.entries {
    value, err := Decrypt(v.dek, v.entries[key], FastCiphers)
    if nil != err {
      return nil, err
    }

    result[key] = value
  }

  return result, nil
}
