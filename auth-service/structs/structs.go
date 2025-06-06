package structs

import (
	"errors"
	"main/encrypt"
)

type Payload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"fullName"`
}

type ResUser struct {
	FullName string `json:"fullName"`
	UUID     string `json:"uuid"`
}

func (p Payload) ValidateFields() error {
	if p.Email == "" || p.FullName == "" || p.Password == "" {
		return errors.New("all fields must be filled")
	}
	return nil
}

func (data Payload) EncryptPayload(key string) (Payload, error) {

	encryptedEmail, err := encrypt.EncryptDataStaticIV(data.Email, key)
	if err != nil {
		return Payload{}, err
	}

	encryptedName, err := encrypt.EncryptDataRandomIV(data.FullName, key)
	if err != nil {
		return Payload{}, err
	}

	return Payload{Email: encryptedEmail, FullName: encryptedName}, nil
}

func (encrypted Payload) DecryptPayload(key string) (Payload, error) {
	decryptedEmail, err := encrypt.DecryptDataStaticIV(encrypted.Email, key)
	if err != nil {
		return Payload{}, err
	}

	decryptedName, err := encrypt.DecryptDataRandomIV(encrypted.FullName, key)
	if err != nil {
		return Payload{}, err
	}

	return Payload{Email: decryptedEmail, FullName: decryptedName}, nil
}
