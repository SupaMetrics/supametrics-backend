package utils

import (
	"encoding/json"
	"net/http"
)

type IPInfo struct {
	CountryName string `json:"countryName"`
}

func GetCountryFromIP(ip string) (string, error) {
	resp, err := http.Get("https://freeipapi.com/api/json/" + ip)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var info IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	return info.CountryName, nil
}

const InsertString = `
INSERT INTO users (uuid, full_name, email, password, country, ip, user_agent)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`
