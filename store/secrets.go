package store

import (
	"encoding/json"
	"forta-network/go-agent/botdb"
	"os"
)

type Secrets struct {
	Aws struct {
		AccessKey string `json:"accessKey"`
		SecretKey string `json:"secretKey"`
	} `json:"aws"`
	JsonRpc struct {
		Ethereum  string `json:"ethereum"`
		Optimism  string `json:"optimism"`
		Arbitrum  string `json:"arbitrum"`
		Palm      string `json:"palm"`
		Polygon   string `json:"polygon"`
		Avalanche string `json:"avalanche"`
	} `json:"jsonRpc"`
}

func LoadSecretsFromFile(filename string) (*Secrets, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var secrets Secrets
	if err := json.Unmarshal(b, &secrets); err != nil {
		return nil, err
	}
	return &secrets, nil
}

func LoadSecrets() (*Secrets, error) {
	db, err := botdb.NewDefaultClient("https://research.forta.network")
	if err != nil {
		return nil, err
	}
	resp, err := db.Get(botdb.ScopeOwner, "secrets.json")
	if err != nil {
		return nil, err
	}
	var secrets Secrets
	if err := json.Unmarshal(resp, &secrets); err != nil {
		return nil, err
	}
	return &secrets, nil
}
