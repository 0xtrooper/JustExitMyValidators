package wallet

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

const (
	// see: https://github.com/rocket-pool/smartnode/blob/1b2aa51dc1a3c0443921704e2e80454a20971e6f/shared/services/wallet/wallet.go#L29
	DefaultNodeKeyPath       = "m/44'/60'/0'/0/%d"
	MyEtherWalletNodeKeyPath = "m/44'/60'/0'/%d"
	LedgerLiveNodeKeyPath    = "m/44'/60'/%d/0/0"
)

var (
	ErrInvalidWordCount = errors.New("mnemonic must be 12, 15, 18, 21 or 24 words")
)

type NodeRecoveryData struct {
	Seed           []byte `json:"seed"`
	DerivationPath string `json:"derivation_path"`
	Index          uint   `json:"index"`
}

type NodeKey struct {
	recoveryData NodeRecoveryData
	privateKey   *ecdsa.PrivateKey
	publicKey    *ecdsa.PublicKey
}

func NewNodeKeyFromJson(jsonData string) (*NodeKey, error) {
	type wrapper struct {
		WalletData NodeRecoveryData `json:"WalletData"`
	}
	var nodeRecoveryData NodeRecoveryData
	err := json.Unmarshal([]byte(jsonData), &nodeRecoveryData)
	if err != nil {
		return nil, errors.New("could not unmarshal node recovery data from JSON")
	}

	if nodeRecoveryData.Seed == nil {
		return nil, errors.New("seed is required")
	}

	masterKey, err := hdkeychain.NewMaster(nodeRecoveryData.Seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("could not create wallet master key: %s", err.Error())
	}

	return NewNodeKey(masterKey, nodeRecoveryData)
}

// index: the index of the key, default 0
// derivationPath: the derivation path of the key, default DefaultNodeKeyPath
func NewNodeKey(masterKey *hdkeychain.ExtendedKey, recoveryData NodeRecoveryData) (*NodeKey, error) {
	// Get derived key
	derivedKey, err := getNodeDerivedKey(masterKey, recoveryData.DerivationPath, recoveryData.Index)
	if err != nil {
		return nil, err
	}

	// Get private key
	secpPrivateKey, err := derivedKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("could not get node private key: %w", err)
	}
	privateKeyECDSA := secpPrivateKey.ToECDSA()

	// Get public key
	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("could not get node public key")
	}

	nk := &NodeKey{
		recoveryData: recoveryData,
		privateKey:   privateKeyECDSA,
		publicKey:    publicKeyECDSA,
	}

	return nk, nil
}

func (nk *NodeKey) GetPrivateKey() *ecdsa.PrivateKey {
	return nk.privateKey
}

func (nk *NodeKey) GetPublicKey() *ecdsa.PublicKey {
	return nk.publicKey
}

func (nk *NodeKey) Address() common.Address {
	if nk.publicKey == nil {
		return common.Address{}
	}
	return crypto.PubkeyToAddress(*nk.publicKey)
}

func (nk *NodeKey) DerivationPath() string {
	return nk.recoveryData.DerivationPath
}

func (nk *NodeKey) Index() uint {
	return nk.recoveryData.Index
}

func (nk *NodeKey) Seed() []byte {
	return nk.recoveryData.Seed
}

func (nk *NodeKey) Json() (string, error) {
	type wrapper struct {
		WalletData NodeRecoveryData `json:"WalletData"`
	}

	w := wrapper{WalletData: nk.recoveryData}
	data, err := json.Marshal(w)
	if err != nil {
		return "", fmt.Errorf("could not marshal node recovery data to JSON: %w", err)
	}
	return string(data), nil
}

func getNodeDerivedKey(masterKey *hdkeychain.ExtendedKey, derivationPath string, index uint) (*hdkeychain.ExtendedKey, error) {
	derivationPath = fmt.Sprintf(derivationPath, index)

	path, err := accounts.ParseDerivationPath(derivationPath)
	if err != nil {
		return nil, fmt.Errorf("invalid node key derivation path '%s': %w", derivationPath, err)
	}

	key := masterKey
	for i, n := range path {
		key, err = key.Derive(n)
		if err == hdkeychain.ErrInvalidChild {
			return getNodeDerivedKey(masterKey, derivationPath, index+1)
		} else if err != nil {
			return nil, fmt.Errorf("invalid child key at depth %d: %w", i, err)
		}
	}

	return key, nil
}

type WalletInstance struct {
	masterKey *hdkeychain.ExtendedKey

	CustomKey            *NodeKey
	DefaultNodeKey       *NodeKey
	MyEtherWalletNodeKey *NodeKey
	LedgerLiveNodeKey    *NodeKey
}

func NewWallet(mnemonic string, derivationPath string, index uint) (*WalletInstance, error) {
	// normalize and validate mnemonic length
	mnemonic = strings.ReplaceAll(mnemonic, ",", " ")
	mnemonic = strings.TrimSpace(mnemonic)
	numOfWords := len(strings.Fields(mnemonic))
	if numOfWords%3 != 0 || numOfWords < 12 || numOfWords > 24 {
		return nil, ErrInvalidWordCount
	}

	// check if mnemonic is valid
	_, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	seed := bip39.NewSeed(mnemonic, "")

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("could not create wallet master key: %s", err.Error())
	}

	wi := &WalletInstance{
		masterKey: masterKey,
	}
	err = wi.initNodeWallets(seed, derivationPath, index)
	if err != nil {
		return nil, errors.Join(errors.New("failed to initialize one or more node wallets"), err)
	}

	return wi, nil
}

func (wi *WalletInstance) initNodeWallets(seed []byte, derivationPath string, index uint) error {
	var err error
	var firstError error

	if derivationPath != "" {
		wi.CustomKey, err = NewNodeKey(wi.masterKey, NodeRecoveryData{seed, derivationPath, index})
		if err != nil {
			firstError = fmt.Errorf("failed to initialize custom key: %w", err)
		}
	}

	wi.DefaultNodeKey, err = NewNodeKey(wi.masterKey, NodeRecoveryData{seed, DefaultNodeKeyPath, index})
	if err != nil && firstError == nil {
		firstError = fmt.Errorf("failed to initialize default node key: %w", err)
	}

	wi.MyEtherWalletNodeKey, err = NewNodeKey(wi.masterKey, NodeRecoveryData{seed, MyEtherWalletNodeKeyPath, index})
	if err != nil && firstError == nil {
		firstError = fmt.Errorf("failed to initialize MyEtherWallet node key: %w", err)
	}

	wi.LedgerLiveNodeKey, err = NewNodeKey(wi.masterKey, NodeRecoveryData{seed, LedgerLiveNodeKeyPath, index})
	if err != nil && firstError == nil {
		firstError = fmt.Errorf("failed to initialize LedgerLive node key: %w", err)
	}

	return firstError
}
