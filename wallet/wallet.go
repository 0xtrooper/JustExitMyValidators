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

	"github.com/rocket-pool/node-manager-core/wallet"
	eth2ks "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

const (
	// see: https://github.com/rocket-pool/smartnode/blob/1b2aa51dc1a3c0443921704e2e80454a20971e6f/shared/services/wallet/wallet.go#L29
	DefaultNodeKeyPath       = "m/44'/60'/0'/0/%d"
	MyEtherWalletNodeKeyPath = "m/44'/60'/0'/%d"
	LedgerLiveNodeKeyPath    = "m/44'/60'/%d/0/0"
)

type Wallet struct {
	walletData *wallet.LocalWalletData
	seed       []byte
	password   string
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// loads wallet from JSON string
func LoadWallet(jsonData string, password string) (*Wallet, error) {
	walletRecoveryData := &wallet.LocalWalletData{}
	err := json.Unmarshal([]byte(jsonData), walletRecoveryData)
	if err != nil {
		return nil, errors.New("could not unmarshal wallet recovery data from JSON")
	}

	return LoadWalletFromJson(walletRecoveryData, password)
}

// see: https://github.com/rocket-pool/node-manager-core/blob/dfd914e4e77be54fbbf4ebb8e47d7578146bf429/node/wallet/local-wallet-manager.go#L156-L202
func LoadWalletFromJson(data *wallet.LocalWalletData, password string) (*Wallet, error) {
	encryptor := eth2ks.New()
	if data.Version != encryptor.Version() {
		return nil, fmt.Errorf("invalid wallet keystore version %d, expected %d", data.Version, encryptor.Version())
	}

	if data.Name != encryptor.Name() {
		return nil, fmt.Errorf("invalid wallet keystore name %s, expected %s", data.Name, encryptor.Name())
	}

	// Decrypt the seed
	var err error
	seed, err := encryptor.Decrypt(data.Crypto, password)
	if err != nil {
		return nil, fmt.Errorf("error decrypting wallet keystore: %w", err)
	}

	return NewWallet(data, seed, password)
}

// see: https://github.com/rocket-pool/node-manager-core/blob/dfd914e4e77be54fbbf4ebb8e47d7578146bf429/node/wallet/local-wallet-manager.go#L108-L135
func InitializeWallet(derivationPath string, walletIndex uint, mnemonic string, password string) (*Wallet, error) {
	if derivationPath == "" {
		derivationPath = DefaultNodeKeyPath
	}

	// Generate the seed from the mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	encryptor := eth2ks.New()
	encryptedSeed, err := encryptor.Encrypt(seed, password)
	if err != nil {
		return nil, fmt.Errorf("error encrypting wallet seed: %w", err)
	}

	data := &wallet.LocalWalletData{
		Crypto:         encryptedSeed,
		Name:           encryptor.Name(),
		Version:        encryptor.Version(),
		DerivationPath: derivationPath,
		WalletIndex:    walletIndex,
	}

	return NewWallet(data, seed, password)
}

// see: https://github.com/rocket-pool/node-manager-core/blob/dfd914e4e77be54fbbf4ebb8e47d7578146bf429/node/wallet/local-wallet-manager.go#L164-L202
func NewWallet(data *wallet.LocalWalletData, seed []byte, password string) (*Wallet, error) {
	// Create the master key
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("error creating wallet master key: %w", err)
	}

	// Handle an empty derivation path
	if data.DerivationPath == "" {
		data.DerivationPath = wallet.DefaultNodeKeyPath
	}

	// Get the derived key
	var derivedKey *hdkeychain.ExtendedKey
	var index uint
	if strings.Contains(data.DerivationPath, "%d") {
		derivedKey, index, err = getDerivedKey(masterKey, data.DerivationPath, data.WalletIndex)
	} else {
		derivedKey, err = getDerivedKeyFixedPath(masterKey, data.DerivationPath)
	}
	if err != nil {
		return nil, fmt.Errorf("error getting node wallet derived key: %w", err)
	}
	data.WalletIndex = index // Update the index in case of the ErrInvalidChild issue

	// Get the private key from it
	privateKey, err := derivedKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("error getting node wallet private key: %w", err)
	}
	privateKeyECDSA := privateKey.ToECDSA()

	w := &Wallet{
		walletData: data,
		seed:       seed,
		password:   password,
		privateKey: privateKeyECDSA,
		publicKey:  privateKeyECDSA.Public().(*ecdsa.PublicKey),
	}

	return w, nil
}

func (w *Wallet) Address() common.Address {
	if w.publicKey == nil {
		return common.Address{}
	}
	return crypto.PubkeyToAddress(*w.publicKey)
}

func (w *Wallet) SerializeData() (string, error) {
	bytes, err := json.Marshal(w.walletData)
	if err != nil {
		return "", fmt.Errorf("error serializing wallet data: %w", err)
	}
	return string(bytes), nil
}

func (w *Wallet) SerializeDataWithPassword() (string, error) {
	data := struct {
		WalletData     *wallet.LocalWalletData
		WalletPassword string
	}{
		WalletData:     w.walletData,
		WalletPassword: w.password,
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("error serializing wallet data: %w", err)
	}
	return string(bytes), nil
}

// see: https://github.com/rocket-pool/node-manager-core/blob/dfd914e4e77be54fbbf4ebb8e47d7578146bf429/node/wallet/local-wallet-manager.go#L274-L297
func getDerivedKey(masterKey *hdkeychain.ExtendedKey, derivationPath string, index uint) (*hdkeychain.ExtendedKey, uint, error) {
	formattedDerivationPath := fmt.Sprintf(derivationPath, index)

	// Parse derivation path
	path, err := accounts.ParseDerivationPath(formattedDerivationPath)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid node key derivation path '%s': %w", formattedDerivationPath, err)
	}

	// Follow derivation path
	key := masterKey
	for i, n := range path {
		key, err = key.Derive(n)
		if err == hdkeychain.ErrInvalidChild {
			// Start over with the next index
			return getDerivedKey(masterKey, derivationPath, index+1)
		} else if err != nil {
			return nil, 0, fmt.Errorf("invalid child key at depth %d: %w", i, err)
		}
	}

	// Return
	return key, index, nil
}

// based on getNodeDerivedKey, with fixed path, no index
func getDerivedKeyFixedPath(masterKey *hdkeychain.ExtendedKey, derivationPath string) (*hdkeychain.ExtendedKey, error) {
	path, err := accounts.ParseDerivationPath(derivationPath)
	if err != nil {
		return nil, fmt.Errorf("invalid node key derivation path '%s': %w", derivationPath, err)
	}

	key := masterKey
	for i, n := range path {
		key, err = key.Derive(n)
		if err != nil {
			return nil, fmt.Errorf("invalid child key at depth %d: %w", i, err)
		}
	}

	return key, nil
}
