package wallet

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

var (
	ErrInvalidWordCount = errors.New("mnemonic must be 12, 15, 18, 21 or 24 words")
)

type RecoveredWalletData struct {
	Text        string
	NodeAddress string
	Data        string
}

type WalletManager struct {
	CustomKey            *Wallet
	DefaultNodeKey       *Wallet
	MyEtherWalletNodeKey *Wallet
	LedgerLiveNodeKey    *Wallet
}

func NewWalletManager(mnemonic string, derivationPath string, index uint) (*WalletManager, error) {
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

	wm := &WalletManager{}
	err = wm.initNodeWallets(mnemonic, derivationPath, index)
	if err != nil {
		return nil, errors.Join(errors.New("failed to initialize one or more node wallets"), err)
	}

	return wm, nil
}

func (wm *WalletManager) initNodeWallets(mnemonic, derivationPath string, index uint) error {
	// Generate a random password
	password, err := generatePassword(32)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}

	var firstError error
	if derivationPath != "" {
		wm.CustomKey, err = InitializeWallet(derivationPath, index, mnemonic, password)
		if err != nil {
			firstError = fmt.Errorf("failed to initialize custom key: %w", err)
		}
	}

	wm.DefaultNodeKey, err = InitializeWallet(DefaultNodeKeyPath, index, mnemonic, password)
	if err != nil && firstError == nil {
		firstError = fmt.Errorf("failed to initialize default node key: %w", err)
	}

	wm.MyEtherWalletNodeKey, err = InitializeWallet(MyEtherWalletNodeKeyPath, index, mnemonic, password)
	if err != nil && firstError == nil {
		firstError = fmt.Errorf("failed to initialize MyEtherWallet node key: %w", err)
	}

	wm.LedgerLiveNodeKey, err = InitializeWallet(LedgerLiveNodeKeyPath, index, mnemonic, password)
	if err != nil && firstError == nil {
		firstError = fmt.Errorf("failed to initialize LedgerLive node key: %w", err)
	}

	return firstError
}

// RecoverNodeAddresses recovers the node addresses for the wallets that were initialized
func (wm *WalletManager) RecoverWalletData() ([]RecoveredWalletData, error) {
	var recoveredWalletData []RecoveredWalletData

	if wm.CustomKey != nil {
		recoveryData, err := wm.CustomKey.SerializeDataWithPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize custom wallet data: %w", err)
		}
		recoveredWalletData = append(recoveredWalletData, RecoveredWalletData{
			Text:        "Recovered node address using custom derivation path",
			NodeAddress: wm.CustomKey.Address().Hex(),
			Data:        recoveryData,
		})
	}

	if wm.DefaultNodeKey != nil {
		recoveryData, err := wm.DefaultNodeKey.SerializeDataWithPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize default node key data: %w", err)
		}

		recoveredWalletData = append(recoveredWalletData, RecoveredWalletData{
			Text:        "Default Node Key",
			NodeAddress: wm.DefaultNodeKey.Address().Hex(),
			Data:        recoveryData,
		})
	}

	if wm.MyEtherWalletNodeKey != nil {
		recoveryData, err := wm.MyEtherWalletNodeKey.SerializeDataWithPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize MyEtherWallet node key data: %w", err)
		}

		recoveredWalletData = append(recoveredWalletData, RecoveredWalletData{
			Text:        "MyEtherWallet Node Key",
			NodeAddress: wm.MyEtherWalletNodeKey.Address().Hex(),
			Data:        recoveryData,
		})
	}

	if wm.LedgerLiveNodeKey != nil {
		recoveryData, err := wm.LedgerLiveNodeKey.SerializeDataWithPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize LedgerLive node key data: %w", err)
		}

		recoveredWalletData = append(recoveredWalletData, RecoveredWalletData{
			Text:        "LedgerLive Node Key",
			NodeAddress: wm.LedgerLiveNodeKey.Address().Hex(),
			Data:        recoveryData,
		})
	}

	return recoveredWalletData, nil
}
