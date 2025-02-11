package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	eth2types "github.com/wealdtech/go-eth2-types/v2"
	eth2util "github.com/wealdtech/go-eth2-util"
)

const (
	// see: https://github.com/rocket-pool/smartnode/blob/master/shared/utils/validator/bls.go#L14
	ValidatorKeyPath string = "m/12381/3600/%d/0/0"

	// see: https://github.com/rocket-pool/smartnode/blob/9429cbafac15bc08d27da3b7413a138cb99f6287/shared/utils/wallet/recover-keys.go#L27-L28
	bucketSize  uint64 = 20
	bucketLimit uint64 = 2000
)

const ValidatorPubkeyLength = 48 // bytes
type ValidatorPubkey [ValidatorPubkeyLength]byte

func (vp ValidatorPubkey) String() string {
	b := make([]byte, ValidatorPubkeyLength)
	copy(b, vp[:])
	return ("0x" + hex.EncodeToString(b))
}

type ValidatorData struct {
	Number          uint64
	Index           uint64
	PubKey          string
	MinipoolAddress string
	Status          string
	PrivateKey      string
}

type ValidatorKey struct {
	PublicKey      ValidatorPubkey
	PrivateKey     *eth2types.BLSPrivateKey
	DerivationPath string
	WalletIndex    uint64
}

// based on: https://github.com/rocket-pool/smartnode/blob/9429cbafac15bc08d27da3b7413a138cb99f6287/shared/utils/wallet/recover-keys.go#L31-L105
func (w *Wallet) RecoverValidatorPrivateKeys(validators []ValidatorData) error {
	validatorsToRecover := make(map[string]int)
	for i, validator := range validators {
		validatorsToRecover[validator.PubKey] = i
	}

	// Recover conventionally generated keys
	// see: https://github.com/rocket-pool/smartnode/blob/9429cbafac15bc08d27da3b7413a138cb99f6287/shared/utils/wallet/recover-keys.go#L64-L101
	bucketStart := uint64(0)
	for {
		if bucketStart >= bucketLimit {
			return fmt.Errorf("attempt limit exceeded (%d keys)", bucketLimit)
		}
		bucketEnd := bucketStart + bucketSize
		if bucketEnd > bucketLimit {
			bucketEnd = bucketLimit
		}

		// Get the keys for this bucket
		keys, err := w.GetValidatorKeys(bucketStart, bucketEnd-bucketStart)
		if err != nil {
			return err
		}
		for _, validatorKey := range keys {
			key := validatorKey.PublicKey.String()
			_, exists := validatorsToRecover[key]
			if exists {
				// Found one!
				pkBytes := validatorKey.PrivateKey.Marshal()
				validators[validatorsToRecover[key]].PrivateKey = hex.EncodeToString(pkBytes)
				delete(validatorsToRecover, key)
			}
		}

		if len(validatorsToRecover) == 0 {
			// All keys recovered!
			break
		}

		// Run another iteration with the next bucket
		bucketStart = bucketEnd
	}
	return nil
}

// Recover a set of validator keys by their public key
// see: https://github.com/rocket-pool/smartnode/blob/0729581e82f46755593d426ab6cdb508ebf7b82b/rocketpool-daemon/common/validator/validator-manager.go#L130-L153
func (w *Wallet) GetValidatorKeys(startIndex uint64, length uint64) ([]ValidatorKey, error) {
	validatorKeys := make([]ValidatorKey, 0, length)
	for index := startIndex; index < startIndex+length; index++ {
		key, path, err := w.getValidatorPrivateKey(index)
		if err != nil {
			return nil, fmt.Errorf("error getting validator key for index %d: %w", index, err)
		}
		validatorKey := ValidatorKey{
			PublicKey:      ValidatorPubkey(key.PublicKey().Marshal()),
			PrivateKey:     key,
			DerivationPath: path,
			WalletIndex:    index,
		}
		validatorKeys = append(validatorKeys, validatorKey)
	}

	return validatorKeys, nil
}

// Initialize BLS support
// see: https://github.com/rocket-pool/smartnode/blob/9429cbafac15bc08d27da3b7413a138cb99f6287/shared/utils/validator/bls.go#L23-L32
var initBLS sync.Once

func initializeBLS() error {
	var err error
	initBLS.Do(func() {
		err = eth2types.InitBLS()
	})
	return err
}

// see: https://github.com/rocket-pool/smartnode/blob/9429cbafac15bc08d27da3b7413a138cb99f6287/shared/services/wallet/validator.go#L301-L328
func (w *Wallet) getValidatorPrivateKey(index uint64) (*eth2types.BLSPrivateKey, string, error) {
	// Get derivation path
	derivationPath := fmt.Sprintf(ValidatorKeyPath, index)

	// Initialize BLS support
	if err := initializeBLS(); err != nil {
		return nil, "", errors.Join(errors.New("failed to initialize BLS support"), err)
	}

	// Get private key
	privateKey, err := eth2util.PrivateKeyFromSeedAndPath(w.seed, derivationPath)
	if err != nil {
		return nil, "", fmt.Errorf("could not get validator %d private key: %w", index, err)
	}

	// Return
	return privateKey, derivationPath, nil
}
