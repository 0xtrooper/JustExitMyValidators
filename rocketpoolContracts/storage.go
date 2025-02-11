package rocketpoolContracts

import (
	"context"
	"errors"
	"fmt"
	"justExitMyValidators/rocketpoolContracts/storage"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	mainnetRocketStorageAddressStr = "0x1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46"
	holeskyRocketStorageAddressStr = "0x594Fb75D3dc2DFa0150Ad03F99F97817747dd4E1"
)

func GetContractByName(ctx context.Context, rpc *ethclient.Client, networkId uint64, contractName string) (common.Address, error) {
	var rocketStorageAddressStr string
	switch networkId {
	case 1:
		rocketStorageAddressStr = mainnetRocketStorageAddressStr
	case 17000:
		rocketStorageAddressStr = holeskyRocketStorageAddressStr
	default:
		return common.Address{}, errors.New("unsupported network id")
	}

	fmt.Println("rocketStorageAddressStr: ", rocketStorageAddressStr)

	rocketStorageAddress := common.HexToAddress(rocketStorageAddressStr)
	storageInstance, err := storage.NewStorage(rocketStorageAddress, rpc)
	if err != nil {
		return common.Address{}, errors.Join(errors.New("failed to create storage instance"), err)
	}

	opts := &bind.CallOpts{
		Context: ctx,
	}
	return storageInstance.GetAddress(opts, crypto.Keccak256Hash([]byte("contract.address"+contractName)))
}
