package rocketpoolContracts

import (
	"context"
	"errors"
	"fmt"
	"justExitMyValidators/rocketpoolContracts/minipoolManager"
	"justExitMyValidators/wallet"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Minipool struct {
	Error error

	Number          uint64
	MinipoolAddress common.Address
	ValidatorPubkey wallet.ValidatorPubkey
}

type MinipoolManagerInstance struct {
	contractInstance *minipoolManager.MinipoolManager
	contractAbi      *abi.ABI
}

func NewMinipoolManager(ctx context.Context, rpc *ethclient.Client) (*MinipoolManagerInstance, error) {
	contractAddress, err := GetContractByName(ctx, rpc, "rocketMinipoolManager")
	if err != nil {
		return nil, errors.Join(errors.New("failed to get contract address"), err)
	}

	fmt.Println("contractAddress: ", contractAddress.Hex())

	contractInstance, err := minipoolManager.NewMinipoolManager(contractAddress, rpc)
	if err != nil {
		return nil, errors.Join(errors.New("failed to create contract instance"), err)
	}

	contractAbi, err := minipoolManager.MinipoolManagerMetaData.GetAbi()
	if err != nil {
		return nil, errors.Join(errors.New("failed to get contract abi"), err)
	}

	return &MinipoolManagerInstance{
		contractInstance: contractInstance,
		contractAbi:      contractAbi,
	}, nil
}

func (mm *MinipoolManagerInstance) GetMinipoolCount(ctx context.Context, nodeAddress common.Address) (uint64, error) {
	opts := &bind.CallOpts{
		Context: ctx,
	}

	count, err := mm.contractInstance.GetNodeValidatingMinipoolCount(opts, nodeAddress)
	if err != nil {
		return 0, errors.Join(errors.New("failed to get minipool count"), err)
	}

	return count.Uint64(), nil
}

func (mm *MinipoolManagerInstance) GetMinipools(ctx context.Context, nodeAddress common.Address, start, end uint64) ([]Minipool, error) {
	out := make([]Minipool, end-start)

	opts := &bind.CallOpts{
		Context: ctx,
	}
	for indexToFetch := start; indexToFetch < end; indexToFetch++ {
		indexToStore := indexToFetch - start
		// get minipool address
		minipoolAddress, err := mm.contractInstance.GetNodeValidatingMinipoolAt(opts, nodeAddress, new(big.Int).SetUint64(indexToFetch))
		if err != nil {
			out[indexToStore] = Minipool{
				Error: errors.Join(errors.New("failed to get minipool"), err),
			}
			continue
		}

		// get pubkey
		pubkey, err := mm.contractInstance.GetMinipoolPubkey(opts, minipoolAddress)
		if err != nil {
			out[indexToStore] = Minipool{
				Error: errors.Join(errors.New("failed to get pubkey"), err),
			}
			continue
		}

		out[indexToStore] = Minipool{
			Number:          indexToFetch + 1,
			MinipoolAddress: minipoolAddress,
			ValidatorPubkey: wallet.ValidatorPubkey(pubkey),
		}

	}
	return out, nil
}
