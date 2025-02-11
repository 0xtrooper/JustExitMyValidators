package rocketpoolContracts

import (
	"context"
	"errors"
	"justExitMyValidators/multicall"
	"justExitMyValidators/rocketpoolContracts/minipoolManager"
	"justExitMyValidators/wallet"
	"log/slog"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Minipool struct {
	Number          uint64
	MinipoolAddress common.Address
	ValidatorPubkey wallet.ValidatorPubkey
}

type MinipoolManagerInstance struct {
	contractAddress  common.Address
	contractInstance *minipoolManager.MinipoolManager
	contractAbi      *abi.ABI
	multiCaller      *multicall.MultiCaller
}

func NewMinipoolManager(ctx context.Context, rpc *ethclient.Client, logger *slog.Logger) (*MinipoolManagerInstance, error) {
	networkId, err := rpc.NetworkID(ctx)
	if err != nil {
		return nil, errors.Join(errors.New("failed to get network id"), err)
	}

	contractAddress, err := GetContractByName(ctx, rpc, networkId.Uint64(), "rocketMinipoolManager")
	if err != nil {
		return nil, errors.Join(errors.New("failed to get contract address"), err)
	}

	logger.Debug("fetched minipool manger address", slog.String("minipoolManagerAddress", contractAddress.Hex()))

	contractInstance, err := minipoolManager.NewMinipoolManager(contractAddress, rpc)
	if err != nil {
		return nil, errors.Join(errors.New("failed to create contract instance"), err)
	}

	contractAbi, err := minipoolManager.MinipoolManagerMetaData.GetAbi()
	if err != nil {
		return nil, errors.Join(errors.New("failed to get contract abi"), err)
	}

	multiCaller, err := multicall.NewMultiCaller(rpc, int(networkId.Int64()))
	if err != nil {
		return nil, errors.Join(errors.New("failed to create multicaller"), err)
	}

	return &MinipoolManagerInstance{
		contractAddress:  contractAddress,
		contractInstance: contractInstance,
		contractAbi:      contractAbi,
		multiCaller:      multiCaller,
	}, nil
}

// get minipool count for a given node address
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

// get minipool address and pubkey for a given node address
func (mm *MinipoolManagerInstance) GetMinipools(ctx context.Context, nodeAddress common.Address, start, end uint64) ([]Minipool, error) {
	minipoolAddresses := make([]common.Address, end-start)
	for indexToFetch := start; indexToFetch < end; indexToFetch++ {
		indexToStore := indexToFetch - start
		mm.multiCaller.AddCall(mm.contractAddress, mm.contractAbi, &minipoolAddresses[indexToStore], "getNodeValidatingMinipoolAt", nodeAddress, new(big.Int).SetUint64(indexToFetch))
	}

	callResponseArrayAddresses, err := mm.multiCaller.ExecuteAndParseCalldata(false, 0)
	if err != nil {
		return nil, errors.Join(errors.New("failed to execute multicall"), err)
	}

	if len(callResponseArrayAddresses) != len(minipoolAddresses) {
		return nil, errors.New("unexpected response length")
	}

	pubKeys := make([][]byte, end-start)
	for indexToFetch := start; indexToFetch < end; indexToFetch++ {
		indexToStore := indexToFetch - start

		if !callResponseArrayAddresses[indexToStore].Success {
			return nil, errors.New("call failed")
		}

		mm.multiCaller.AddCall(mm.contractAddress, mm.contractAbi, &pubKeys[indexToStore], "getMinipoolPubkey", minipoolAddresses[indexToStore])
	}

	callResponseArrayPubkeys, err := mm.multiCaller.ExecuteAndParseCalldata(false, 0)
	if err != nil {
		return nil, errors.Join(errors.New("failed to execute multicall"), err)
	}

	if len(callResponseArrayPubkeys) != len(pubKeys) {
		return nil, errors.New("unexpected response length")
	}

	out := make([]Minipool, end-start)
	for indexToFetch := start; indexToFetch < end; indexToFetch++ {
		indexToStore := indexToFetch - start

		if !callResponseArrayPubkeys[indexToStore].Success {
			return nil, errors.New("call failed")
		}

		out[indexToStore] = Minipool{
			Number:          indexToFetch + 1,
			MinipoolAddress: minipoolAddresses[indexToStore],
			ValidatorPubkey: wallet.ValidatorPubkey(pubKeys[indexToStore]),
		}
	}
	return out, nil
}
