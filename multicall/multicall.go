package multicall

import (
	"context"
	"errors"
	"fmt"
	multicall "justExitMyValidators/multicall/contracts"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Call struct {
	Method   string         `json:"method"`
	Target   common.Address `json:"target"`
	CallData []byte         `json:"call_data"`
	ABI      *abi.ABI
	output   interface{}
}

type MultiCaller struct {
	ethClient *ethclient.Client
	chainId   int

	abi *abi.ABI

	multicallerAddress common.Address
	calls              []Call
}

type CallResponse struct {
	Success       bool
	ReturnDataRaw []byte `json:"returnData"`
}

type Result struct {
	Success bool `json:"success"`
	Output  interface{}
}

func (call Call) GetMultiCall() multicall.IMulticall3Call {
	return multicall.IMulticall3Call{Target: call.Target, CallData: call.CallData}
}

func NewMultiCaller(client *ethclient.Client, chainId int) (*MultiCaller, error) {
	multicallerAddress, err := getMulticallerAddress(chainId)
	if err != nil {
		return nil, err
	}

	abi, err := multicall.ContractsMetaData.GetAbi()
	if err != nil {
		return nil, err
	}

	return &MultiCaller{
		ethClient:          client,
		chainId:            chainId,
		multicallerAddress: multicallerAddress,

		abi: abi,
	}, nil
}

func (caller *MultiCaller) AddCall(targetAddress common.Address, ABI *abi.ABI, output interface{}, method string, args ...interface{}) error {
	callData, err := ABI.Pack(method, args...)
	if err != nil {
		return fmt.Errorf("error adding call [%s]: %w", method, err)
	}

	call := Call{
		Method:   method,
		Target:   targetAddress,
		CallData: callData,
		ABI:      ABI,
		output:   output,
	}
	caller.calls = append(caller.calls, call)
	return nil
}

type MulticallCall struct {
	Target   common.Address
	CallData []byte
}

func (caller *MultiCaller) GenerateAggregateCalldata(calls []MulticallCall, chainId int) ([]byte, common.Address, error) {
	callData, err := caller.abi.Pack("aggregate", false, calls)
	if err != nil {
		return nil, common.Address{}, errors.Join(errors.New("error packing aggregate3 call"), err)
	}

	toAddress, err := getMulticallerAddress(chainId)
	if err != nil {
		return nil, common.Address{}, errors.Join(errors.New("error getting multicaller address"), err)
	}

	return callData, toAddress, nil
}

func (caller *MultiCaller) Execute(requireSuccess bool, blockNumber uint64) ([]CallResponse, error) {
	var multiCalls = make([]multicall.IMulticall3Call, 0, len(caller.calls))
	for _, call := range caller.calls {
		multiCalls = append(multiCalls, call.GetMultiCall())
	}

	callData, err := caller.abi.Pack("tryAggregate", requireSuccess, multiCalls)
	if err != nil {
		return nil, err
	}

	if blockNumber == 0 {
		blockNumber, err = caller.ethClient.BlockNumber(context.Background())
		if err != nil {
			return nil, err
		}
	}

	resp, err := caller.ethClient.CallContract(context.Background(), ethereum.CallMsg{To: &caller.multicallerAddress, Data: callData}, big.NewInt(int64(blockNumber)))
	if err != nil {
		return nil, err
	}

	responses, err := caller.abi.Unpack("tryAggregate", resp)
	if err != nil {
		return nil, err
	}

	results := make([]CallResponse, len(caller.calls))
	for i, response := range responses[0].([]struct {
		Success    bool   `json:"success"`
		ReturnData []byte `json:"returnData"`
	}) {
		results[i].ReturnDataRaw = response.ReturnData
		results[i].Success = response.Success && len(response.ReturnData) > 0
	}
	return results, nil
}

func (caller *MultiCaller) ExecuteAndParseCalldata(requireSuccess bool, blocknumber uint64) ([]CallResponse, error) {
	results, err := caller.Execute(requireSuccess, blocknumber)
	if err != nil {
		caller.calls = []Call{}
		return results, err
	}

	for i, call := range caller.calls {
		callSuccess := results[i].Success
		if callSuccess {
			err := call.ABI.UnpackIntoInterface(call.output, call.Method, results[i].ReturnDataRaw)
			if err != nil {
				caller.calls = []Call{}
				return results, err
			}
		}
	}
	caller.calls = []Call{}
	return results, err
}

func getMulticallerAddress(chainId int) (common.Address, error) {
	switch chainId {
	case 1:
		return common.HexToAddress("0xcA11bde05977b3631167028862bE2a173976CA11"), nil
	case 17000:
		return common.HexToAddress("0xcA11bde05977b3631167028862bE2a173976CA11"), nil
	default:
		return common.Address{}, errors.New("not found")
	}	
}
