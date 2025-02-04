// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package minipoolManager

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// MinipoolManagerMetaData contains all meta data concerning the MinipoolManager contract.
var MinipoolManagerMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"contractRocketStorageInterface\",\"name\":\"_rocketStorageAddress\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"minipool\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"time\",\"type\":\"uint256\"}],\"name\":\"BeginBondReduction\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"minipool\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"member\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"time\",\"type\":\"uint256\"}],\"name\":\"CancelReductionVoted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"minipool\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"node\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"time\",\"type\":\"uint256\"}],\"name\":\"MinipoolCreated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"minipool\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"node\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"time\",\"type\":\"uint256\"}],\"name\":\"MinipoolDestroyed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"minipool\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"time\",\"type\":\"uint256\"}],\"name\":\"ReductionCancelled\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_salt\",\"type\":\"uint256\"}],\"name\":\"createMinipool\",\"outputs\":[{\"internalType\":\"contractRocketMinipoolInterface\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_salt\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"_validatorPubkey\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"_bondAmount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_currentBalance\",\"type\":\"uint256\"}],\"name\":\"createVacantMinipool\",\"outputs\":[{\"internalType\":\"contractRocketMinipoolInterface\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"}],\"name\":\"decrementNodeStakingMinipoolCount\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"destroyMinipool\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getActiveMinipoolCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getFinalisedMinipoolCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_index\",\"type\":\"uint256\"}],\"name\":\"getMinipoolAt\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_pubkey\",\"type\":\"bytes\"}],\"name\":\"getMinipoolByPubkey\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getMinipoolCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_offset\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_limit\",\"type\":\"uint256\"}],\"name\":\"getMinipoolCountPerStatus\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"initialisedCount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"prelaunchCount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"stakingCount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"withdrawableCount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"dissolvedCount\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_minipoolAddress\",\"type\":\"address\"}],\"name\":\"getMinipoolDepositType\",\"outputs\":[{\"internalType\":\"enumMinipoolDeposit\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_minipoolAddress\",\"type\":\"address\"}],\"name\":\"getMinipoolDestroyed\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_minipoolAddress\",\"type\":\"address\"}],\"name\":\"getMinipoolExists\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_minipoolAddress\",\"type\":\"address\"}],\"name\":\"getMinipoolPubkey\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_minipoolAddress\",\"type\":\"address\"}],\"name\":\"getMinipoolRPLSlashed\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_minipoolAddress\",\"type\":\"address\"}],\"name\":\"getMinipoolWithdrawalCredentials\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"}],\"name\":\"getNodeActiveMinipoolCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"}],\"name\":\"getNodeFinalisedMinipoolCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_index\",\"type\":\"uint256\"}],\"name\":\"getNodeMinipoolAt\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"}],\"name\":\"getNodeMinipoolCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"}],\"name\":\"getNodeStakingMinipoolCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_depositSize\",\"type\":\"uint256\"}],\"name\":\"getNodeStakingMinipoolCountBySize\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_index\",\"type\":\"uint256\"}],\"name\":\"getNodeValidatingMinipoolAt\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"}],\"name\":\"getNodeValidatingMinipoolCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_offset\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_limit\",\"type\":\"uint256\"}],\"name\":\"getPrelaunchMinipools\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getStakingMinipoolCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_index\",\"type\":\"uint256\"}],\"name\":\"getVacantMinipoolAt\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getVacantMinipoolCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"}],\"name\":\"incrementNodeFinalisedMinipoolCount\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"}],\"name\":\"incrementNodeStakingMinipoolCount\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"removeVacantMinipool\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_pubkey\",\"type\":\"bytes\"}],\"name\":\"setMinipoolPubkey\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_nodeAddress\",\"type\":\"address\"}],\"name\":\"tryDistribute\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_previousBond\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_newBond\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_previousFee\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_newFee\",\"type\":\"uint256\"}],\"name\":\"updateNodeStakingMinipoolCount\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"version\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// MinipoolManagerABI is the input ABI used to generate the binding from.
// Deprecated: Use MinipoolManagerMetaData.ABI instead.
var MinipoolManagerABI = MinipoolManagerMetaData.ABI

// MinipoolManager is an auto generated Go binding around an Ethereum contract.
type MinipoolManager struct {
	MinipoolManagerCaller     // Read-only binding to the contract
	MinipoolManagerTransactor // Write-only binding to the contract
	MinipoolManagerFilterer   // Log filterer for contract events
}

// MinipoolManagerCaller is an auto generated read-only Go binding around an Ethereum contract.
type MinipoolManagerCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MinipoolManagerTransactor is an auto generated write-only Go binding around an Ethereum contract.
type MinipoolManagerTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MinipoolManagerFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type MinipoolManagerFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MinipoolManagerSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type MinipoolManagerSession struct {
	Contract     *MinipoolManager  // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// MinipoolManagerCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type MinipoolManagerCallerSession struct {
	Contract *MinipoolManagerCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts          // Call options to use throughout this session
}

// MinipoolManagerTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type MinipoolManagerTransactorSession struct {
	Contract     *MinipoolManagerTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts          // Transaction auth options to use throughout this session
}

// MinipoolManagerRaw is an auto generated low-level Go binding around an Ethereum contract.
type MinipoolManagerRaw struct {
	Contract *MinipoolManager // Generic contract binding to access the raw methods on
}

// MinipoolManagerCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type MinipoolManagerCallerRaw struct {
	Contract *MinipoolManagerCaller // Generic read-only contract binding to access the raw methods on
}

// MinipoolManagerTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type MinipoolManagerTransactorRaw struct {
	Contract *MinipoolManagerTransactor // Generic write-only contract binding to access the raw methods on
}

// NewMinipoolManager creates a new instance of MinipoolManager, bound to a specific deployed contract.
func NewMinipoolManager(address common.Address, backend bind.ContractBackend) (*MinipoolManager, error) {
	contract, err := bindMinipoolManager(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &MinipoolManager{MinipoolManagerCaller: MinipoolManagerCaller{contract: contract}, MinipoolManagerTransactor: MinipoolManagerTransactor{contract: contract}, MinipoolManagerFilterer: MinipoolManagerFilterer{contract: contract}}, nil
}

// NewMinipoolManagerCaller creates a new read-only instance of MinipoolManager, bound to a specific deployed contract.
func NewMinipoolManagerCaller(address common.Address, caller bind.ContractCaller) (*MinipoolManagerCaller, error) {
	contract, err := bindMinipoolManager(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &MinipoolManagerCaller{contract: contract}, nil
}

// NewMinipoolManagerTransactor creates a new write-only instance of MinipoolManager, bound to a specific deployed contract.
func NewMinipoolManagerTransactor(address common.Address, transactor bind.ContractTransactor) (*MinipoolManagerTransactor, error) {
	contract, err := bindMinipoolManager(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &MinipoolManagerTransactor{contract: contract}, nil
}

// NewMinipoolManagerFilterer creates a new log filterer instance of MinipoolManager, bound to a specific deployed contract.
func NewMinipoolManagerFilterer(address common.Address, filterer bind.ContractFilterer) (*MinipoolManagerFilterer, error) {
	contract, err := bindMinipoolManager(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &MinipoolManagerFilterer{contract: contract}, nil
}

// bindMinipoolManager binds a generic wrapper to an already deployed contract.
func bindMinipoolManager(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := MinipoolManagerMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_MinipoolManager *MinipoolManagerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _MinipoolManager.Contract.MinipoolManagerCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_MinipoolManager *MinipoolManagerRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _MinipoolManager.Contract.MinipoolManagerTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_MinipoolManager *MinipoolManagerRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _MinipoolManager.Contract.MinipoolManagerTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_MinipoolManager *MinipoolManagerCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _MinipoolManager.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_MinipoolManager *MinipoolManagerTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _MinipoolManager.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_MinipoolManager *MinipoolManagerTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _MinipoolManager.Contract.contract.Transact(opts, method, params...)
}

// GetActiveMinipoolCount is a free data retrieval call binding the contract method 0xce9b79ad.
//
// Solidity: function getActiveMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetActiveMinipoolCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getActiveMinipoolCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetActiveMinipoolCount is a free data retrieval call binding the contract method 0xce9b79ad.
//
// Solidity: function getActiveMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetActiveMinipoolCount() (*big.Int, error) {
	return _MinipoolManager.Contract.GetActiveMinipoolCount(&_MinipoolManager.CallOpts)
}

// GetActiveMinipoolCount is a free data retrieval call binding the contract method 0xce9b79ad.
//
// Solidity: function getActiveMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetActiveMinipoolCount() (*big.Int, error) {
	return _MinipoolManager.Contract.GetActiveMinipoolCount(&_MinipoolManager.CallOpts)
}

// GetFinalisedMinipoolCount is a free data retrieval call binding the contract method 0xd1ea6ce0.
//
// Solidity: function getFinalisedMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetFinalisedMinipoolCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getFinalisedMinipoolCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetFinalisedMinipoolCount is a free data retrieval call binding the contract method 0xd1ea6ce0.
//
// Solidity: function getFinalisedMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetFinalisedMinipoolCount() (*big.Int, error) {
	return _MinipoolManager.Contract.GetFinalisedMinipoolCount(&_MinipoolManager.CallOpts)
}

// GetFinalisedMinipoolCount is a free data retrieval call binding the contract method 0xd1ea6ce0.
//
// Solidity: function getFinalisedMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetFinalisedMinipoolCount() (*big.Int, error) {
	return _MinipoolManager.Contract.GetFinalisedMinipoolCount(&_MinipoolManager.CallOpts)
}

// GetMinipoolAt is a free data retrieval call binding the contract method 0xeff7319f.
//
// Solidity: function getMinipoolAt(uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerCaller) GetMinipoolAt(opts *bind.CallOpts, _index *big.Int) (common.Address, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getMinipoolAt", _index)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetMinipoolAt is a free data retrieval call binding the contract method 0xeff7319f.
//
// Solidity: function getMinipoolAt(uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerSession) GetMinipoolAt(_index *big.Int) (common.Address, error) {
	return _MinipoolManager.Contract.GetMinipoolAt(&_MinipoolManager.CallOpts, _index)
}

// GetMinipoolAt is a free data retrieval call binding the contract method 0xeff7319f.
//
// Solidity: function getMinipoolAt(uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerCallerSession) GetMinipoolAt(_index *big.Int) (common.Address, error) {
	return _MinipoolManager.Contract.GetMinipoolAt(&_MinipoolManager.CallOpts, _index)
}

// GetMinipoolByPubkey is a free data retrieval call binding the contract method 0xcf6a4763.
//
// Solidity: function getMinipoolByPubkey(bytes _pubkey) view returns(address)
func (_MinipoolManager *MinipoolManagerCaller) GetMinipoolByPubkey(opts *bind.CallOpts, _pubkey []byte) (common.Address, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getMinipoolByPubkey", _pubkey)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetMinipoolByPubkey is a free data retrieval call binding the contract method 0xcf6a4763.
//
// Solidity: function getMinipoolByPubkey(bytes _pubkey) view returns(address)
func (_MinipoolManager *MinipoolManagerSession) GetMinipoolByPubkey(_pubkey []byte) (common.Address, error) {
	return _MinipoolManager.Contract.GetMinipoolByPubkey(&_MinipoolManager.CallOpts, _pubkey)
}

// GetMinipoolByPubkey is a free data retrieval call binding the contract method 0xcf6a4763.
//
// Solidity: function getMinipoolByPubkey(bytes _pubkey) view returns(address)
func (_MinipoolManager *MinipoolManagerCallerSession) GetMinipoolByPubkey(_pubkey []byte) (common.Address, error) {
	return _MinipoolManager.Contract.GetMinipoolByPubkey(&_MinipoolManager.CallOpts, _pubkey)
}

// GetMinipoolCount is a free data retrieval call binding the contract method 0xae4d0bed.
//
// Solidity: function getMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetMinipoolCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getMinipoolCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetMinipoolCount is a free data retrieval call binding the contract method 0xae4d0bed.
//
// Solidity: function getMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetMinipoolCount() (*big.Int, error) {
	return _MinipoolManager.Contract.GetMinipoolCount(&_MinipoolManager.CallOpts)
}

// GetMinipoolCount is a free data retrieval call binding the contract method 0xae4d0bed.
//
// Solidity: function getMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetMinipoolCount() (*big.Int, error) {
	return _MinipoolManager.Contract.GetMinipoolCount(&_MinipoolManager.CallOpts)
}

// GetMinipoolCountPerStatus is a free data retrieval call binding the contract method 0x3b5ecefa.
//
// Solidity: function getMinipoolCountPerStatus(uint256 _offset, uint256 _limit) view returns(uint256 initialisedCount, uint256 prelaunchCount, uint256 stakingCount, uint256 withdrawableCount, uint256 dissolvedCount)
func (_MinipoolManager *MinipoolManagerCaller) GetMinipoolCountPerStatus(opts *bind.CallOpts, _offset *big.Int, _limit *big.Int) (struct {
	InitialisedCount  *big.Int
	PrelaunchCount    *big.Int
	StakingCount      *big.Int
	WithdrawableCount *big.Int
	DissolvedCount    *big.Int
}, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getMinipoolCountPerStatus", _offset, _limit)

	outstruct := new(struct {
		InitialisedCount  *big.Int
		PrelaunchCount    *big.Int
		StakingCount      *big.Int
		WithdrawableCount *big.Int
		DissolvedCount    *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.InitialisedCount = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.PrelaunchCount = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.StakingCount = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)
	outstruct.WithdrawableCount = *abi.ConvertType(out[3], new(*big.Int)).(**big.Int)
	outstruct.DissolvedCount = *abi.ConvertType(out[4], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// GetMinipoolCountPerStatus is a free data retrieval call binding the contract method 0x3b5ecefa.
//
// Solidity: function getMinipoolCountPerStatus(uint256 _offset, uint256 _limit) view returns(uint256 initialisedCount, uint256 prelaunchCount, uint256 stakingCount, uint256 withdrawableCount, uint256 dissolvedCount)
func (_MinipoolManager *MinipoolManagerSession) GetMinipoolCountPerStatus(_offset *big.Int, _limit *big.Int) (struct {
	InitialisedCount  *big.Int
	PrelaunchCount    *big.Int
	StakingCount      *big.Int
	WithdrawableCount *big.Int
	DissolvedCount    *big.Int
}, error) {
	return _MinipoolManager.Contract.GetMinipoolCountPerStatus(&_MinipoolManager.CallOpts, _offset, _limit)
}

// GetMinipoolCountPerStatus is a free data retrieval call binding the contract method 0x3b5ecefa.
//
// Solidity: function getMinipoolCountPerStatus(uint256 _offset, uint256 _limit) view returns(uint256 initialisedCount, uint256 prelaunchCount, uint256 stakingCount, uint256 withdrawableCount, uint256 dissolvedCount)
func (_MinipoolManager *MinipoolManagerCallerSession) GetMinipoolCountPerStatus(_offset *big.Int, _limit *big.Int) (struct {
	InitialisedCount  *big.Int
	PrelaunchCount    *big.Int
	StakingCount      *big.Int
	WithdrawableCount *big.Int
	DissolvedCount    *big.Int
}, error) {
	return _MinipoolManager.Contract.GetMinipoolCountPerStatus(&_MinipoolManager.CallOpts, _offset, _limit)
}

// GetMinipoolDepositType is a free data retrieval call binding the contract method 0x5ea1a6e2.
//
// Solidity: function getMinipoolDepositType(address _minipoolAddress) view returns(uint8)
func (_MinipoolManager *MinipoolManagerCaller) GetMinipoolDepositType(opts *bind.CallOpts, _minipoolAddress common.Address) (uint8, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getMinipoolDepositType", _minipoolAddress)

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// GetMinipoolDepositType is a free data retrieval call binding the contract method 0x5ea1a6e2.
//
// Solidity: function getMinipoolDepositType(address _minipoolAddress) view returns(uint8)
func (_MinipoolManager *MinipoolManagerSession) GetMinipoolDepositType(_minipoolAddress common.Address) (uint8, error) {
	return _MinipoolManager.Contract.GetMinipoolDepositType(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolDepositType is a free data retrieval call binding the contract method 0x5ea1a6e2.
//
// Solidity: function getMinipoolDepositType(address _minipoolAddress) view returns(uint8)
func (_MinipoolManager *MinipoolManagerCallerSession) GetMinipoolDepositType(_minipoolAddress common.Address) (uint8, error) {
	return _MinipoolManager.Contract.GetMinipoolDepositType(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolDestroyed is a free data retrieval call binding the contract method 0xa757987a.
//
// Solidity: function getMinipoolDestroyed(address _minipoolAddress) view returns(bool)
func (_MinipoolManager *MinipoolManagerCaller) GetMinipoolDestroyed(opts *bind.CallOpts, _minipoolAddress common.Address) (bool, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getMinipoolDestroyed", _minipoolAddress)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// GetMinipoolDestroyed is a free data retrieval call binding the contract method 0xa757987a.
//
// Solidity: function getMinipoolDestroyed(address _minipoolAddress) view returns(bool)
func (_MinipoolManager *MinipoolManagerSession) GetMinipoolDestroyed(_minipoolAddress common.Address) (bool, error) {
	return _MinipoolManager.Contract.GetMinipoolDestroyed(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolDestroyed is a free data retrieval call binding the contract method 0xa757987a.
//
// Solidity: function getMinipoolDestroyed(address _minipoolAddress) view returns(bool)
func (_MinipoolManager *MinipoolManagerCallerSession) GetMinipoolDestroyed(_minipoolAddress common.Address) (bool, error) {
	return _MinipoolManager.Contract.GetMinipoolDestroyed(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolExists is a free data retrieval call binding the contract method 0x606bb62e.
//
// Solidity: function getMinipoolExists(address _minipoolAddress) view returns(bool)
func (_MinipoolManager *MinipoolManagerCaller) GetMinipoolExists(opts *bind.CallOpts, _minipoolAddress common.Address) (bool, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getMinipoolExists", _minipoolAddress)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// GetMinipoolExists is a free data retrieval call binding the contract method 0x606bb62e.
//
// Solidity: function getMinipoolExists(address _minipoolAddress) view returns(bool)
func (_MinipoolManager *MinipoolManagerSession) GetMinipoolExists(_minipoolAddress common.Address) (bool, error) {
	return _MinipoolManager.Contract.GetMinipoolExists(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolExists is a free data retrieval call binding the contract method 0x606bb62e.
//
// Solidity: function getMinipoolExists(address _minipoolAddress) view returns(bool)
func (_MinipoolManager *MinipoolManagerCallerSession) GetMinipoolExists(_minipoolAddress common.Address) (bool, error) {
	return _MinipoolManager.Contract.GetMinipoolExists(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolPubkey is a free data retrieval call binding the contract method 0x3eb535e9.
//
// Solidity: function getMinipoolPubkey(address _minipoolAddress) view returns(bytes)
func (_MinipoolManager *MinipoolManagerCaller) GetMinipoolPubkey(opts *bind.CallOpts, _minipoolAddress common.Address) ([]byte, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getMinipoolPubkey", _minipoolAddress)

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// GetMinipoolPubkey is a free data retrieval call binding the contract method 0x3eb535e9.
//
// Solidity: function getMinipoolPubkey(address _minipoolAddress) view returns(bytes)
func (_MinipoolManager *MinipoolManagerSession) GetMinipoolPubkey(_minipoolAddress common.Address) ([]byte, error) {
	return _MinipoolManager.Contract.GetMinipoolPubkey(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolPubkey is a free data retrieval call binding the contract method 0x3eb535e9.
//
// Solidity: function getMinipoolPubkey(address _minipoolAddress) view returns(bytes)
func (_MinipoolManager *MinipoolManagerCallerSession) GetMinipoolPubkey(_minipoolAddress common.Address) ([]byte, error) {
	return _MinipoolManager.Contract.GetMinipoolPubkey(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolRPLSlashed is a free data retrieval call binding the contract method 0x0c21b8a7.
//
// Solidity: function getMinipoolRPLSlashed(address _minipoolAddress) view returns(bool)
func (_MinipoolManager *MinipoolManagerCaller) GetMinipoolRPLSlashed(opts *bind.CallOpts, _minipoolAddress common.Address) (bool, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getMinipoolRPLSlashed", _minipoolAddress)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// GetMinipoolRPLSlashed is a free data retrieval call binding the contract method 0x0c21b8a7.
//
// Solidity: function getMinipoolRPLSlashed(address _minipoolAddress) view returns(bool)
func (_MinipoolManager *MinipoolManagerSession) GetMinipoolRPLSlashed(_minipoolAddress common.Address) (bool, error) {
	return _MinipoolManager.Contract.GetMinipoolRPLSlashed(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolRPLSlashed is a free data retrieval call binding the contract method 0x0c21b8a7.
//
// Solidity: function getMinipoolRPLSlashed(address _minipoolAddress) view returns(bool)
func (_MinipoolManager *MinipoolManagerCallerSession) GetMinipoolRPLSlashed(_minipoolAddress common.Address) (bool, error) {
	return _MinipoolManager.Contract.GetMinipoolRPLSlashed(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolWithdrawalCredentials is a free data retrieval call binding the contract method 0x2cb76c37.
//
// Solidity: function getMinipoolWithdrawalCredentials(address _minipoolAddress) pure returns(bytes)
func (_MinipoolManager *MinipoolManagerCaller) GetMinipoolWithdrawalCredentials(opts *bind.CallOpts, _minipoolAddress common.Address) ([]byte, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getMinipoolWithdrawalCredentials", _minipoolAddress)

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// GetMinipoolWithdrawalCredentials is a free data retrieval call binding the contract method 0x2cb76c37.
//
// Solidity: function getMinipoolWithdrawalCredentials(address _minipoolAddress) pure returns(bytes)
func (_MinipoolManager *MinipoolManagerSession) GetMinipoolWithdrawalCredentials(_minipoolAddress common.Address) ([]byte, error) {
	return _MinipoolManager.Contract.GetMinipoolWithdrawalCredentials(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetMinipoolWithdrawalCredentials is a free data retrieval call binding the contract method 0x2cb76c37.
//
// Solidity: function getMinipoolWithdrawalCredentials(address _minipoolAddress) pure returns(bytes)
func (_MinipoolManager *MinipoolManagerCallerSession) GetMinipoolWithdrawalCredentials(_minipoolAddress common.Address) ([]byte, error) {
	return _MinipoolManager.Contract.GetMinipoolWithdrawalCredentials(&_MinipoolManager.CallOpts, _minipoolAddress)
}

// GetNodeActiveMinipoolCount is a free data retrieval call binding the contract method 0x1844ec01.
//
// Solidity: function getNodeActiveMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetNodeActiveMinipoolCount(opts *bind.CallOpts, _nodeAddress common.Address) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getNodeActiveMinipoolCount", _nodeAddress)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetNodeActiveMinipoolCount is a free data retrieval call binding the contract method 0x1844ec01.
//
// Solidity: function getNodeActiveMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetNodeActiveMinipoolCount(_nodeAddress common.Address) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeActiveMinipoolCount(&_MinipoolManager.CallOpts, _nodeAddress)
}

// GetNodeActiveMinipoolCount is a free data retrieval call binding the contract method 0x1844ec01.
//
// Solidity: function getNodeActiveMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetNodeActiveMinipoolCount(_nodeAddress common.Address) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeActiveMinipoolCount(&_MinipoolManager.CallOpts, _nodeAddress)
}

// GetNodeFinalisedMinipoolCount is a free data retrieval call binding the contract method 0xb88a89f7.
//
// Solidity: function getNodeFinalisedMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetNodeFinalisedMinipoolCount(opts *bind.CallOpts, _nodeAddress common.Address) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getNodeFinalisedMinipoolCount", _nodeAddress)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetNodeFinalisedMinipoolCount is a free data retrieval call binding the contract method 0xb88a89f7.
//
// Solidity: function getNodeFinalisedMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetNodeFinalisedMinipoolCount(_nodeAddress common.Address) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeFinalisedMinipoolCount(&_MinipoolManager.CallOpts, _nodeAddress)
}

// GetNodeFinalisedMinipoolCount is a free data retrieval call binding the contract method 0xb88a89f7.
//
// Solidity: function getNodeFinalisedMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetNodeFinalisedMinipoolCount(_nodeAddress common.Address) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeFinalisedMinipoolCount(&_MinipoolManager.CallOpts, _nodeAddress)
}

// GetNodeMinipoolAt is a free data retrieval call binding the contract method 0x8b300029.
//
// Solidity: function getNodeMinipoolAt(address _nodeAddress, uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerCaller) GetNodeMinipoolAt(opts *bind.CallOpts, _nodeAddress common.Address, _index *big.Int) (common.Address, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getNodeMinipoolAt", _nodeAddress, _index)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetNodeMinipoolAt is a free data retrieval call binding the contract method 0x8b300029.
//
// Solidity: function getNodeMinipoolAt(address _nodeAddress, uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerSession) GetNodeMinipoolAt(_nodeAddress common.Address, _index *big.Int) (common.Address, error) {
	return _MinipoolManager.Contract.GetNodeMinipoolAt(&_MinipoolManager.CallOpts, _nodeAddress, _index)
}

// GetNodeMinipoolAt is a free data retrieval call binding the contract method 0x8b300029.
//
// Solidity: function getNodeMinipoolAt(address _nodeAddress, uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerCallerSession) GetNodeMinipoolAt(_nodeAddress common.Address, _index *big.Int) (common.Address, error) {
	return _MinipoolManager.Contract.GetNodeMinipoolAt(&_MinipoolManager.CallOpts, _nodeAddress, _index)
}

// GetNodeMinipoolCount is a free data retrieval call binding the contract method 0x1ce9ec33.
//
// Solidity: function getNodeMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetNodeMinipoolCount(opts *bind.CallOpts, _nodeAddress common.Address) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getNodeMinipoolCount", _nodeAddress)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetNodeMinipoolCount is a free data retrieval call binding the contract method 0x1ce9ec33.
//
// Solidity: function getNodeMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetNodeMinipoolCount(_nodeAddress common.Address) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeMinipoolCount(&_MinipoolManager.CallOpts, _nodeAddress)
}

// GetNodeMinipoolCount is a free data retrieval call binding the contract method 0x1ce9ec33.
//
// Solidity: function getNodeMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetNodeMinipoolCount(_nodeAddress common.Address) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeMinipoolCount(&_MinipoolManager.CallOpts, _nodeAddress)
}

// GetNodeStakingMinipoolCount is a free data retrieval call binding the contract method 0x57b4ef6b.
//
// Solidity: function getNodeStakingMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetNodeStakingMinipoolCount(opts *bind.CallOpts, _nodeAddress common.Address) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getNodeStakingMinipoolCount", _nodeAddress)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetNodeStakingMinipoolCount is a free data retrieval call binding the contract method 0x57b4ef6b.
//
// Solidity: function getNodeStakingMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetNodeStakingMinipoolCount(_nodeAddress common.Address) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeStakingMinipoolCount(&_MinipoolManager.CallOpts, _nodeAddress)
}

// GetNodeStakingMinipoolCount is a free data retrieval call binding the contract method 0x57b4ef6b.
//
// Solidity: function getNodeStakingMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetNodeStakingMinipoolCount(_nodeAddress common.Address) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeStakingMinipoolCount(&_MinipoolManager.CallOpts, _nodeAddress)
}

// GetNodeStakingMinipoolCountBySize is a free data retrieval call binding the contract method 0x240eb330.
//
// Solidity: function getNodeStakingMinipoolCountBySize(address _nodeAddress, uint256 _depositSize) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetNodeStakingMinipoolCountBySize(opts *bind.CallOpts, _nodeAddress common.Address, _depositSize *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getNodeStakingMinipoolCountBySize", _nodeAddress, _depositSize)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetNodeStakingMinipoolCountBySize is a free data retrieval call binding the contract method 0x240eb330.
//
// Solidity: function getNodeStakingMinipoolCountBySize(address _nodeAddress, uint256 _depositSize) view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetNodeStakingMinipoolCountBySize(_nodeAddress common.Address, _depositSize *big.Int) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeStakingMinipoolCountBySize(&_MinipoolManager.CallOpts, _nodeAddress, _depositSize)
}

// GetNodeStakingMinipoolCountBySize is a free data retrieval call binding the contract method 0x240eb330.
//
// Solidity: function getNodeStakingMinipoolCountBySize(address _nodeAddress, uint256 _depositSize) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetNodeStakingMinipoolCountBySize(_nodeAddress common.Address, _depositSize *big.Int) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeStakingMinipoolCountBySize(&_MinipoolManager.CallOpts, _nodeAddress, _depositSize)
}

// GetNodeValidatingMinipoolAt is a free data retrieval call binding the contract method 0x9da0700f.
//
// Solidity: function getNodeValidatingMinipoolAt(address _nodeAddress, uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerCaller) GetNodeValidatingMinipoolAt(opts *bind.CallOpts, _nodeAddress common.Address, _index *big.Int) (common.Address, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getNodeValidatingMinipoolAt", _nodeAddress, _index)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetNodeValidatingMinipoolAt is a free data retrieval call binding the contract method 0x9da0700f.
//
// Solidity: function getNodeValidatingMinipoolAt(address _nodeAddress, uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerSession) GetNodeValidatingMinipoolAt(_nodeAddress common.Address, _index *big.Int) (common.Address, error) {
	return _MinipoolManager.Contract.GetNodeValidatingMinipoolAt(&_MinipoolManager.CallOpts, _nodeAddress, _index)
}

// GetNodeValidatingMinipoolAt is a free data retrieval call binding the contract method 0x9da0700f.
//
// Solidity: function getNodeValidatingMinipoolAt(address _nodeAddress, uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerCallerSession) GetNodeValidatingMinipoolAt(_nodeAddress common.Address, _index *big.Int) (common.Address, error) {
	return _MinipoolManager.Contract.GetNodeValidatingMinipoolAt(&_MinipoolManager.CallOpts, _nodeAddress, _index)
}

// GetNodeValidatingMinipoolCount is a free data retrieval call binding the contract method 0xf90267c4.
//
// Solidity: function getNodeValidatingMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetNodeValidatingMinipoolCount(opts *bind.CallOpts, _nodeAddress common.Address) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getNodeValidatingMinipoolCount", _nodeAddress)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetNodeValidatingMinipoolCount is a free data retrieval call binding the contract method 0xf90267c4.
//
// Solidity: function getNodeValidatingMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetNodeValidatingMinipoolCount(_nodeAddress common.Address) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeValidatingMinipoolCount(&_MinipoolManager.CallOpts, _nodeAddress)
}

// GetNodeValidatingMinipoolCount is a free data retrieval call binding the contract method 0xf90267c4.
//
// Solidity: function getNodeValidatingMinipoolCount(address _nodeAddress) view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetNodeValidatingMinipoolCount(_nodeAddress common.Address) (*big.Int, error) {
	return _MinipoolManager.Contract.GetNodeValidatingMinipoolCount(&_MinipoolManager.CallOpts, _nodeAddress)
}

// GetPrelaunchMinipools is a free data retrieval call binding the contract method 0x5dfef965.
//
// Solidity: function getPrelaunchMinipools(uint256 _offset, uint256 _limit) view returns(address[])
func (_MinipoolManager *MinipoolManagerCaller) GetPrelaunchMinipools(opts *bind.CallOpts, _offset *big.Int, _limit *big.Int) ([]common.Address, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getPrelaunchMinipools", _offset, _limit)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// GetPrelaunchMinipools is a free data retrieval call binding the contract method 0x5dfef965.
//
// Solidity: function getPrelaunchMinipools(uint256 _offset, uint256 _limit) view returns(address[])
func (_MinipoolManager *MinipoolManagerSession) GetPrelaunchMinipools(_offset *big.Int, _limit *big.Int) ([]common.Address, error) {
	return _MinipoolManager.Contract.GetPrelaunchMinipools(&_MinipoolManager.CallOpts, _offset, _limit)
}

// GetPrelaunchMinipools is a free data retrieval call binding the contract method 0x5dfef965.
//
// Solidity: function getPrelaunchMinipools(uint256 _offset, uint256 _limit) view returns(address[])
func (_MinipoolManager *MinipoolManagerCallerSession) GetPrelaunchMinipools(_offset *big.Int, _limit *big.Int) ([]common.Address, error) {
	return _MinipoolManager.Contract.GetPrelaunchMinipools(&_MinipoolManager.CallOpts, _offset, _limit)
}

// GetStakingMinipoolCount is a free data retrieval call binding the contract method 0x67bca235.
//
// Solidity: function getStakingMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetStakingMinipoolCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getStakingMinipoolCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetStakingMinipoolCount is a free data retrieval call binding the contract method 0x67bca235.
//
// Solidity: function getStakingMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetStakingMinipoolCount() (*big.Int, error) {
	return _MinipoolManager.Contract.GetStakingMinipoolCount(&_MinipoolManager.CallOpts)
}

// GetStakingMinipoolCount is a free data retrieval call binding the contract method 0x67bca235.
//
// Solidity: function getStakingMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetStakingMinipoolCount() (*big.Int, error) {
	return _MinipoolManager.Contract.GetStakingMinipoolCount(&_MinipoolManager.CallOpts)
}

// GetVacantMinipoolAt is a free data retrieval call binding the contract method 0xd1401991.
//
// Solidity: function getVacantMinipoolAt(uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerCaller) GetVacantMinipoolAt(opts *bind.CallOpts, _index *big.Int) (common.Address, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getVacantMinipoolAt", _index)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetVacantMinipoolAt is a free data retrieval call binding the contract method 0xd1401991.
//
// Solidity: function getVacantMinipoolAt(uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerSession) GetVacantMinipoolAt(_index *big.Int) (common.Address, error) {
	return _MinipoolManager.Contract.GetVacantMinipoolAt(&_MinipoolManager.CallOpts, _index)
}

// GetVacantMinipoolAt is a free data retrieval call binding the contract method 0xd1401991.
//
// Solidity: function getVacantMinipoolAt(uint256 _index) view returns(address)
func (_MinipoolManager *MinipoolManagerCallerSession) GetVacantMinipoolAt(_index *big.Int) (common.Address, error) {
	return _MinipoolManager.Contract.GetVacantMinipoolAt(&_MinipoolManager.CallOpts, _index)
}

// GetVacantMinipoolCount is a free data retrieval call binding the contract method 0x1286377e.
//
// Solidity: function getVacantMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerCaller) GetVacantMinipoolCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "getVacantMinipoolCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetVacantMinipoolCount is a free data retrieval call binding the contract method 0x1286377e.
//
// Solidity: function getVacantMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerSession) GetVacantMinipoolCount() (*big.Int, error) {
	return _MinipoolManager.Contract.GetVacantMinipoolCount(&_MinipoolManager.CallOpts)
}

// GetVacantMinipoolCount is a free data retrieval call binding the contract method 0x1286377e.
//
// Solidity: function getVacantMinipoolCount() view returns(uint256)
func (_MinipoolManager *MinipoolManagerCallerSession) GetVacantMinipoolCount() (*big.Int, error) {
	return _MinipoolManager.Contract.GetVacantMinipoolCount(&_MinipoolManager.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(uint8)
func (_MinipoolManager *MinipoolManagerCaller) Version(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _MinipoolManager.contract.Call(opts, &out, "version")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(uint8)
func (_MinipoolManager *MinipoolManagerSession) Version() (uint8, error) {
	return _MinipoolManager.Contract.Version(&_MinipoolManager.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(uint8)
func (_MinipoolManager *MinipoolManagerCallerSession) Version() (uint8, error) {
	return _MinipoolManager.Contract.Version(&_MinipoolManager.CallOpts)
}

// CreateMinipool is a paid mutator transaction binding the contract method 0xc64372bb.
//
// Solidity: function createMinipool(address _nodeAddress, uint256 _salt) returns(address)
func (_MinipoolManager *MinipoolManagerTransactor) CreateMinipool(opts *bind.TransactOpts, _nodeAddress common.Address, _salt *big.Int) (*types.Transaction, error) {
	return _MinipoolManager.contract.Transact(opts, "createMinipool", _nodeAddress, _salt)
}

// CreateMinipool is a paid mutator transaction binding the contract method 0xc64372bb.
//
// Solidity: function createMinipool(address _nodeAddress, uint256 _salt) returns(address)
func (_MinipoolManager *MinipoolManagerSession) CreateMinipool(_nodeAddress common.Address, _salt *big.Int) (*types.Transaction, error) {
	return _MinipoolManager.Contract.CreateMinipool(&_MinipoolManager.TransactOpts, _nodeAddress, _salt)
}

// CreateMinipool is a paid mutator transaction binding the contract method 0xc64372bb.
//
// Solidity: function createMinipool(address _nodeAddress, uint256 _salt) returns(address)
func (_MinipoolManager *MinipoolManagerTransactorSession) CreateMinipool(_nodeAddress common.Address, _salt *big.Int) (*types.Transaction, error) {
	return _MinipoolManager.Contract.CreateMinipool(&_MinipoolManager.TransactOpts, _nodeAddress, _salt)
}

// CreateVacantMinipool is a paid mutator transaction binding the contract method 0xa179778b.
//
// Solidity: function createVacantMinipool(address _nodeAddress, uint256 _salt, bytes _validatorPubkey, uint256 _bondAmount, uint256 _currentBalance) returns(address)
func (_MinipoolManager *MinipoolManagerTransactor) CreateVacantMinipool(opts *bind.TransactOpts, _nodeAddress common.Address, _salt *big.Int, _validatorPubkey []byte, _bondAmount *big.Int, _currentBalance *big.Int) (*types.Transaction, error) {
	return _MinipoolManager.contract.Transact(opts, "createVacantMinipool", _nodeAddress, _salt, _validatorPubkey, _bondAmount, _currentBalance)
}

// CreateVacantMinipool is a paid mutator transaction binding the contract method 0xa179778b.
//
// Solidity: function createVacantMinipool(address _nodeAddress, uint256 _salt, bytes _validatorPubkey, uint256 _bondAmount, uint256 _currentBalance) returns(address)
func (_MinipoolManager *MinipoolManagerSession) CreateVacantMinipool(_nodeAddress common.Address, _salt *big.Int, _validatorPubkey []byte, _bondAmount *big.Int, _currentBalance *big.Int) (*types.Transaction, error) {
	return _MinipoolManager.Contract.CreateVacantMinipool(&_MinipoolManager.TransactOpts, _nodeAddress, _salt, _validatorPubkey, _bondAmount, _currentBalance)
}

// CreateVacantMinipool is a paid mutator transaction binding the contract method 0xa179778b.
//
// Solidity: function createVacantMinipool(address _nodeAddress, uint256 _salt, bytes _validatorPubkey, uint256 _bondAmount, uint256 _currentBalance) returns(address)
func (_MinipoolManager *MinipoolManagerTransactorSession) CreateVacantMinipool(_nodeAddress common.Address, _salt *big.Int, _validatorPubkey []byte, _bondAmount *big.Int, _currentBalance *big.Int) (*types.Transaction, error) {
	return _MinipoolManager.Contract.CreateVacantMinipool(&_MinipoolManager.TransactOpts, _nodeAddress, _salt, _validatorPubkey, _bondAmount, _currentBalance)
}

// DecrementNodeStakingMinipoolCount is a paid mutator transaction binding the contract method 0x75b59c7f.
//
// Solidity: function decrementNodeStakingMinipoolCount(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerTransactor) DecrementNodeStakingMinipoolCount(opts *bind.TransactOpts, _nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.contract.Transact(opts, "decrementNodeStakingMinipoolCount", _nodeAddress)
}

// DecrementNodeStakingMinipoolCount is a paid mutator transaction binding the contract method 0x75b59c7f.
//
// Solidity: function decrementNodeStakingMinipoolCount(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerSession) DecrementNodeStakingMinipoolCount(_nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.Contract.DecrementNodeStakingMinipoolCount(&_MinipoolManager.TransactOpts, _nodeAddress)
}

// DecrementNodeStakingMinipoolCount is a paid mutator transaction binding the contract method 0x75b59c7f.
//
// Solidity: function decrementNodeStakingMinipoolCount(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerTransactorSession) DecrementNodeStakingMinipoolCount(_nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.Contract.DecrementNodeStakingMinipoolCount(&_MinipoolManager.TransactOpts, _nodeAddress)
}

// DestroyMinipool is a paid mutator transaction binding the contract method 0x7bb40aaf.
//
// Solidity: function destroyMinipool() returns()
func (_MinipoolManager *MinipoolManagerTransactor) DestroyMinipool(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _MinipoolManager.contract.Transact(opts, "destroyMinipool")
}

// DestroyMinipool is a paid mutator transaction binding the contract method 0x7bb40aaf.
//
// Solidity: function destroyMinipool() returns()
func (_MinipoolManager *MinipoolManagerSession) DestroyMinipool() (*types.Transaction, error) {
	return _MinipoolManager.Contract.DestroyMinipool(&_MinipoolManager.TransactOpts)
}

// DestroyMinipool is a paid mutator transaction binding the contract method 0x7bb40aaf.
//
// Solidity: function destroyMinipool() returns()
func (_MinipoolManager *MinipoolManagerTransactorSession) DestroyMinipool() (*types.Transaction, error) {
	return _MinipoolManager.Contract.DestroyMinipool(&_MinipoolManager.TransactOpts)
}

// IncrementNodeFinalisedMinipoolCount is a paid mutator transaction binding the contract method 0xb04e8868.
//
// Solidity: function incrementNodeFinalisedMinipoolCount(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerTransactor) IncrementNodeFinalisedMinipoolCount(opts *bind.TransactOpts, _nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.contract.Transact(opts, "incrementNodeFinalisedMinipoolCount", _nodeAddress)
}

// IncrementNodeFinalisedMinipoolCount is a paid mutator transaction binding the contract method 0xb04e8868.
//
// Solidity: function incrementNodeFinalisedMinipoolCount(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerSession) IncrementNodeFinalisedMinipoolCount(_nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.Contract.IncrementNodeFinalisedMinipoolCount(&_MinipoolManager.TransactOpts, _nodeAddress)
}

// IncrementNodeFinalisedMinipoolCount is a paid mutator transaction binding the contract method 0xb04e8868.
//
// Solidity: function incrementNodeFinalisedMinipoolCount(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerTransactorSession) IncrementNodeFinalisedMinipoolCount(_nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.Contract.IncrementNodeFinalisedMinipoolCount(&_MinipoolManager.TransactOpts, _nodeAddress)
}

// IncrementNodeStakingMinipoolCount is a paid mutator transaction binding the contract method 0x9907288c.
//
// Solidity: function incrementNodeStakingMinipoolCount(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerTransactor) IncrementNodeStakingMinipoolCount(opts *bind.TransactOpts, _nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.contract.Transact(opts, "incrementNodeStakingMinipoolCount", _nodeAddress)
}

// IncrementNodeStakingMinipoolCount is a paid mutator transaction binding the contract method 0x9907288c.
//
// Solidity: function incrementNodeStakingMinipoolCount(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerSession) IncrementNodeStakingMinipoolCount(_nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.Contract.IncrementNodeStakingMinipoolCount(&_MinipoolManager.TransactOpts, _nodeAddress)
}

// IncrementNodeStakingMinipoolCount is a paid mutator transaction binding the contract method 0x9907288c.
//
// Solidity: function incrementNodeStakingMinipoolCount(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerTransactorSession) IncrementNodeStakingMinipoolCount(_nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.Contract.IncrementNodeStakingMinipoolCount(&_MinipoolManager.TransactOpts, _nodeAddress)
}

// RemoveVacantMinipool is a paid mutator transaction binding the contract method 0x44e51a03.
//
// Solidity: function removeVacantMinipool() returns()
func (_MinipoolManager *MinipoolManagerTransactor) RemoveVacantMinipool(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _MinipoolManager.contract.Transact(opts, "removeVacantMinipool")
}

// RemoveVacantMinipool is a paid mutator transaction binding the contract method 0x44e51a03.
//
// Solidity: function removeVacantMinipool() returns()
func (_MinipoolManager *MinipoolManagerSession) RemoveVacantMinipool() (*types.Transaction, error) {
	return _MinipoolManager.Contract.RemoveVacantMinipool(&_MinipoolManager.TransactOpts)
}

// RemoveVacantMinipool is a paid mutator transaction binding the contract method 0x44e51a03.
//
// Solidity: function removeVacantMinipool() returns()
func (_MinipoolManager *MinipoolManagerTransactorSession) RemoveVacantMinipool() (*types.Transaction, error) {
	return _MinipoolManager.Contract.RemoveVacantMinipool(&_MinipoolManager.TransactOpts)
}

// SetMinipoolPubkey is a paid mutator transaction binding the contract method 0x2c7f64d4.
//
// Solidity: function setMinipoolPubkey(bytes _pubkey) returns()
func (_MinipoolManager *MinipoolManagerTransactor) SetMinipoolPubkey(opts *bind.TransactOpts, _pubkey []byte) (*types.Transaction, error) {
	return _MinipoolManager.contract.Transact(opts, "setMinipoolPubkey", _pubkey)
}

// SetMinipoolPubkey is a paid mutator transaction binding the contract method 0x2c7f64d4.
//
// Solidity: function setMinipoolPubkey(bytes _pubkey) returns()
func (_MinipoolManager *MinipoolManagerSession) SetMinipoolPubkey(_pubkey []byte) (*types.Transaction, error) {
	return _MinipoolManager.Contract.SetMinipoolPubkey(&_MinipoolManager.TransactOpts, _pubkey)
}

// SetMinipoolPubkey is a paid mutator transaction binding the contract method 0x2c7f64d4.
//
// Solidity: function setMinipoolPubkey(bytes _pubkey) returns()
func (_MinipoolManager *MinipoolManagerTransactorSession) SetMinipoolPubkey(_pubkey []byte) (*types.Transaction, error) {
	return _MinipoolManager.Contract.SetMinipoolPubkey(&_MinipoolManager.TransactOpts, _pubkey)
}

// TryDistribute is a paid mutator transaction binding the contract method 0xd1afe958.
//
// Solidity: function tryDistribute(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerTransactor) TryDistribute(opts *bind.TransactOpts, _nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.contract.Transact(opts, "tryDistribute", _nodeAddress)
}

// TryDistribute is a paid mutator transaction binding the contract method 0xd1afe958.
//
// Solidity: function tryDistribute(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerSession) TryDistribute(_nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.Contract.TryDistribute(&_MinipoolManager.TransactOpts, _nodeAddress)
}

// TryDistribute is a paid mutator transaction binding the contract method 0xd1afe958.
//
// Solidity: function tryDistribute(address _nodeAddress) returns()
func (_MinipoolManager *MinipoolManagerTransactorSession) TryDistribute(_nodeAddress common.Address) (*types.Transaction, error) {
	return _MinipoolManager.Contract.TryDistribute(&_MinipoolManager.TransactOpts, _nodeAddress)
}

// UpdateNodeStakingMinipoolCount is a paid mutator transaction binding the contract method 0x0fcc8178.
//
// Solidity: function updateNodeStakingMinipoolCount(uint256 _previousBond, uint256 _newBond, uint256 _previousFee, uint256 _newFee) returns()
func (_MinipoolManager *MinipoolManagerTransactor) UpdateNodeStakingMinipoolCount(opts *bind.TransactOpts, _previousBond *big.Int, _newBond *big.Int, _previousFee *big.Int, _newFee *big.Int) (*types.Transaction, error) {
	return _MinipoolManager.contract.Transact(opts, "updateNodeStakingMinipoolCount", _previousBond, _newBond, _previousFee, _newFee)
}

// UpdateNodeStakingMinipoolCount is a paid mutator transaction binding the contract method 0x0fcc8178.
//
// Solidity: function updateNodeStakingMinipoolCount(uint256 _previousBond, uint256 _newBond, uint256 _previousFee, uint256 _newFee) returns()
func (_MinipoolManager *MinipoolManagerSession) UpdateNodeStakingMinipoolCount(_previousBond *big.Int, _newBond *big.Int, _previousFee *big.Int, _newFee *big.Int) (*types.Transaction, error) {
	return _MinipoolManager.Contract.UpdateNodeStakingMinipoolCount(&_MinipoolManager.TransactOpts, _previousBond, _newBond, _previousFee, _newFee)
}

// UpdateNodeStakingMinipoolCount is a paid mutator transaction binding the contract method 0x0fcc8178.
//
// Solidity: function updateNodeStakingMinipoolCount(uint256 _previousBond, uint256 _newBond, uint256 _previousFee, uint256 _newFee) returns()
func (_MinipoolManager *MinipoolManagerTransactorSession) UpdateNodeStakingMinipoolCount(_previousBond *big.Int, _newBond *big.Int, _previousFee *big.Int, _newFee *big.Int) (*types.Transaction, error) {
	return _MinipoolManager.Contract.UpdateNodeStakingMinipoolCount(&_MinipoolManager.TransactOpts, _previousBond, _newBond, _previousFee, _newFee)
}

// MinipoolManagerBeginBondReductionIterator is returned from FilterBeginBondReduction and is used to iterate over the raw logs and unpacked data for BeginBondReduction events raised by the MinipoolManager contract.
type MinipoolManagerBeginBondReductionIterator struct {
	Event *MinipoolManagerBeginBondReduction // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *MinipoolManagerBeginBondReductionIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(MinipoolManagerBeginBondReduction)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(MinipoolManagerBeginBondReduction)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *MinipoolManagerBeginBondReductionIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *MinipoolManagerBeginBondReductionIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// MinipoolManagerBeginBondReduction represents a BeginBondReduction event raised by the MinipoolManager contract.
type MinipoolManagerBeginBondReduction struct {
	Minipool common.Address
	Time     *big.Int
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterBeginBondReduction is a free log retrieval operation binding the contract event 0xebae778aeca850cfad423220d7978598785ef5905b868c482e03011b53808678.
//
// Solidity: event BeginBondReduction(address indexed minipool, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) FilterBeginBondReduction(opts *bind.FilterOpts, minipool []common.Address) (*MinipoolManagerBeginBondReductionIterator, error) {

	var minipoolRule []interface{}
	for _, minipoolItem := range minipool {
		minipoolRule = append(minipoolRule, minipoolItem)
	}

	logs, sub, err := _MinipoolManager.contract.FilterLogs(opts, "BeginBondReduction", minipoolRule)
	if err != nil {
		return nil, err
	}
	return &MinipoolManagerBeginBondReductionIterator{contract: _MinipoolManager.contract, event: "BeginBondReduction", logs: logs, sub: sub}, nil
}

// WatchBeginBondReduction is a free log subscription operation binding the contract event 0xebae778aeca850cfad423220d7978598785ef5905b868c482e03011b53808678.
//
// Solidity: event BeginBondReduction(address indexed minipool, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) WatchBeginBondReduction(opts *bind.WatchOpts, sink chan<- *MinipoolManagerBeginBondReduction, minipool []common.Address) (event.Subscription, error) {

	var minipoolRule []interface{}
	for _, minipoolItem := range minipool {
		minipoolRule = append(minipoolRule, minipoolItem)
	}

	logs, sub, err := _MinipoolManager.contract.WatchLogs(opts, "BeginBondReduction", minipoolRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(MinipoolManagerBeginBondReduction)
				if err := _MinipoolManager.contract.UnpackLog(event, "BeginBondReduction", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseBeginBondReduction is a log parse operation binding the contract event 0xebae778aeca850cfad423220d7978598785ef5905b868c482e03011b53808678.
//
// Solidity: event BeginBondReduction(address indexed minipool, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) ParseBeginBondReduction(log types.Log) (*MinipoolManagerBeginBondReduction, error) {
	event := new(MinipoolManagerBeginBondReduction)
	if err := _MinipoolManager.contract.UnpackLog(event, "BeginBondReduction", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// MinipoolManagerCancelReductionVotedIterator is returned from FilterCancelReductionVoted and is used to iterate over the raw logs and unpacked data for CancelReductionVoted events raised by the MinipoolManager contract.
type MinipoolManagerCancelReductionVotedIterator struct {
	Event *MinipoolManagerCancelReductionVoted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *MinipoolManagerCancelReductionVotedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(MinipoolManagerCancelReductionVoted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(MinipoolManagerCancelReductionVoted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *MinipoolManagerCancelReductionVotedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *MinipoolManagerCancelReductionVotedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// MinipoolManagerCancelReductionVoted represents a CancelReductionVoted event raised by the MinipoolManager contract.
type MinipoolManagerCancelReductionVoted struct {
	Minipool common.Address
	Member   common.Address
	Time     *big.Int
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterCancelReductionVoted is a free log retrieval operation binding the contract event 0x7cfaf8cd5e8153c2679a1100841445ab9926ef98867f41bd6e6afa9e3f09068e.
//
// Solidity: event CancelReductionVoted(address indexed minipool, address indexed member, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) FilterCancelReductionVoted(opts *bind.FilterOpts, minipool []common.Address, member []common.Address) (*MinipoolManagerCancelReductionVotedIterator, error) {

	var minipoolRule []interface{}
	for _, minipoolItem := range minipool {
		minipoolRule = append(minipoolRule, minipoolItem)
	}
	var memberRule []interface{}
	for _, memberItem := range member {
		memberRule = append(memberRule, memberItem)
	}

	logs, sub, err := _MinipoolManager.contract.FilterLogs(opts, "CancelReductionVoted", minipoolRule, memberRule)
	if err != nil {
		return nil, err
	}
	return &MinipoolManagerCancelReductionVotedIterator{contract: _MinipoolManager.contract, event: "CancelReductionVoted", logs: logs, sub: sub}, nil
}

// WatchCancelReductionVoted is a free log subscription operation binding the contract event 0x7cfaf8cd5e8153c2679a1100841445ab9926ef98867f41bd6e6afa9e3f09068e.
//
// Solidity: event CancelReductionVoted(address indexed minipool, address indexed member, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) WatchCancelReductionVoted(opts *bind.WatchOpts, sink chan<- *MinipoolManagerCancelReductionVoted, minipool []common.Address, member []common.Address) (event.Subscription, error) {

	var minipoolRule []interface{}
	for _, minipoolItem := range minipool {
		minipoolRule = append(minipoolRule, minipoolItem)
	}
	var memberRule []interface{}
	for _, memberItem := range member {
		memberRule = append(memberRule, memberItem)
	}

	logs, sub, err := _MinipoolManager.contract.WatchLogs(opts, "CancelReductionVoted", minipoolRule, memberRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(MinipoolManagerCancelReductionVoted)
				if err := _MinipoolManager.contract.UnpackLog(event, "CancelReductionVoted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseCancelReductionVoted is a log parse operation binding the contract event 0x7cfaf8cd5e8153c2679a1100841445ab9926ef98867f41bd6e6afa9e3f09068e.
//
// Solidity: event CancelReductionVoted(address indexed minipool, address indexed member, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) ParseCancelReductionVoted(log types.Log) (*MinipoolManagerCancelReductionVoted, error) {
	event := new(MinipoolManagerCancelReductionVoted)
	if err := _MinipoolManager.contract.UnpackLog(event, "CancelReductionVoted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// MinipoolManagerMinipoolCreatedIterator is returned from FilterMinipoolCreated and is used to iterate over the raw logs and unpacked data for MinipoolCreated events raised by the MinipoolManager contract.
type MinipoolManagerMinipoolCreatedIterator struct {
	Event *MinipoolManagerMinipoolCreated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *MinipoolManagerMinipoolCreatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(MinipoolManagerMinipoolCreated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(MinipoolManagerMinipoolCreated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *MinipoolManagerMinipoolCreatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *MinipoolManagerMinipoolCreatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// MinipoolManagerMinipoolCreated represents a MinipoolCreated event raised by the MinipoolManager contract.
type MinipoolManagerMinipoolCreated struct {
	Minipool common.Address
	Node     common.Address
	Time     *big.Int
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterMinipoolCreated is a free log retrieval operation binding the contract event 0x08b4b91bafaf992145c5dd7e098dfcdb32f879714c154c651c2758a44c7aeae4.
//
// Solidity: event MinipoolCreated(address indexed minipool, address indexed node, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) FilterMinipoolCreated(opts *bind.FilterOpts, minipool []common.Address, node []common.Address) (*MinipoolManagerMinipoolCreatedIterator, error) {

	var minipoolRule []interface{}
	for _, minipoolItem := range minipool {
		minipoolRule = append(minipoolRule, minipoolItem)
	}
	var nodeRule []interface{}
	for _, nodeItem := range node {
		nodeRule = append(nodeRule, nodeItem)
	}

	logs, sub, err := _MinipoolManager.contract.FilterLogs(opts, "MinipoolCreated", minipoolRule, nodeRule)
	if err != nil {
		return nil, err
	}
	return &MinipoolManagerMinipoolCreatedIterator{contract: _MinipoolManager.contract, event: "MinipoolCreated", logs: logs, sub: sub}, nil
}

// WatchMinipoolCreated is a free log subscription operation binding the contract event 0x08b4b91bafaf992145c5dd7e098dfcdb32f879714c154c651c2758a44c7aeae4.
//
// Solidity: event MinipoolCreated(address indexed minipool, address indexed node, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) WatchMinipoolCreated(opts *bind.WatchOpts, sink chan<- *MinipoolManagerMinipoolCreated, minipool []common.Address, node []common.Address) (event.Subscription, error) {

	var minipoolRule []interface{}
	for _, minipoolItem := range minipool {
		minipoolRule = append(minipoolRule, minipoolItem)
	}
	var nodeRule []interface{}
	for _, nodeItem := range node {
		nodeRule = append(nodeRule, nodeItem)
	}

	logs, sub, err := _MinipoolManager.contract.WatchLogs(opts, "MinipoolCreated", minipoolRule, nodeRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(MinipoolManagerMinipoolCreated)
				if err := _MinipoolManager.contract.UnpackLog(event, "MinipoolCreated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseMinipoolCreated is a log parse operation binding the contract event 0x08b4b91bafaf992145c5dd7e098dfcdb32f879714c154c651c2758a44c7aeae4.
//
// Solidity: event MinipoolCreated(address indexed minipool, address indexed node, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) ParseMinipoolCreated(log types.Log) (*MinipoolManagerMinipoolCreated, error) {
	event := new(MinipoolManagerMinipoolCreated)
	if err := _MinipoolManager.contract.UnpackLog(event, "MinipoolCreated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// MinipoolManagerMinipoolDestroyedIterator is returned from FilterMinipoolDestroyed and is used to iterate over the raw logs and unpacked data for MinipoolDestroyed events raised by the MinipoolManager contract.
type MinipoolManagerMinipoolDestroyedIterator struct {
	Event *MinipoolManagerMinipoolDestroyed // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *MinipoolManagerMinipoolDestroyedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(MinipoolManagerMinipoolDestroyed)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(MinipoolManagerMinipoolDestroyed)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *MinipoolManagerMinipoolDestroyedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *MinipoolManagerMinipoolDestroyedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// MinipoolManagerMinipoolDestroyed represents a MinipoolDestroyed event raised by the MinipoolManager contract.
type MinipoolManagerMinipoolDestroyed struct {
	Minipool common.Address
	Node     common.Address
	Time     *big.Int
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterMinipoolDestroyed is a free log retrieval operation binding the contract event 0x3097cb0f536cd88115b814915d7030d2fe958943357cd2b1a9e1dba8a673ec69.
//
// Solidity: event MinipoolDestroyed(address indexed minipool, address indexed node, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) FilterMinipoolDestroyed(opts *bind.FilterOpts, minipool []common.Address, node []common.Address) (*MinipoolManagerMinipoolDestroyedIterator, error) {

	var minipoolRule []interface{}
	for _, minipoolItem := range minipool {
		minipoolRule = append(minipoolRule, minipoolItem)
	}
	var nodeRule []interface{}
	for _, nodeItem := range node {
		nodeRule = append(nodeRule, nodeItem)
	}

	logs, sub, err := _MinipoolManager.contract.FilterLogs(opts, "MinipoolDestroyed", minipoolRule, nodeRule)
	if err != nil {
		return nil, err
	}
	return &MinipoolManagerMinipoolDestroyedIterator{contract: _MinipoolManager.contract, event: "MinipoolDestroyed", logs: logs, sub: sub}, nil
}

// WatchMinipoolDestroyed is a free log subscription operation binding the contract event 0x3097cb0f536cd88115b814915d7030d2fe958943357cd2b1a9e1dba8a673ec69.
//
// Solidity: event MinipoolDestroyed(address indexed minipool, address indexed node, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) WatchMinipoolDestroyed(opts *bind.WatchOpts, sink chan<- *MinipoolManagerMinipoolDestroyed, minipool []common.Address, node []common.Address) (event.Subscription, error) {

	var minipoolRule []interface{}
	for _, minipoolItem := range minipool {
		minipoolRule = append(minipoolRule, minipoolItem)
	}
	var nodeRule []interface{}
	for _, nodeItem := range node {
		nodeRule = append(nodeRule, nodeItem)
	}

	logs, sub, err := _MinipoolManager.contract.WatchLogs(opts, "MinipoolDestroyed", minipoolRule, nodeRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(MinipoolManagerMinipoolDestroyed)
				if err := _MinipoolManager.contract.UnpackLog(event, "MinipoolDestroyed", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseMinipoolDestroyed is a log parse operation binding the contract event 0x3097cb0f536cd88115b814915d7030d2fe958943357cd2b1a9e1dba8a673ec69.
//
// Solidity: event MinipoolDestroyed(address indexed minipool, address indexed node, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) ParseMinipoolDestroyed(log types.Log) (*MinipoolManagerMinipoolDestroyed, error) {
	event := new(MinipoolManagerMinipoolDestroyed)
	if err := _MinipoolManager.contract.UnpackLog(event, "MinipoolDestroyed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// MinipoolManagerReductionCancelledIterator is returned from FilterReductionCancelled and is used to iterate over the raw logs and unpacked data for ReductionCancelled events raised by the MinipoolManager contract.
type MinipoolManagerReductionCancelledIterator struct {
	Event *MinipoolManagerReductionCancelled // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *MinipoolManagerReductionCancelledIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(MinipoolManagerReductionCancelled)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(MinipoolManagerReductionCancelled)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *MinipoolManagerReductionCancelledIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *MinipoolManagerReductionCancelledIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// MinipoolManagerReductionCancelled represents a ReductionCancelled event raised by the MinipoolManager contract.
type MinipoolManagerReductionCancelled struct {
	Minipool common.Address
	Time     *big.Int
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterReductionCancelled is a free log retrieval operation binding the contract event 0xf5248f3aef129e8fd5ee9f0bd6dc051e7a9f3ad64e171a0acfb396298683bc24.
//
// Solidity: event ReductionCancelled(address indexed minipool, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) FilterReductionCancelled(opts *bind.FilterOpts, minipool []common.Address) (*MinipoolManagerReductionCancelledIterator, error) {

	var minipoolRule []interface{}
	for _, minipoolItem := range minipool {
		minipoolRule = append(minipoolRule, minipoolItem)
	}

	logs, sub, err := _MinipoolManager.contract.FilterLogs(opts, "ReductionCancelled", minipoolRule)
	if err != nil {
		return nil, err
	}
	return &MinipoolManagerReductionCancelledIterator{contract: _MinipoolManager.contract, event: "ReductionCancelled", logs: logs, sub: sub}, nil
}

// WatchReductionCancelled is a free log subscription operation binding the contract event 0xf5248f3aef129e8fd5ee9f0bd6dc051e7a9f3ad64e171a0acfb396298683bc24.
//
// Solidity: event ReductionCancelled(address indexed minipool, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) WatchReductionCancelled(opts *bind.WatchOpts, sink chan<- *MinipoolManagerReductionCancelled, minipool []common.Address) (event.Subscription, error) {

	var minipoolRule []interface{}
	for _, minipoolItem := range minipool {
		minipoolRule = append(minipoolRule, minipoolItem)
	}

	logs, sub, err := _MinipoolManager.contract.WatchLogs(opts, "ReductionCancelled", minipoolRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(MinipoolManagerReductionCancelled)
				if err := _MinipoolManager.contract.UnpackLog(event, "ReductionCancelled", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseReductionCancelled is a log parse operation binding the contract event 0xf5248f3aef129e8fd5ee9f0bd6dc051e7a9f3ad64e171a0acfb396298683bc24.
//
// Solidity: event ReductionCancelled(address indexed minipool, uint256 time)
func (_MinipoolManager *MinipoolManagerFilterer) ParseReductionCancelled(log types.Log) (*MinipoolManagerReductionCancelled, error) {
	event := new(MinipoolManagerReductionCancelled)
	if err := _MinipoolManager.contract.UnpackLog(event, "ReductionCancelled", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
