// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package registry

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

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
	_ = time.Tick
	_ = context.Background
)

// VeriLogRegistryMetaData contains all meta data concerning the VeriLogRegistry contract.
var VeriLogRegistryMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"admin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"anchorer\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"ANCHORER_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"DEFAULT_ADMIN_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"agentAnchors\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"merkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"logCount\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"anchorEpoch\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"merkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"logCount\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[{\"name\":\"epochId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getRoleAdmin\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"grantRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"hasRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"latestEpoch\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"renounceRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"callerConfirmation\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"revokeRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"supportsInterface\",\"inputs\":[{\"name\":\"interfaceId\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"verifyAnchoredLeaf\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"epochId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"leaf\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"verifyProof\",\"inputs\":[{\"name\":\"leaf\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"root\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"event\",\"name\":\"LogAnchored\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"epochId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"},{\"name\":\"merkleRoot\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"logCount\",\"type\":\"uint32\",\"indexed\":false,\"internalType\":\"uint32\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleAdminChanged\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"previousAdminRole\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"newAdminRole\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleGranted\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"sender\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleRevoked\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"sender\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AccessControlBadConfirmation\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"AccessControlUnauthorizedAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"neededRole\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"EpochNotAnchored\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"epochId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"ZeroAddress\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZeroAgentId\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZeroLogCount\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZeroMerkleRoot\",\"inputs\":[]}]",
	Bin: "0x608060405234801561000f575f5ffd5b50604051610d2e380380610d2e83398101604081905261002e9161016a565b6001600160a01b038216158061004b57506001600160a01b038116155b156100695760405163d92e233d60e01b815260040160405180910390fd5b6100735f836100a6565b5061009e7f4b3e6527f1b0d33beb6c20e3c362af276f03c4526b5f8b6d118672f0d75a60eb826100a6565b50505061019b565b5f828152602081815260408083206001600160a01b038516845290915281205460ff16610146575f838152602081815260408083206001600160a01b03861684529091529020805460ff191660011790556100fe3390565b6001600160a01b0316826001600160a01b0316847f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d60405160405180910390a4506001610149565b505f5b92915050565b80516001600160a01b0381168114610165575f5ffd5b919050565b5f5f6040838503121561017b575f5ffd5b6101848361014f565b91506101926020840161014f565b90509250929050565b610b86806101a85f395ff3fe608060405234801561000f575f5ffd5b50600436106100da575f3560e01c806358161a4211610088578063a217fddf11610063578063a217fddf14610264578063abaad9ae1461026b578063c9ecaf6d1461027e578063d547741f1461029d575f5ffd5b806358161a42146101e75780637cfd9a51146101fa57806391d1485414610221575f5ffd5b8063248a9ca3116100b8578063248a9ca31461018f5780632f2ff15d146101bf57806336568abe146101d4575f5ffd5b806301ffc9a7146100de5780630819f81414610106578063231b80d21461017c575b5f5ffd5b6100f16100ec366004610936565b6102b0565b60405190151581526020015b60405180910390f35b610152610114366004610975565b600160208181525f93845260408085209091529183529120805491015467ffffffffffffffff81169068010000000000000000900463ffffffff1683565b6040805193845267ffffffffffffffff909216602084015263ffffffff16908201526060016100fd565b6100f161018a3660046109dd565b610348565b6101b161019d366004610a39565b5f9081526020819052604090206001015490565b6040519081526020016100fd565b6101d26101cd366004610a50565b6103be565b005b6101d26101e2366004610a50565b6103e8565b6100f16101f5366004610a96565b610446565b6101b17f4b3e6527f1b0d33beb6c20e3c362af276f03c4526b5f8b6d118672f0d75a60eb81565b6100f161022f366004610a50565b5f9182526020828152604080842073ffffffffffffffffffffffffffffffffffffffff93909316845291905290205460ff1690565b6101b15f81565b6101b1610279366004610ae5565b61045c565b6101b161028c366004610a39565b60026020525f908152604090205481565b6101d26102ab366004610a50565b610643565b5f7fffffffff0000000000000000000000000000000000000000000000000000000082167f7965db0b00000000000000000000000000000000000000000000000000000000148061034257507f01ffc9a7000000000000000000000000000000000000000000000000000000007fffffffff000000000000000000000000000000000000000000000000000000008316145b92915050565b5f858152600160209081526040808320878452909152812054806103a7576040517facaaf6ef00000000000000000000000000000000000000000000000000000000815260048101889052602481018790526044015b60405180910390fd5b6103b384848388610667565b979650505050505050565b5f828152602081905260409020600101546103d88161067e565b6103e2838361068b565b50505050565b73ffffffffffffffffffffffffffffffffffffffff81163314610437576040517f6697b23200000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6104418282610784565b505050565b5f61045384848488610667565b95945050505050565b5f7f4b3e6527f1b0d33beb6c20e3c362af276f03c4526b5f8b6d118672f0d75a60eb6104878161067e565b846104be576040517f42c5b17a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b836104f5576040517f9266ee6200000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b8263ffffffff165f03610534576040517ffb00b7a900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f8581526002602090815260408083208054600190810191829055825160608101845289815267ffffffffffffffff4281811683880190815263ffffffff808d168589019081528f8b52868a52888b20888c52909952988790209351845551929093018054965190971668010000000000000000027fffffffffffffffffffffffffffffffffffffffff000000000000000000000000909616911617939093179093555191935090839087907f0d7f028acbb0cc55a704d6d96e27d5ef5a8490693e35797fb31924541fcc7f30906106329089908990879092835263ffffffff91909116602083015267ffffffffffffffff16604082015260600190565b60405180910390a350509392505050565b5f8281526020819052604090206001015461065d8161067e565b6103e28383610784565b5f8261067486868561083d565b1495945050505050565b610688813361087e565b50565b5f8281526020818152604080832073ffffffffffffffffffffffffffffffffffffffff8516845290915281205460ff1661077d575f8381526020818152604080832073ffffffffffffffffffffffffffffffffffffffff86168452909152902080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0016600117905561071b3390565b73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16847f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d60405160405180910390a4506001610342565b505f610342565b5f8281526020818152604080832073ffffffffffffffffffffffffffffffffffffffff8516845290915281205460ff161561077d575f8381526020818152604080832073ffffffffffffffffffffffffffffffffffffffff8616808552925280832080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0016905551339286917ff6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b9190a4506001610342565b5f81815b848110156108755761086b8287878481811061085f5761085f610b23565b90506020020135610907565b9150600101610841565b50949350505050565b5f8281526020818152604080832073ffffffffffffffffffffffffffffffffffffffff8516845290915290205460ff16610903576040517fe2517d3f00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff821660048201526024810183905260440161039e565b5050565b5f818310610921575f82815260208490526040902061092f565b5f8381526020839052604090205b9392505050565b5f60208284031215610946575f5ffd5b81357fffffffff000000000000000000000000000000000000000000000000000000008116811461092f575f5ffd5b5f5f60408385031215610986575f5ffd5b50508035926020909101359150565b5f5f83601f8401126109a5575f5ffd5b50813567ffffffffffffffff8111156109bc575f5ffd5b6020830191508360208260051b85010111156109d6575f5ffd5b9250929050565b5f5f5f5f5f608086880312156109f1575f5ffd5b853594506020860135935060408601359250606086013567ffffffffffffffff811115610a1c575f5ffd5b610a2888828901610995565b969995985093965092949392505050565b5f60208284031215610a49575f5ffd5b5035919050565b5f5f60408385031215610a61575f5ffd5b82359150602083013573ffffffffffffffffffffffffffffffffffffffff81168114610a8b575f5ffd5b809150509250929050565b5f5f5f5f60608587031215610aa9575f5ffd5b84359350602085013567ffffffffffffffff811115610ac6575f5ffd5b610ad287828801610995565b9598909750949560400135949350505050565b5f5f5f60608486031215610af7575f5ffd5b8335925060208401359150604084013563ffffffff81168114610b18575f5ffd5b809150509250925092565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffdfea264697066735822122095e5d17bdbccf6aec81c8c605249c4299fccfae2713cf1349f7fbf07e3ea191e64736f6c634300081c0033",
}

// VeriLogRegistryABI is the input ABI used to generate the binding from.
// Deprecated: Use VeriLogRegistryMetaData.ABI instead.
var VeriLogRegistryABI = VeriLogRegistryMetaData.ABI

// VeriLogRegistryBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use VeriLogRegistryMetaData.Bin instead.
var VeriLogRegistryBin = VeriLogRegistryMetaData.Bin

// DeployVeriLogRegistry deploys a new Ethereum contract, binding an instance of VeriLogRegistry to it.
func DeployVeriLogRegistry(auth *bind.TransactOpts, backend bind.ContractBackend, admin common.Address, anchorer common.Address) (common.Address, *types.Transaction, *VeriLogRegistry, error) {
	parsed, err := VeriLogRegistryMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(VeriLogRegistryBin), backend, admin, anchorer)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &VeriLogRegistry{VeriLogRegistryCaller: VeriLogRegistryCaller{contract: contract}, VeriLogRegistryTransactor: VeriLogRegistryTransactor{contract: contract}, VeriLogRegistryFilterer: VeriLogRegistryFilterer{contract: contract}}, nil
}

// VeriLogRegistry is an auto generated Go binding around an Ethereum contract.
type VeriLogRegistry struct {
	VeriLogRegistryCaller     // Read-only binding to the contract
	VeriLogRegistryTransactor // Write-only binding to the contract
	VeriLogRegistryFilterer   // Log filterer for contract events
}

// VeriLogRegistryCaller is an auto generated read-only Go binding around an Ethereum contract.
type VeriLogRegistryCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VeriLogRegistryTransactor is an auto generated write-only Go binding around an Ethereum contract.
type VeriLogRegistryTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VeriLogRegistryFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type VeriLogRegistryFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VeriLogRegistrySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type VeriLogRegistrySession struct {
	Contract     *VeriLogRegistry  // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// VeriLogRegistryCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type VeriLogRegistryCallerSession struct {
	Contract *VeriLogRegistryCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts          // Call options to use throughout this session
}

// VeriLogRegistryTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type VeriLogRegistryTransactorSession struct {
	Contract     *VeriLogRegistryTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts          // Transaction auth options to use throughout this session
}

// VeriLogRegistryRaw is an auto generated low-level Go binding around an Ethereum contract.
type VeriLogRegistryRaw struct {
	Contract *VeriLogRegistry // Generic contract binding to access the raw methods on
}

// VeriLogRegistryCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type VeriLogRegistryCallerRaw struct {
	Contract *VeriLogRegistryCaller // Generic read-only contract binding to access the raw methods on
}

// VeriLogRegistryTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type VeriLogRegistryTransactorRaw struct {
	Contract *VeriLogRegistryTransactor // Generic write-only contract binding to access the raw methods on
}

// NewVeriLogRegistry creates a new instance of VeriLogRegistry, bound to a specific deployed contract.
func NewVeriLogRegistry(address common.Address, backend bind.ContractBackend) (*VeriLogRegistry, error) {
	contract, err := bindVeriLogRegistry(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &VeriLogRegistry{VeriLogRegistryCaller: VeriLogRegistryCaller{contract: contract}, VeriLogRegistryTransactor: VeriLogRegistryTransactor{contract: contract}, VeriLogRegistryFilterer: VeriLogRegistryFilterer{contract: contract}}, nil
}

// NewVeriLogRegistryCaller creates a new read-only instance of VeriLogRegistry, bound to a specific deployed contract.
func NewVeriLogRegistryCaller(address common.Address, caller bind.ContractCaller) (*VeriLogRegistryCaller, error) {
	contract, err := bindVeriLogRegistry(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &VeriLogRegistryCaller{contract: contract}, nil
}

// NewVeriLogRegistryTransactor creates a new write-only instance of VeriLogRegistry, bound to a specific deployed contract.
func NewVeriLogRegistryTransactor(address common.Address, transactor bind.ContractTransactor) (*VeriLogRegistryTransactor, error) {
	contract, err := bindVeriLogRegistry(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &VeriLogRegistryTransactor{contract: contract}, nil
}

// NewVeriLogRegistryFilterer creates a new log filterer instance of VeriLogRegistry, bound to a specific deployed contract.
func NewVeriLogRegistryFilterer(address common.Address, filterer bind.ContractFilterer) (*VeriLogRegistryFilterer, error) {
	contract, err := bindVeriLogRegistry(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &VeriLogRegistryFilterer{contract: contract}, nil
}

// bindVeriLogRegistry binds a generic wrapper to an already deployed contract.
func bindVeriLogRegistry(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := VeriLogRegistryMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_VeriLogRegistry *VeriLogRegistryRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _VeriLogRegistry.Contract.VeriLogRegistryCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_VeriLogRegistry *VeriLogRegistryRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.VeriLogRegistryTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_VeriLogRegistry *VeriLogRegistryRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.VeriLogRegistryTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_VeriLogRegistry *VeriLogRegistryCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _VeriLogRegistry.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_VeriLogRegistry *VeriLogRegistryTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_VeriLogRegistry *VeriLogRegistryTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.contract.Transact(opts, method, params...)
}

// ANCHORERROLE is a free data retrieval call binding the contract method 0x7cfd9a51.
//
// Solidity: function ANCHORER_ROLE() view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistryCaller) ANCHORERROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "ANCHORER_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ANCHORERROLE is a free data retrieval call binding the contract method 0x7cfd9a51.
//
// Solidity: function ANCHORER_ROLE() view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistrySession) ANCHORERROLE() ([32]byte, error) {
	return _VeriLogRegistry.Contract.ANCHORERROLE(&_VeriLogRegistry.CallOpts)
}

// ANCHORERROLE is a free data retrieval call binding the contract method 0x7cfd9a51.
//
// Solidity: function ANCHORER_ROLE() view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) ANCHORERROLE() ([32]byte, error) {
	return _VeriLogRegistry.Contract.ANCHORERROLE(&_VeriLogRegistry.CallOpts)
}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistryCaller) DEFAULTADMINROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "DEFAULT_ADMIN_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistrySession) DEFAULTADMINROLE() ([32]byte, error) {
	return _VeriLogRegistry.Contract.DEFAULTADMINROLE(&_VeriLogRegistry.CallOpts)
}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) DEFAULTADMINROLE() ([32]byte, error) {
	return _VeriLogRegistry.Contract.DEFAULTADMINROLE(&_VeriLogRegistry.CallOpts)
}

// AgentAnchors is a free data retrieval call binding the contract method 0x0819f814.
//
// Solidity: function agentAnchors(bytes32 , uint256 ) view returns(bytes32 merkleRoot, uint64 timestamp, uint32 logCount)
func (_VeriLogRegistry *VeriLogRegistryCaller) AgentAnchors(opts *bind.CallOpts, arg0 [32]byte, arg1 *big.Int) (struct {
	MerkleRoot [32]byte
	Timestamp  uint64
	LogCount   uint32
}, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "agentAnchors", arg0, arg1)

	outstruct := new(struct {
		MerkleRoot [32]byte
		Timestamp  uint64
		LogCount   uint32
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.MerkleRoot = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.Timestamp = *abi.ConvertType(out[1], new(uint64)).(*uint64)
	outstruct.LogCount = *abi.ConvertType(out[2], new(uint32)).(*uint32)

	return *outstruct, err

}

// AgentAnchors is a free data retrieval call binding the contract method 0x0819f814.
//
// Solidity: function agentAnchors(bytes32 , uint256 ) view returns(bytes32 merkleRoot, uint64 timestamp, uint32 logCount)
func (_VeriLogRegistry *VeriLogRegistrySession) AgentAnchors(arg0 [32]byte, arg1 *big.Int) (struct {
	MerkleRoot [32]byte
	Timestamp  uint64
	LogCount   uint32
}, error) {
	return _VeriLogRegistry.Contract.AgentAnchors(&_VeriLogRegistry.CallOpts, arg0, arg1)
}

// AgentAnchors is a free data retrieval call binding the contract method 0x0819f814.
//
// Solidity: function agentAnchors(bytes32 , uint256 ) view returns(bytes32 merkleRoot, uint64 timestamp, uint32 logCount)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) AgentAnchors(arg0 [32]byte, arg1 *big.Int) (struct {
	MerkleRoot [32]byte
	Timestamp  uint64
	LogCount   uint32
}, error) {
	return _VeriLogRegistry.Contract.AgentAnchors(&_VeriLogRegistry.CallOpts, arg0, arg1)
}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistryCaller) GetRoleAdmin(opts *bind.CallOpts, role [32]byte) ([32]byte, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "getRoleAdmin", role)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistrySession) GetRoleAdmin(role [32]byte) ([32]byte, error) {
	return _VeriLogRegistry.Contract.GetRoleAdmin(&_VeriLogRegistry.CallOpts, role)
}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) GetRoleAdmin(role [32]byte) ([32]byte, error) {
	return _VeriLogRegistry.Contract.GetRoleAdmin(&_VeriLogRegistry.CallOpts, role)
}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_VeriLogRegistry *VeriLogRegistryCaller) HasRole(opts *bind.CallOpts, role [32]byte, account common.Address) (bool, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "hasRole", role, account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_VeriLogRegistry *VeriLogRegistrySession) HasRole(role [32]byte, account common.Address) (bool, error) {
	return _VeriLogRegistry.Contract.HasRole(&_VeriLogRegistry.CallOpts, role, account)
}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) HasRole(role [32]byte, account common.Address) (bool, error) {
	return _VeriLogRegistry.Contract.HasRole(&_VeriLogRegistry.CallOpts, role, account)
}

// LatestEpoch is a free data retrieval call binding the contract method 0xc9ecaf6d.
//
// Solidity: function latestEpoch(bytes32 ) view returns(uint256)
func (_VeriLogRegistry *VeriLogRegistryCaller) LatestEpoch(opts *bind.CallOpts, arg0 [32]byte) (*big.Int, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "latestEpoch", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// LatestEpoch is a free data retrieval call binding the contract method 0xc9ecaf6d.
//
// Solidity: function latestEpoch(bytes32 ) view returns(uint256)
func (_VeriLogRegistry *VeriLogRegistrySession) LatestEpoch(arg0 [32]byte) (*big.Int, error) {
	return _VeriLogRegistry.Contract.LatestEpoch(&_VeriLogRegistry.CallOpts, arg0)
}

// LatestEpoch is a free data retrieval call binding the contract method 0xc9ecaf6d.
//
// Solidity: function latestEpoch(bytes32 ) view returns(uint256)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) LatestEpoch(arg0 [32]byte) (*big.Int, error) {
	return _VeriLogRegistry.Contract.LatestEpoch(&_VeriLogRegistry.CallOpts, arg0)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_VeriLogRegistry *VeriLogRegistryCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_VeriLogRegistry *VeriLogRegistrySession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _VeriLogRegistry.Contract.SupportsInterface(&_VeriLogRegistry.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _VeriLogRegistry.Contract.SupportsInterface(&_VeriLogRegistry.CallOpts, interfaceId)
}

// VerifyAnchoredLeaf is a free data retrieval call binding the contract method 0x231b80d2.
//
// Solidity: function verifyAnchoredLeaf(bytes32 agentId, uint256 epochId, bytes32 leaf, bytes32[] proof) view returns(bool)
func (_VeriLogRegistry *VeriLogRegistryCaller) VerifyAnchoredLeaf(opts *bind.CallOpts, agentId [32]byte, epochId *big.Int, leaf [32]byte, proof [][32]byte) (bool, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "verifyAnchoredLeaf", agentId, epochId, leaf, proof)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// VerifyAnchoredLeaf is a free data retrieval call binding the contract method 0x231b80d2.
//
// Solidity: function verifyAnchoredLeaf(bytes32 agentId, uint256 epochId, bytes32 leaf, bytes32[] proof) view returns(bool)
func (_VeriLogRegistry *VeriLogRegistrySession) VerifyAnchoredLeaf(agentId [32]byte, epochId *big.Int, leaf [32]byte, proof [][32]byte) (bool, error) {
	return _VeriLogRegistry.Contract.VerifyAnchoredLeaf(&_VeriLogRegistry.CallOpts, agentId, epochId, leaf, proof)
}

// VerifyAnchoredLeaf is a free data retrieval call binding the contract method 0x231b80d2.
//
// Solidity: function verifyAnchoredLeaf(bytes32 agentId, uint256 epochId, bytes32 leaf, bytes32[] proof) view returns(bool)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) VerifyAnchoredLeaf(agentId [32]byte, epochId *big.Int, leaf [32]byte, proof [][32]byte) (bool, error) {
	return _VeriLogRegistry.Contract.VerifyAnchoredLeaf(&_VeriLogRegistry.CallOpts, agentId, epochId, leaf, proof)
}

// VerifyProof is a free data retrieval call binding the contract method 0x58161a42.
//
// Solidity: function verifyProof(bytes32 leaf, bytes32[] proof, bytes32 root) pure returns(bool)
func (_VeriLogRegistry *VeriLogRegistryCaller) VerifyProof(opts *bind.CallOpts, leaf [32]byte, proof [][32]byte, root [32]byte) (bool, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "verifyProof", leaf, proof, root)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// VerifyProof is a free data retrieval call binding the contract method 0x58161a42.
//
// Solidity: function verifyProof(bytes32 leaf, bytes32[] proof, bytes32 root) pure returns(bool)
func (_VeriLogRegistry *VeriLogRegistrySession) VerifyProof(leaf [32]byte, proof [][32]byte, root [32]byte) (bool, error) {
	return _VeriLogRegistry.Contract.VerifyProof(&_VeriLogRegistry.CallOpts, leaf, proof, root)
}

// VerifyProof is a free data retrieval call binding the contract method 0x58161a42.
//
// Solidity: function verifyProof(bytes32 leaf, bytes32[] proof, bytes32 root) pure returns(bool)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) VerifyProof(leaf [32]byte, proof [][32]byte, root [32]byte) (bool, error) {
	return _VeriLogRegistry.Contract.VerifyProof(&_VeriLogRegistry.CallOpts, leaf, proof, root)
}

// AnchorEpoch is a paid mutator transaction binding the contract method 0xabaad9ae.
//
// Solidity: function anchorEpoch(bytes32 agentId, bytes32 merkleRoot, uint32 logCount) returns(uint256 epochId)
func (_VeriLogRegistry *VeriLogRegistryTransactor) AnchorEpoch(opts *bind.TransactOpts, agentId [32]byte, merkleRoot [32]byte, logCount uint32) (*types.Transaction, error) {
	return _VeriLogRegistry.contract.Transact(opts, "anchorEpoch", agentId, merkleRoot, logCount)
}

// AnchorEpoch is a paid mutator transaction binding the contract method 0xabaad9ae.
//
// Solidity: function anchorEpoch(bytes32 agentId, bytes32 merkleRoot, uint32 logCount) returns(uint256 epochId)
func (_VeriLogRegistry *VeriLogRegistrySession) AnchorEpoch(agentId [32]byte, merkleRoot [32]byte, logCount uint32) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.AnchorEpoch(&_VeriLogRegistry.TransactOpts, agentId, merkleRoot, logCount)
}

// AnchorEpoch is a paid mutator transaction binding the contract method 0xabaad9ae.
//
// Solidity: function anchorEpoch(bytes32 agentId, bytes32 merkleRoot, uint32 logCount) returns(uint256 epochId)
func (_VeriLogRegistry *VeriLogRegistryTransactorSession) AnchorEpoch(agentId [32]byte, merkleRoot [32]byte, logCount uint32) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.AnchorEpoch(&_VeriLogRegistry.TransactOpts, agentId, merkleRoot, logCount)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_VeriLogRegistry *VeriLogRegistryTransactor) GrantRole(opts *bind.TransactOpts, role [32]byte, account common.Address) (*types.Transaction, error) {
	return _VeriLogRegistry.contract.Transact(opts, "grantRole", role, account)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_VeriLogRegistry *VeriLogRegistrySession) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.GrantRole(&_VeriLogRegistry.TransactOpts, role, account)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_VeriLogRegistry *VeriLogRegistryTransactorSession) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.GrantRole(&_VeriLogRegistry.TransactOpts, role, account)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_VeriLogRegistry *VeriLogRegistryTransactor) RenounceRole(opts *bind.TransactOpts, role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _VeriLogRegistry.contract.Transact(opts, "renounceRole", role, callerConfirmation)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_VeriLogRegistry *VeriLogRegistrySession) RenounceRole(role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.RenounceRole(&_VeriLogRegistry.TransactOpts, role, callerConfirmation)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_VeriLogRegistry *VeriLogRegistryTransactorSession) RenounceRole(role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.RenounceRole(&_VeriLogRegistry.TransactOpts, role, callerConfirmation)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_VeriLogRegistry *VeriLogRegistryTransactor) RevokeRole(opts *bind.TransactOpts, role [32]byte, account common.Address) (*types.Transaction, error) {
	return _VeriLogRegistry.contract.Transact(opts, "revokeRole", role, account)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_VeriLogRegistry *VeriLogRegistrySession) RevokeRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.RevokeRole(&_VeriLogRegistry.TransactOpts, role, account)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_VeriLogRegistry *VeriLogRegistryTransactorSession) RevokeRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.RevokeRole(&_VeriLogRegistry.TransactOpts, role, account)
}

// VeriLogRegistryLogAnchoredIterator is returned from FilterLogAnchored and is used to iterate over the raw logs and unpacked data for LogAnchored events raised by the VeriLogRegistry contract.
type VeriLogRegistryLogAnchoredIterator struct {
	Event *VeriLogRegistryLogAnchored // Event containing the contract specifics and raw log

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
func (it *VeriLogRegistryLogAnchoredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(VeriLogRegistryLogAnchored)
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
		it.Event = new(VeriLogRegistryLogAnchored)
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
func (it *VeriLogRegistryLogAnchoredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *VeriLogRegistryLogAnchoredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// VeriLogRegistryLogAnchored represents a LogAnchored event raised by the VeriLogRegistry contract.
type VeriLogRegistryLogAnchored struct {
	AgentId    [32]byte
	EpochId    *big.Int
	MerkleRoot [32]byte
	LogCount   uint32
	Timestamp  uint64
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterLogAnchored is a free log retrieval operation binding the contract event 0x0d7f028acbb0cc55a704d6d96e27d5ef5a8490693e35797fb31924541fcc7f30.
//
// Solidity: event LogAnchored(bytes32 indexed agentId, uint256 indexed epochId, bytes32 merkleRoot, uint32 logCount, uint64 timestamp)
func (_VeriLogRegistry *VeriLogRegistryFilterer) FilterLogAnchored(opts *bind.FilterOpts, agentId [][32]byte, epochId []*big.Int) (*VeriLogRegistryLogAnchoredIterator, error) {

	var agentIdRule []interface{}
	for _, agentIdItem := range agentId {
		agentIdRule = append(agentIdRule, agentIdItem)
	}
	var epochIdRule []interface{}
	for _, epochIdItem := range epochId {
		epochIdRule = append(epochIdRule, epochIdItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.FilterLogs(opts, "LogAnchored", agentIdRule, epochIdRule)
	if err != nil {
		return nil, err
	}
	return &VeriLogRegistryLogAnchoredIterator{contract: _VeriLogRegistry.contract, event: "LogAnchored", logs: logs, sub: sub}, nil
}

// WatchLogAnchored is a free log subscription operation binding the contract event 0x0d7f028acbb0cc55a704d6d96e27d5ef5a8490693e35797fb31924541fcc7f30.
//
// Solidity: event LogAnchored(bytes32 indexed agentId, uint256 indexed epochId, bytes32 merkleRoot, uint32 logCount, uint64 timestamp)
func (_VeriLogRegistry *VeriLogRegistryFilterer) WatchLogAnchored(opts *bind.WatchOpts, sink chan<- *VeriLogRegistryLogAnchored, agentId [][32]byte, epochId []*big.Int) (event.Subscription, error) {

	var agentIdRule []interface{}
	for _, agentIdItem := range agentId {
		agentIdRule = append(agentIdRule, agentIdItem)
	}
	var epochIdRule []interface{}
	for _, epochIdItem := range epochId {
		epochIdRule = append(epochIdRule, epochIdItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.WatchLogs(opts, "LogAnchored", agentIdRule, epochIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(VeriLogRegistryLogAnchored)
				if err := _VeriLogRegistry.contract.UnpackLog(event, "LogAnchored", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
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

// ParseLogAnchored is a log parse operation binding the contract event 0x0d7f028acbb0cc55a704d6d96e27d5ef5a8490693e35797fb31924541fcc7f30.
//
// Solidity: event LogAnchored(bytes32 indexed agentId, uint256 indexed epochId, bytes32 merkleRoot, uint32 logCount, uint64 timestamp)
func (_VeriLogRegistry *VeriLogRegistryFilterer) ParseLogAnchored(log types.Log) (*VeriLogRegistryLogAnchored, error) {
	event := new(VeriLogRegistryLogAnchored)
	if err := _VeriLogRegistry.contract.UnpackLog(event, "LogAnchored", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// VeriLogRegistryRoleAdminChangedIterator is returned from FilterRoleAdminChanged and is used to iterate over the raw logs and unpacked data for RoleAdminChanged events raised by the VeriLogRegistry contract.
type VeriLogRegistryRoleAdminChangedIterator struct {
	Event *VeriLogRegistryRoleAdminChanged // Event containing the contract specifics and raw log

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
func (it *VeriLogRegistryRoleAdminChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(VeriLogRegistryRoleAdminChanged)
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
		it.Event = new(VeriLogRegistryRoleAdminChanged)
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
func (it *VeriLogRegistryRoleAdminChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *VeriLogRegistryRoleAdminChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// VeriLogRegistryRoleAdminChanged represents a RoleAdminChanged event raised by the VeriLogRegistry contract.
type VeriLogRegistryRoleAdminChanged struct {
	Role              [32]byte
	PreviousAdminRole [32]byte
	NewAdminRole      [32]byte
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterRoleAdminChanged is a free log retrieval operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_VeriLogRegistry *VeriLogRegistryFilterer) FilterRoleAdminChanged(opts *bind.FilterOpts, role [][32]byte, previousAdminRole [][32]byte, newAdminRole [][32]byte) (*VeriLogRegistryRoleAdminChangedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var previousAdminRoleRule []interface{}
	for _, previousAdminRoleItem := range previousAdminRole {
		previousAdminRoleRule = append(previousAdminRoleRule, previousAdminRoleItem)
	}
	var newAdminRoleRule []interface{}
	for _, newAdminRoleItem := range newAdminRole {
		newAdminRoleRule = append(newAdminRoleRule, newAdminRoleItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.FilterLogs(opts, "RoleAdminChanged", roleRule, previousAdminRoleRule, newAdminRoleRule)
	if err != nil {
		return nil, err
	}
	return &VeriLogRegistryRoleAdminChangedIterator{contract: _VeriLogRegistry.contract, event: "RoleAdminChanged", logs: logs, sub: sub}, nil
}

// WatchRoleAdminChanged is a free log subscription operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_VeriLogRegistry *VeriLogRegistryFilterer) WatchRoleAdminChanged(opts *bind.WatchOpts, sink chan<- *VeriLogRegistryRoleAdminChanged, role [][32]byte, previousAdminRole [][32]byte, newAdminRole [][32]byte) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var previousAdminRoleRule []interface{}
	for _, previousAdminRoleItem := range previousAdminRole {
		previousAdminRoleRule = append(previousAdminRoleRule, previousAdminRoleItem)
	}
	var newAdminRoleRule []interface{}
	for _, newAdminRoleItem := range newAdminRole {
		newAdminRoleRule = append(newAdminRoleRule, newAdminRoleItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.WatchLogs(opts, "RoleAdminChanged", roleRule, previousAdminRoleRule, newAdminRoleRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(VeriLogRegistryRoleAdminChanged)
				if err := _VeriLogRegistry.contract.UnpackLog(event, "RoleAdminChanged", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
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

// ParseRoleAdminChanged is a log parse operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_VeriLogRegistry *VeriLogRegistryFilterer) ParseRoleAdminChanged(log types.Log) (*VeriLogRegistryRoleAdminChanged, error) {
	event := new(VeriLogRegistryRoleAdminChanged)
	if err := _VeriLogRegistry.contract.UnpackLog(event, "RoleAdminChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// VeriLogRegistryRoleGrantedIterator is returned from FilterRoleGranted and is used to iterate over the raw logs and unpacked data for RoleGranted events raised by the VeriLogRegistry contract.
type VeriLogRegistryRoleGrantedIterator struct {
	Event *VeriLogRegistryRoleGranted // Event containing the contract specifics and raw log

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
func (it *VeriLogRegistryRoleGrantedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(VeriLogRegistryRoleGranted)
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
		it.Event = new(VeriLogRegistryRoleGranted)
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
func (it *VeriLogRegistryRoleGrantedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *VeriLogRegistryRoleGrantedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// VeriLogRegistryRoleGranted represents a RoleGranted event raised by the VeriLogRegistry contract.
type VeriLogRegistryRoleGranted struct {
	Role    [32]byte
	Account common.Address
	Sender  common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRoleGranted is a free log retrieval operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_VeriLogRegistry *VeriLogRegistryFilterer) FilterRoleGranted(opts *bind.FilterOpts, role [][32]byte, account []common.Address, sender []common.Address) (*VeriLogRegistryRoleGrantedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.FilterLogs(opts, "RoleGranted", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return &VeriLogRegistryRoleGrantedIterator{contract: _VeriLogRegistry.contract, event: "RoleGranted", logs: logs, sub: sub}, nil
}

// WatchRoleGranted is a free log subscription operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_VeriLogRegistry *VeriLogRegistryFilterer) WatchRoleGranted(opts *bind.WatchOpts, sink chan<- *VeriLogRegistryRoleGranted, role [][32]byte, account []common.Address, sender []common.Address) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.WatchLogs(opts, "RoleGranted", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(VeriLogRegistryRoleGranted)
				if err := _VeriLogRegistry.contract.UnpackLog(event, "RoleGranted", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
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

// ParseRoleGranted is a log parse operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_VeriLogRegistry *VeriLogRegistryFilterer) ParseRoleGranted(log types.Log) (*VeriLogRegistryRoleGranted, error) {
	event := new(VeriLogRegistryRoleGranted)
	if err := _VeriLogRegistry.contract.UnpackLog(event, "RoleGranted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// VeriLogRegistryRoleRevokedIterator is returned from FilterRoleRevoked and is used to iterate over the raw logs and unpacked data for RoleRevoked events raised by the VeriLogRegistry contract.
type VeriLogRegistryRoleRevokedIterator struct {
	Event *VeriLogRegistryRoleRevoked // Event containing the contract specifics and raw log

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
func (it *VeriLogRegistryRoleRevokedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(VeriLogRegistryRoleRevoked)
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
		it.Event = new(VeriLogRegistryRoleRevoked)
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
func (it *VeriLogRegistryRoleRevokedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *VeriLogRegistryRoleRevokedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// VeriLogRegistryRoleRevoked represents a RoleRevoked event raised by the VeriLogRegistry contract.
type VeriLogRegistryRoleRevoked struct {
	Role    [32]byte
	Account common.Address
	Sender  common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRoleRevoked is a free log retrieval operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_VeriLogRegistry *VeriLogRegistryFilterer) FilterRoleRevoked(opts *bind.FilterOpts, role [][32]byte, account []common.Address, sender []common.Address) (*VeriLogRegistryRoleRevokedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.FilterLogs(opts, "RoleRevoked", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return &VeriLogRegistryRoleRevokedIterator{contract: _VeriLogRegistry.contract, event: "RoleRevoked", logs: logs, sub: sub}, nil
}

// WatchRoleRevoked is a free log subscription operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_VeriLogRegistry *VeriLogRegistryFilterer) WatchRoleRevoked(opts *bind.WatchOpts, sink chan<- *VeriLogRegistryRoleRevoked, role [][32]byte, account []common.Address, sender []common.Address) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.WatchLogs(opts, "RoleRevoked", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(VeriLogRegistryRoleRevoked)
				if err := _VeriLogRegistry.contract.UnpackLog(event, "RoleRevoked", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
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

// ParseRoleRevoked is a log parse operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_VeriLogRegistry *VeriLogRegistryFilterer) ParseRoleRevoked(log types.Log) (*VeriLogRegistryRoleRevoked, error) {
	event := new(VeriLogRegistryRoleRevoked)
	if err := _VeriLogRegistry.contract.UnpackLog(event, "RoleRevoked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
