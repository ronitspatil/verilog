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
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"admin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"anchorer\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"ANCHORER_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"DEFAULT_ADMIN_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"KEY_ADMIN_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"agentAnchors\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"merkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"logCount\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"agentKeys\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"keyId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"pubkey\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validFrom\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revokedAt\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"anchorEpoch\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"merkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"logCount\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[{\"name\":\"epochId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getRoleAdmin\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"grantRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"hasRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"isWeakPubkey\",\"inputs\":[{\"name\":\"pubkey\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"latestEpoch\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"registerAgentKey\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"pubkey\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"keyId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"renounceRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"callerConfirmation\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"revokeAgentKey\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"keyId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"effectiveAt\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"revokeRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"supportsInterface\",\"inputs\":[{\"name\":\"interfaceId\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"verifyAnchoredLeaf\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"epochId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"leaf\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"verifyProof\",\"inputs\":[{\"name\":\"leaf\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"root\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"event\",\"name\":\"AgentKeyRegistered\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"keyId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"pubkey\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"validFrom\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"AgentKeyRevoked\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"keyId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"revokedAt\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"},{\"name\":\"recordedAt\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"LogAnchored\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"epochId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"},{\"name\":\"merkleRoot\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"logCount\",\"type\":\"uint32\",\"indexed\":false,\"internalType\":\"uint32\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleAdminChanged\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"previousAdminRole\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"newAdminRole\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleGranted\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"sender\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleRevoked\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"sender\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AccessControlBadConfirmation\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"AccessControlUnauthorizedAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"neededRole\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"AnchorerCannotAdminister\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"EpochNotAnchored\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"epochId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"KeyAlreadyRevoked\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"keyId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"KeyExists\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"keyId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"RevocationInPast\",\"inputs\":[{\"name\":\"effectiveAt\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"blockTimestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"type\":\"error\",\"name\":\"UnknownKey\",\"inputs\":[{\"name\":\"agentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"keyId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"WeakPubkey\",\"inputs\":[{\"name\":\"pubkey\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"ZeroAddress\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZeroAgentId\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZeroLogCount\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZeroMerkleRoot\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZeroPubkey\",\"inputs\":[]}]",
	Bin: "0x608060405234801561000f575f5ffd5b5060405161180438038061180483398101604081905261002e916102c4565b6001600160a01b038216158061004b57506001600160a01b038116155b156100695760405163d92e233d60e01b815260040160405180910390fd5b6100735f836100ab565b5061008b5f5160206117e45f395f51905f52836100ab565b506100a35f5160206117c45f395f51905f52826100ab565b5050506102f5565b5f5f5160206117c45f395f51905f52830361016e576001600160a01b0382165f9081527f4f39ad2d49660849ded16eb618fd35bd782bc9826b29c3464c6dd0a5826c2046602052604090205460ff168061013b57506001600160a01b0382165f9081527fad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5602052604090205460ff165b156101695760405163339304c160e21b81526001600160a01b03831660048201526024015b60405180910390fd5b6101ef565b5f5160206117e45f395f51905f52831480610187575082155b156101ef576001600160a01b0382165f9081527ff9afc5eccc556dfbeedb3ca7bc93a51b4efbf91901a8edd8d8d95baa0671a408602052604090205460ff16156101ef5760405163339304c160e21b81526001600160a01b0383166004820152602401610160565b6101f98383610202565b90505b92915050565b5f828152602081815260408083206001600160a01b038516845290915281205460ff166102a2575f838152602081815260408083206001600160a01b03861684529091529020805460ff1916600117905561025a3390565b6001600160a01b0316826001600160a01b0316847f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d60405160405180910390a45060016101fc565b505f6101fc565b80516001600160a01b03811681146102bf575f5ffd5b919050565b5f5f604083850312156102d5575f5ffd5b6102de836102a9565b91506102ec602084016102a9565b90509250929050565b6114c2806103025f395ff3fe608060405234801561000f575f5ffd5b506004361061012f575f3560e01c80636876f5d7116100ad578063a217fddf1161007d578063bfcedf5411610063578063bfcedf5414610333578063c9ecaf6d146103a4578063d547741f146103c3575f5ffd5b8063a217fddf14610319578063abaad9ae14610320575f5ffd5b80636876f5d7146102895780637cfd9a511461029c578063804177c2146102c357806391d14854146102d6575f5ffd5b8063231b80d2116101025780632f2ff15d116100e85780632f2ff15d1461025057806336568abe1461026357806358161a4214610276575f5ffd5b8063231b80d21461021b578063248a9ca31461022e575f5ffd5b806301ffc9a714610133578063068fbdc21461015b5780630819f8141461017057806309fe0387146101e6575b5f5ffd5b61014661014136600461123b565b6103d6565b60405190151581526020015b60405180910390f35b61016e61016936600461127a565b61046e565b005b6101bc61017e3660046112bc565b600160208181525f93845260408085209091529183529120805491015467ffffffffffffffff81169068010000000000000000900463ffffffff1683565b6040805193845267ffffffffffffffff909216602084015263ffffffff1690820152606001610152565b61020d7f460de93bc770bad3bedb94b9a38b09df8ac71a47512a218a7cb89bfe8008abdc81565b604051908152602001610152565b610146610229366004611324565b61063d565b61020d61023c366004611380565b5f9081526020819052604090206001015490565b61016e61025e366004611397565b6106ae565b61016e610271366004611397565b6106d8565b6101466102843660046113dd565b610736565b61020d6102973660046112bc565b61074c565b61020d7f4b3e6527f1b0d33beb6c20e3c362af276f03c4526b5f8b6d118672f0d75a60eb81565b6101466102d1366004611380565b6109a4565b6101466102e4366004611397565b5f9182526020828152604080842073ffffffffffffffffffffffffffffffffffffffff93909316845291905290205460ff1690565b61020d5f81565b61020d61032e36600461142c565b610b82565b61037e6103413660046112bc565b600360209081525f92835260408084209091529082529020805460019091015467ffffffffffffffff808216916801000000000000000090041683565b6040805193845267ffffffffffffffff9283166020850152911690820152606001610152565b61020d6103b2366004611380565b60026020525f908152604090205481565b61016e6103d1366004611397565b610d69565b5f7fffffffff0000000000000000000000000000000000000000000000000000000082167f7965db0b00000000000000000000000000000000000000000000000000000000148061046857507f01ffc9a7000000000000000000000000000000000000000000000000000000007fffffffff000000000000000000000000000000000000000000000000000000008316145b92915050565b7f460de93bc770bad3bedb94b9a38b09df8ac71a47512a218a7cb89bfe8008abdc61049881610d8d565b5f848152600360209081526040808320868452909152902080546104f7576040517f2f5b76ac00000000000000000000000000000000000000000000000000000000815260048101869052602481018590526044015b60405180910390fd5b600181015468010000000000000000900467ffffffffffffffff1615610553576040517fb0d6c16f00000000000000000000000000000000000000000000000000000000815260048101869052602481018590526044016104ee565b4267ffffffffffffffff80821690851610156105af576040517fb14c2fc800000000000000000000000000000000000000000000000000000000815267ffffffffffffffff8086166004830152821660248201526044016104ee565b6001820180547fffffffffffffffffffffffffffffffff0000000000000000ffffffffffffffff166801000000000000000067ffffffffffffffff87811691820292909217909255604080519283529083166020830152869188917f468bba4cbd1d2f6d2e5f110b913ef83942bca8242a5f567b60becad23d702571910160405180910390a3505050505050565b5f85815260016020908152604080832087845290915281205480610697576040517facaaf6ef00000000000000000000000000000000000000000000000000000000815260048101889052602481018790526044016104ee565b6106a384848388610d9a565b979650505050505050565b5f828152602081905260409020600101546106c881610d8d565b6106d28383610db1565b50505050565b73ffffffffffffffffffffffffffffffffffffffff81163314610727576040517f6697b23200000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6107318282610f93565b505050565b5f61074384848488610d9a565b95945050505050565b5f7f460de93bc770bad3bedb94b9a38b09df8ac71a47512a218a7cb89bfe8008abdc61077781610d8d565b836107ae576040517f42c5b17a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b826107e5576040517f4935505f00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6107ee836109a4565b15610828576040517f4fb3f415000000000000000000000000000000000000000000000000000000008152600481018490526024016104ee565b604080516020810185905201604080517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe081840301815291815281516020928301205f87815260038452828120828252909352912054909250156108c2576040517f3b6af2de00000000000000000000000000000000000000000000000000000000815260048101859052602481018390526044016104ee565b6040805160608101825284815267ffffffffffffffff4281811660208085019182525f8587018181528b8252600383528782208a8352909252869020945185559051600190940180549151841668010000000000000000027fffffffffffffffffffffffffffffffff0000000000000000000000000000000090921694909316939093179290921790559051839086907f6ee71b52095caaca792b0200e1634f78566623b204e3c6c48291c9e186793b6890610994908890869091825267ffffffffffffffff16602082015260400190565b60405180910390a3505092915050565b5f7f01000000000000000000000000000000000000000000000000000000000000008214806109f257507fecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f82145b806109fb575081155b80610a065750608082145b80610a3057507f26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc0582145b80610a5a57507f26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc8582145b80610a8457507fc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a82145b80610aae57507fc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa82145b15610abb57506001919050565b7f0100000000000000000000000000000000000000000000000000000000000080821480610b0857507fecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82145b15610b1557506001919050565b8160ed60f882901c10801590610b6c5750600881901c7dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff167dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff145b8015610b7b575080607f16607f145b9392505050565b5f7f4b3e6527f1b0d33beb6c20e3c362af276f03c4526b5f8b6d118672f0d75a60eb610bad81610d8d565b84610be4576040517f42c5b17a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b83610c1b576040517f9266ee6200000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b8263ffffffff165f03610c5a576040517ffb00b7a900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f8581526002602090815260408083208054600190810191829055825160608101845289815267ffffffffffffffff4281811683880190815263ffffffff808d168589019081528f8b52868a52888b20888c52909952988790209351845551929093018054965190971668010000000000000000027fffffffffffffffffffffffffffffffffffffffff000000000000000000000000909616911617939093179093555191935090839087907f0d7f028acbb0cc55a704d6d96e27d5ef5a8490693e35797fb31924541fcc7f3090610d589089908990879092835263ffffffff91909116602083015267ffffffffffffffff16604082015260600190565b60405180910390a350509392505050565b5f82815260208190526040902060010154610d8381610d8d565b6106d28383610f93565b610d978133611053565b50565b5f82610da78686856110dc565b1495945050505050565b5f7f4b3e6527f1b0d33beb6c20e3c362af276f03c4526b5f8b6d118672f0d75a60eb8303610ec25773ffffffffffffffffffffffffffffffffffffffff82165f9081527f4f39ad2d49660849ded16eb618fd35bd782bc9826b29c3464c6dd0a5826c2046602052604090205460ff1680610e6e575073ffffffffffffffffffffffffffffffffffffffff82165f9081527fad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5602052604090205460ff165b15610ebd576040517fce4c130400000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff831660048201526024016104ee565b610f89565b7f460de93bc770bad3bedb94b9a38b09df8ac71a47512a218a7cb89bfe8008abdc831480610eee575082155b15610f895773ffffffffffffffffffffffffffffffffffffffff82165f9081527ff9afc5eccc556dfbeedb3ca7bc93a51b4efbf91901a8edd8d8d95baa0671a408602052604090205460ff1615610f89576040517fce4c130400000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff831660048201526024016104ee565b610b7b838361111d565b5f8281526020818152604080832073ffffffffffffffffffffffffffffffffffffffff8516845290915281205460ff161561104c575f8381526020818152604080832073ffffffffffffffffffffffffffffffffffffffff8616808552925280832080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0016905551339286917ff6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b9190a4506001610468565b505f610468565b5f8281526020818152604080832073ffffffffffffffffffffffffffffffffffffffff8516845290915290205460ff166110d8576040517fe2517d3f00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff82166004820152602481018390526044016104ee565b5050565b5f81815b848110156111145761110a828787848181106110fe576110fe61145f565b9050602002013561120f565b91506001016110e0565b50949350505050565b5f8281526020818152604080832073ffffffffffffffffffffffffffffffffffffffff8516845290915281205460ff1661104c575f8381526020818152604080832073ffffffffffffffffffffffffffffffffffffffff86168452909152902080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660011790556111ad3390565b73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16847f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d60405160405180910390a4506001610468565b5f818310611229575f828152602084905260409020610b7b565b5f838152602083905260409020610b7b565b5f6020828403121561124b575f5ffd5b81357fffffffff0000000000000000000000000000000000000000000000000000000081168114610b7b575f5ffd5b5f5f5f6060848603121561128c575f5ffd5b8335925060208401359150604084013567ffffffffffffffff811681146112b1575f5ffd5b809150509250925092565b5f5f604083850312156112cd575f5ffd5b50508035926020909101359150565b5f5f83601f8401126112ec575f5ffd5b50813567ffffffffffffffff811115611303575f5ffd5b6020830191508360208260051b850101111561131d575f5ffd5b9250929050565b5f5f5f5f5f60808688031215611338575f5ffd5b853594506020860135935060408601359250606086013567ffffffffffffffff811115611363575f5ffd5b61136f888289016112dc565b969995985093965092949392505050565b5f60208284031215611390575f5ffd5b5035919050565b5f5f604083850312156113a8575f5ffd5b82359150602083013573ffffffffffffffffffffffffffffffffffffffff811681146113d2575f5ffd5b809150509250929050565b5f5f5f5f606085870312156113f0575f5ffd5b84359350602085013567ffffffffffffffff81111561140d575f5ffd5b611419878288016112dc565b9598909750949560400135949350505050565b5f5f5f6060848603121561143e575f5ffd5b8335925060208401359150604084013563ffffffff811681146112b1575f5ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffdfea2646970667358221220c5e4c4759907236d7c173a69b4fb5cedd345a08e0ea925ea3bb4dbc442af1c5d64736f6c634300081c00334b3e6527f1b0d33beb6c20e3c362af276f03c4526b5f8b6d118672f0d75a60eb460de93bc770bad3bedb94b9a38b09df8ac71a47512a218a7cb89bfe8008abdc",
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

// KEYADMINROLE is a free data retrieval call binding the contract method 0x09fe0387.
//
// Solidity: function KEY_ADMIN_ROLE() view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistryCaller) KEYADMINROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "KEY_ADMIN_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// KEYADMINROLE is a free data retrieval call binding the contract method 0x09fe0387.
//
// Solidity: function KEY_ADMIN_ROLE() view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistrySession) KEYADMINROLE() ([32]byte, error) {
	return _VeriLogRegistry.Contract.KEYADMINROLE(&_VeriLogRegistry.CallOpts)
}

// KEYADMINROLE is a free data retrieval call binding the contract method 0x09fe0387.
//
// Solidity: function KEY_ADMIN_ROLE() view returns(bytes32)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) KEYADMINROLE() ([32]byte, error) {
	return _VeriLogRegistry.Contract.KEYADMINROLE(&_VeriLogRegistry.CallOpts)
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

// AgentKeys is a free data retrieval call binding the contract method 0xbfcedf54.
//
// Solidity: function agentKeys(bytes32 agentId, bytes32 keyId) view returns(bytes32 pubkey, uint64 validFrom, uint64 revokedAt)
func (_VeriLogRegistry *VeriLogRegistryCaller) AgentKeys(opts *bind.CallOpts, agentId [32]byte, keyId [32]byte) (struct {
	Pubkey    [32]byte
	ValidFrom uint64
	RevokedAt uint64
}, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "agentKeys", agentId, keyId)

	outstruct := new(struct {
		Pubkey    [32]byte
		ValidFrom uint64
		RevokedAt uint64
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Pubkey = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.ValidFrom = *abi.ConvertType(out[1], new(uint64)).(*uint64)
	outstruct.RevokedAt = *abi.ConvertType(out[2], new(uint64)).(*uint64)

	return *outstruct, err

}

// AgentKeys is a free data retrieval call binding the contract method 0xbfcedf54.
//
// Solidity: function agentKeys(bytes32 agentId, bytes32 keyId) view returns(bytes32 pubkey, uint64 validFrom, uint64 revokedAt)
func (_VeriLogRegistry *VeriLogRegistrySession) AgentKeys(agentId [32]byte, keyId [32]byte) (struct {
	Pubkey    [32]byte
	ValidFrom uint64
	RevokedAt uint64
}, error) {
	return _VeriLogRegistry.Contract.AgentKeys(&_VeriLogRegistry.CallOpts, agentId, keyId)
}

// AgentKeys is a free data retrieval call binding the contract method 0xbfcedf54.
//
// Solidity: function agentKeys(bytes32 agentId, bytes32 keyId) view returns(bytes32 pubkey, uint64 validFrom, uint64 revokedAt)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) AgentKeys(agentId [32]byte, keyId [32]byte) (struct {
	Pubkey    [32]byte
	ValidFrom uint64
	RevokedAt uint64
}, error) {
	return _VeriLogRegistry.Contract.AgentKeys(&_VeriLogRegistry.CallOpts, agentId, keyId)
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

// IsWeakPubkey is a free data retrieval call binding the contract method 0x804177c2.
//
// Solidity: function isWeakPubkey(bytes32 pubkey) pure returns(bool)
func (_VeriLogRegistry *VeriLogRegistryCaller) IsWeakPubkey(opts *bind.CallOpts, pubkey [32]byte) (bool, error) {
	var out []interface{}
	err := _VeriLogRegistry.contract.Call(opts, &out, "isWeakPubkey", pubkey)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsWeakPubkey is a free data retrieval call binding the contract method 0x804177c2.
//
// Solidity: function isWeakPubkey(bytes32 pubkey) pure returns(bool)
func (_VeriLogRegistry *VeriLogRegistrySession) IsWeakPubkey(pubkey [32]byte) (bool, error) {
	return _VeriLogRegistry.Contract.IsWeakPubkey(&_VeriLogRegistry.CallOpts, pubkey)
}

// IsWeakPubkey is a free data retrieval call binding the contract method 0x804177c2.
//
// Solidity: function isWeakPubkey(bytes32 pubkey) pure returns(bool)
func (_VeriLogRegistry *VeriLogRegistryCallerSession) IsWeakPubkey(pubkey [32]byte) (bool, error) {
	return _VeriLogRegistry.Contract.IsWeakPubkey(&_VeriLogRegistry.CallOpts, pubkey)
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

// RegisterAgentKey is a paid mutator transaction binding the contract method 0x6876f5d7.
//
// Solidity: function registerAgentKey(bytes32 agentId, bytes32 pubkey) returns(bytes32 keyId)
func (_VeriLogRegistry *VeriLogRegistryTransactor) RegisterAgentKey(opts *bind.TransactOpts, agentId [32]byte, pubkey [32]byte) (*types.Transaction, error) {
	return _VeriLogRegistry.contract.Transact(opts, "registerAgentKey", agentId, pubkey)
}

// RegisterAgentKey is a paid mutator transaction binding the contract method 0x6876f5d7.
//
// Solidity: function registerAgentKey(bytes32 agentId, bytes32 pubkey) returns(bytes32 keyId)
func (_VeriLogRegistry *VeriLogRegistrySession) RegisterAgentKey(agentId [32]byte, pubkey [32]byte) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.RegisterAgentKey(&_VeriLogRegistry.TransactOpts, agentId, pubkey)
}

// RegisterAgentKey is a paid mutator transaction binding the contract method 0x6876f5d7.
//
// Solidity: function registerAgentKey(bytes32 agentId, bytes32 pubkey) returns(bytes32 keyId)
func (_VeriLogRegistry *VeriLogRegistryTransactorSession) RegisterAgentKey(agentId [32]byte, pubkey [32]byte) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.RegisterAgentKey(&_VeriLogRegistry.TransactOpts, agentId, pubkey)
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

// RevokeAgentKey is a paid mutator transaction binding the contract method 0x068fbdc2.
//
// Solidity: function revokeAgentKey(bytes32 agentId, bytes32 keyId, uint64 effectiveAt) returns()
func (_VeriLogRegistry *VeriLogRegistryTransactor) RevokeAgentKey(opts *bind.TransactOpts, agentId [32]byte, keyId [32]byte, effectiveAt uint64) (*types.Transaction, error) {
	return _VeriLogRegistry.contract.Transact(opts, "revokeAgentKey", agentId, keyId, effectiveAt)
}

// RevokeAgentKey is a paid mutator transaction binding the contract method 0x068fbdc2.
//
// Solidity: function revokeAgentKey(bytes32 agentId, bytes32 keyId, uint64 effectiveAt) returns()
func (_VeriLogRegistry *VeriLogRegistrySession) RevokeAgentKey(agentId [32]byte, keyId [32]byte, effectiveAt uint64) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.RevokeAgentKey(&_VeriLogRegistry.TransactOpts, agentId, keyId, effectiveAt)
}

// RevokeAgentKey is a paid mutator transaction binding the contract method 0x068fbdc2.
//
// Solidity: function revokeAgentKey(bytes32 agentId, bytes32 keyId, uint64 effectiveAt) returns()
func (_VeriLogRegistry *VeriLogRegistryTransactorSession) RevokeAgentKey(agentId [32]byte, keyId [32]byte, effectiveAt uint64) (*types.Transaction, error) {
	return _VeriLogRegistry.Contract.RevokeAgentKey(&_VeriLogRegistry.TransactOpts, agentId, keyId, effectiveAt)
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

// VeriLogRegistryAgentKeyRegisteredIterator is returned from FilterAgentKeyRegistered and is used to iterate over the raw logs and unpacked data for AgentKeyRegistered events raised by the VeriLogRegistry contract.
type VeriLogRegistryAgentKeyRegisteredIterator struct {
	Event *VeriLogRegistryAgentKeyRegistered // Event containing the contract specifics and raw log

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
func (it *VeriLogRegistryAgentKeyRegisteredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(VeriLogRegistryAgentKeyRegistered)
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
		it.Event = new(VeriLogRegistryAgentKeyRegistered)
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
func (it *VeriLogRegistryAgentKeyRegisteredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *VeriLogRegistryAgentKeyRegisteredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// VeriLogRegistryAgentKeyRegistered represents a AgentKeyRegistered event raised by the VeriLogRegistry contract.
type VeriLogRegistryAgentKeyRegistered struct {
	AgentId   [32]byte
	KeyId     [32]byte
	Pubkey    [32]byte
	ValidFrom uint64
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterAgentKeyRegistered is a free log retrieval operation binding the contract event 0x6ee71b52095caaca792b0200e1634f78566623b204e3c6c48291c9e186793b68.
//
// Solidity: event AgentKeyRegistered(bytes32 indexed agentId, bytes32 indexed keyId, bytes32 pubkey, uint64 validFrom)
func (_VeriLogRegistry *VeriLogRegistryFilterer) FilterAgentKeyRegistered(opts *bind.FilterOpts, agentId [][32]byte, keyId [][32]byte) (*VeriLogRegistryAgentKeyRegisteredIterator, error) {

	var agentIdRule []interface{}
	for _, agentIdItem := range agentId {
		agentIdRule = append(agentIdRule, agentIdItem)
	}
	var keyIdRule []interface{}
	for _, keyIdItem := range keyId {
		keyIdRule = append(keyIdRule, keyIdItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.FilterLogs(opts, "AgentKeyRegistered", agentIdRule, keyIdRule)
	if err != nil {
		return nil, err
	}
	return &VeriLogRegistryAgentKeyRegisteredIterator{contract: _VeriLogRegistry.contract, event: "AgentKeyRegistered", logs: logs, sub: sub}, nil
}

// WatchAgentKeyRegistered is a free log subscription operation binding the contract event 0x6ee71b52095caaca792b0200e1634f78566623b204e3c6c48291c9e186793b68.
//
// Solidity: event AgentKeyRegistered(bytes32 indexed agentId, bytes32 indexed keyId, bytes32 pubkey, uint64 validFrom)
func (_VeriLogRegistry *VeriLogRegistryFilterer) WatchAgentKeyRegistered(opts *bind.WatchOpts, sink chan<- *VeriLogRegistryAgentKeyRegistered, agentId [][32]byte, keyId [][32]byte) (event.Subscription, error) {

	var agentIdRule []interface{}
	for _, agentIdItem := range agentId {
		agentIdRule = append(agentIdRule, agentIdItem)
	}
	var keyIdRule []interface{}
	for _, keyIdItem := range keyId {
		keyIdRule = append(keyIdRule, keyIdItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.WatchLogs(opts, "AgentKeyRegistered", agentIdRule, keyIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(VeriLogRegistryAgentKeyRegistered)
				if err := _VeriLogRegistry.contract.UnpackLog(event, "AgentKeyRegistered", log); err != nil {
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

// ParseAgentKeyRegistered is a log parse operation binding the contract event 0x6ee71b52095caaca792b0200e1634f78566623b204e3c6c48291c9e186793b68.
//
// Solidity: event AgentKeyRegistered(bytes32 indexed agentId, bytes32 indexed keyId, bytes32 pubkey, uint64 validFrom)
func (_VeriLogRegistry *VeriLogRegistryFilterer) ParseAgentKeyRegistered(log types.Log) (*VeriLogRegistryAgentKeyRegistered, error) {
	event := new(VeriLogRegistryAgentKeyRegistered)
	if err := _VeriLogRegistry.contract.UnpackLog(event, "AgentKeyRegistered", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// VeriLogRegistryAgentKeyRevokedIterator is returned from FilterAgentKeyRevoked and is used to iterate over the raw logs and unpacked data for AgentKeyRevoked events raised by the VeriLogRegistry contract.
type VeriLogRegistryAgentKeyRevokedIterator struct {
	Event *VeriLogRegistryAgentKeyRevoked // Event containing the contract specifics and raw log

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
func (it *VeriLogRegistryAgentKeyRevokedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(VeriLogRegistryAgentKeyRevoked)
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
		it.Event = new(VeriLogRegistryAgentKeyRevoked)
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
func (it *VeriLogRegistryAgentKeyRevokedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *VeriLogRegistryAgentKeyRevokedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// VeriLogRegistryAgentKeyRevoked represents a AgentKeyRevoked event raised by the VeriLogRegistry contract.
type VeriLogRegistryAgentKeyRevoked struct {
	AgentId    [32]byte
	KeyId      [32]byte
	RevokedAt  uint64
	RecordedAt uint64
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterAgentKeyRevoked is a free log retrieval operation binding the contract event 0x468bba4cbd1d2f6d2e5f110b913ef83942bca8242a5f567b60becad23d702571.
//
// Solidity: event AgentKeyRevoked(bytes32 indexed agentId, bytes32 indexed keyId, uint64 revokedAt, uint64 recordedAt)
func (_VeriLogRegistry *VeriLogRegistryFilterer) FilterAgentKeyRevoked(opts *bind.FilterOpts, agentId [][32]byte, keyId [][32]byte) (*VeriLogRegistryAgentKeyRevokedIterator, error) {

	var agentIdRule []interface{}
	for _, agentIdItem := range agentId {
		agentIdRule = append(agentIdRule, agentIdItem)
	}
	var keyIdRule []interface{}
	for _, keyIdItem := range keyId {
		keyIdRule = append(keyIdRule, keyIdItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.FilterLogs(opts, "AgentKeyRevoked", agentIdRule, keyIdRule)
	if err != nil {
		return nil, err
	}
	return &VeriLogRegistryAgentKeyRevokedIterator{contract: _VeriLogRegistry.contract, event: "AgentKeyRevoked", logs: logs, sub: sub}, nil
}

// WatchAgentKeyRevoked is a free log subscription operation binding the contract event 0x468bba4cbd1d2f6d2e5f110b913ef83942bca8242a5f567b60becad23d702571.
//
// Solidity: event AgentKeyRevoked(bytes32 indexed agentId, bytes32 indexed keyId, uint64 revokedAt, uint64 recordedAt)
func (_VeriLogRegistry *VeriLogRegistryFilterer) WatchAgentKeyRevoked(opts *bind.WatchOpts, sink chan<- *VeriLogRegistryAgentKeyRevoked, agentId [][32]byte, keyId [][32]byte) (event.Subscription, error) {

	var agentIdRule []interface{}
	for _, agentIdItem := range agentId {
		agentIdRule = append(agentIdRule, agentIdItem)
	}
	var keyIdRule []interface{}
	for _, keyIdItem := range keyId {
		keyIdRule = append(keyIdRule, keyIdItem)
	}

	logs, sub, err := _VeriLogRegistry.contract.WatchLogs(opts, "AgentKeyRevoked", agentIdRule, keyIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(VeriLogRegistryAgentKeyRevoked)
				if err := _VeriLogRegistry.contract.UnpackLog(event, "AgentKeyRevoked", log); err != nil {
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

// ParseAgentKeyRevoked is a log parse operation binding the contract event 0x468bba4cbd1d2f6d2e5f110b913ef83942bca8242a5f567b60becad23d702571.
//
// Solidity: event AgentKeyRevoked(bytes32 indexed agentId, bytes32 indexed keyId, uint64 revokedAt, uint64 recordedAt)
func (_VeriLogRegistry *VeriLogRegistryFilterer) ParseAgentKeyRevoked(log types.Log) (*VeriLogRegistryAgentKeyRevoked, error) {
	event := new(VeriLogRegistryAgentKeyRevoked)
	if err := _VeriLogRegistry.contract.UnpackLog(event, "AgentKeyRevoked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
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
