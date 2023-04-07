import { Signer, ContractFactory, Overrides } from "ethers";
import type { Provider, TransactionRequest } from "@ethersproject/providers";
import type { PromiseOrValue } from "../common";
import type { ZeroDevSessionKeyPlugin, ZeroDevSessionKeyPluginInterface } from "../ZeroDevSessionKeyPlugin";
type ZeroDevSessionKeyPluginConstructorParams = [signer?: Signer] | ConstructorParameters<typeof ContractFactory>;
export declare class ZeroDevSessionKeyPlugin__factory extends ContractFactory {
    constructor(...args: ZeroDevSessionKeyPluginConstructorParams);
    deploy(overrides?: Overrides & {
        from?: PromiseOrValue<string>;
    }): Promise<ZeroDevSessionKeyPlugin>;
    getDeployTransaction(overrides?: Overrides & {
        from?: PromiseOrValue<string>;
    }): TransactionRequest;
    attach(address: string): ZeroDevSessionKeyPlugin;
    connect(signer: Signer): ZeroDevSessionKeyPlugin__factory;
    static readonly bytecode = "0x6101406040523480156200001257600080fd5b506040518060400160405280601781526020017f5a65726f44657653657373696f6e4b6579506c7567696e0000000000000000008152506040518060400160405280600581526020017f302e302e3100000000000000000000000000000000000000000000000000000081525060008280519060200120905060008280519060200120905060007f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f90508260e081815250508161010081815250504660a08181525050620000e88184846200013760201b60201c565b608081815250503073ffffffffffffffffffffffffffffffffffffffff1660c08173ffffffffffffffffffffffffffffffffffffffff168152505080610120818152505050505050506200024b565b6000838383463060405160200162000154959493929190620001ee565b6040516020818303038152906040528051906020012090509392505050565b6000819050919050565b620001888162000173565b82525050565b6000819050919050565b620001a3816200018e565b82525050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000620001d682620001a9565b9050919050565b620001e881620001c9565b82525050565b600060a0820190506200020560008301886200017d565b6200021460208301876200017d565b6200022360408301866200017d565b62000232606083018562000198565b620002416080830184620001dd565b9695505050505050565b60805160a05160c05160e051610100516101205161208a6200029b6000396000610d4201526000610d8401526000610d6301526000610c9801526000610cee01526000610d17015261208a6000f3fe608060405234801561001057600080fd5b50600436106100575760003560e01c80636d0ae0461461005c57806384f4fc6a1461008c578063970aa9ad146100a85780639e2045ce146100db578063fa01dc061461010b575b600080fd5b61007660048036038101906100719190611168565b61013b565b60405161008391906111ae565b60405180910390f35b6100a660048036038101906100a19190611168565b61018d565b005b6100c260048036038101906100bd919061122e565b610234565b6040516100d294939291906112d9565b60405180910390f35b6100f560048036038101906100f0919061139b565b610447565b6040516101029190611425565b60405180910390f35b61012560048036038101906101209190611168565b61049c565b6040516101329190611425565b60405180910390f35b60006101456104fb565b60010160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b60016101976104fb565b60000160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055508073ffffffffffffffffffffffffffffffffffffffff167f17c796fb82086b3c9effaec517342e5ca9ed8fd78c339137ec082f748ab60cbe60405160405180910390a250565b36600036600080868660009060209261024f9392919061144a565b9061025a919061149d565b60001c9050600087878390602085610272919061152b565b9261027f9392919061144a565b9061028a919061149d565b60001c9050600088886020906040926102a59392919061144a565b906102b0919061149d565b60001c90506000898983906020856102c8919061152b565b926102d59392919061144a565b906102e0919061149d565b60001c905089896020866102f4919061152b565b9085602088610303919061152b565b61030d919061152b565b9261031a9392919061144a565b97509750898960208461032d919061152b565b908360208661033c919061152b565b610346919061152b565b926103539392919061144a565b955095508160208085610366919061158e565b61037091906115bf565b60408661037d919061152b565b610387919061152b565b146103c7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103be9061165e565b60405180910390fd5b89899050602080836103d9919061158e565b6103e391906115bf565b6040846103f0919061152b565b6103fa919061152b565b1461043a576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610431906116ca565b60405180910390fd5b5050505092959194509250565b60003660003660006104798880610140019061046391906116f9565b60619080926104749392919061144a565b610234565b935093509350935061048f88888686868661053a565b9450505050509392505050565b60006104a66104fb565b60000160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff169050919050565b60008060017f6da8a1d7d4f224b5b2581a964c1890eb7e987638c691727e5a2a14ca24d03fd960001c61052e919061175c565b60001b90508091505090565b60008085856000906014926105519392919061144a565b9061055c91906117bc565b60601c90506105696104fb565b60000160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16156105f7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105ee90611867565b60405180910390fd5b87602001356106046104fb565b60010160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205414610685576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161067c906118d3565b60405180910390fd5b6000868660149060349261069b9392919061144a565b906106a6919061149d565b90506000801b810315610a58576000858560008181106106c9576106c86118f3565b5b9050013560f81c60f81b60f81c90506060600060148360ff16036107f45787876001906015926106fb9392919061144a565b604051610709929190611952565b60405180910390209050878760569080926107269392919061144a565b8101906107339190611aa9565b915087876001906015926107499392919061144a565b604051610757929190611952565b60405180910390208c806060019061076f91906116f9565b6010906024926107819392919061144a565b60405161078f929190611952565b6040518091039020146107d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016107ce90611b3e565b60405180910390fd5b87876015906056926107eb9392919061144a565b97509750610a0a565b60188360ff16036109ce5787876001906019926108139392919061144a565b604051610821929190611952565b604051809103902090508787605a90809261083e9392919061144a565b81019061084b9190611aa9565b915087876001906015926108619392919061144a565b60405161086f929190611952565b60405180910390208c806060019061088791906116f9565b6010906024926108999392919061144a565b6040516108a7929190611952565b6040518091039020146108ef576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108e690611b3e565b60405180910390fd5b60008c806060019061090191906116f9565b6044906064926109139392919061144a565b9061091e919061149d565b60001c90503660008e806060019061093691906116f9565b602485610943919061152b565b90602886610951919061152b565b9261095e9392919061144a565b915091508a8a6015906019926109769392919061144a565b604051610984929190611952565b6040518091039020828260405161099c929190611b5e565b6040518091039020146109ae57600080fd5b8a8a601990605a926109c29392919061144a565b9a509a50505050610a09565b6040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a0090611bc3565b60405180910390fd5b5b610a15828583610be6565b610a54576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a4b90611c2f565b60405180910390fd5b5050505b6000610b097ff0a98eef9608fd8bfe5833dfbc8b73ab86d0355db37a1f539565c5985ad1c2428a610a876104fb565b60010160008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000815480929190610ad890611c4f565b91905055604051602001610aee93929190611ca6565b60405160208183030381529060405280519060200120610bfd565b90506000610b6487878080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505083610c1790919063ffffffff16565b90508373ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614610bd4576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610bcb90611d29565b60405180910390fd5b60019450505050509695505050505050565b600082610bf38584610c3e565b1490509392505050565b6000610c10610c0a610c94565b83610dae565b9050919050565b6000806000610c268585610de1565b91509150610c3381610e32565b819250505092915050565b60008082905060005b8451811015610c8957610c7482868381518110610c6757610c666118f3565b5b6020026020010151610f98565b91508080610c8190611c4f565b915050610c47565b508091505092915050565b60007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff163073ffffffffffffffffffffffffffffffffffffffff16148015610d1057507f000000000000000000000000000000000000000000000000000000000000000046145b15610d3d577f00000000000000000000000000000000000000000000000000000000000000009050610dab565b610da87f00000000000000000000000000000000000000000000000000000000000000007f00000000000000000000000000000000000000000000000000000000000000007f0000000000000000000000000000000000000000000000000000000000000000610fc3565b90505b90565b60008282604051602001610dc3929190611dc1565b60405160208183030381529060405280519060200120905092915050565b6000806041835103610e225760008060006020860151925060408601519150606086015160001a9050610e1687828585610ffd565b94509450505050610e2b565b60006002915091505b9250929050565b60006004811115610e4657610e45611df8565b5b816004811115610e5957610e58611df8565b5b0315610f955760016004811115610e7357610e72611df8565b5b816004811115610e8657610e85611df8565b5b03610ec6576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610ebd90611e73565b60405180910390fd5b60026004811115610eda57610ed9611df8565b5b816004811115610eed57610eec611df8565b5b03610f2d576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610f2490611edf565b60405180910390fd5b60036004811115610f4157610f40611df8565b5b816004811115610f5457610f53611df8565b5b03610f94576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610f8b90611f71565b60405180910390fd5b5b50565b6000818310610fb057610fab82846110df565b610fbb565b610fba83836110df565b5b905092915050565b60008383834630604051602001610fde959493929190611fa0565b6040516020818303038152906040528051906020012090509392505050565b6000807f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08360001c11156110385760006003915091506110d6565b60006001878787876040516000815260200160405260405161105d949392919061200f565b6020604051602081039080840390855afa15801561107f573d6000803e3d6000fd5b505050602060405103519050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16036110cd576000600192509250506110d6565b80600092509250505b94509492505050565b600082600052816020526040600020905092915050565b6000604051905090565b600080fd5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006111358261110a565b9050919050565b6111458161112a565b811461115057600080fd5b50565b6000813590506111628161113c565b92915050565b60006020828403121561117e5761117d611100565b5b600061118c84828501611153565b91505092915050565b6000819050919050565b6111a881611195565b82525050565b60006020820190506111c3600083018461119f565b92915050565b600080fd5b600080fd5b600080fd5b60008083601f8401126111ee576111ed6111c9565b5b8235905067ffffffffffffffff81111561120b5761120a6111ce565b5b602083019150836001820283011115611227576112266111d3565b5b9250929050565b6000806020838503121561124557611244611100565b5b600083013567ffffffffffffffff81111561126357611262611105565b5b61126f858286016111d8565b92509250509250929050565b600082825260208201905092915050565b82818337600083830152505050565b6000601f19601f8301169050919050565b60006112b8838561127b565b93506112c583858461128c565b6112ce8361129b565b840190509392505050565b600060408201905081810360008301526112f48186886112ac565b905081810360208301526113098184866112ac565b905095945050505050565b600080fd5b600061016082840312156113305761132f611314565b5b81905092915050565b6000819050919050565b61134c81611339565b811461135757600080fd5b50565b60008135905061136981611343565b92915050565b61137881611195565b811461138357600080fd5b50565b6000813590506113958161136f565b92915050565b6000806000606084860312156113b4576113b3611100565b5b600084013567ffffffffffffffff8111156113d2576113d1611105565b5b6113de86828701611319565b93505060206113ef8682870161135a565b925050604061140086828701611386565b9150509250925092565b60008115159050919050565b61141f8161140a565b82525050565b600060208201905061143a6000830184611416565b92915050565b600080fd5b600080fd5b6000808585111561145e5761145d611440565b5b8386111561146f5761146e611445565b5b6001850283019150848603905094509492505050565b600082905092915050565b600082821b905092915050565b60006114a98383611485565b826114b48135611339565b925060208210156114f4576114ef7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff83602003600802611490565b831692505b505092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061153682611195565b915061154183611195565b9250828201905080821115611559576115586114fc565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b600061159982611195565b91506115a483611195565b9250826115b4576115b361155f565b5b828204905092915050565b60006115ca82611195565b91506115d583611195565b92508282026115e381611195565b915082820484148315176115fa576115f96114fc565b5b5092915050565b600082825260208201905092915050565b7f696e76616c696420646174610000000000000000000000000000000000000000600082015250565b6000611648600c83611601565b915061165382611612565b602082019050919050565b600060208201905081810360008301526116778161163b565b9050919050565b7f696e76616c6964207369676e6174757265000000000000000000000000000000600082015250565b60006116b4601183611601565b91506116bf8261167e565b602082019050919050565b600060208201905081810360008301526116e3816116a7565b9050919050565b600080fd5b600080fd5b600080fd5b60008083356001602003843603038112611716576117156116ea565b5b80840192508235915067ffffffffffffffff821115611738576117376116ef565b5b602083019250600182023603831315611754576117536116f4565b5b509250929050565b600061176782611195565b915061177283611195565b925082820390508181111561178a576117896114fc565b5b92915050565b60007fffffffffffffffffffffffffffffffffffffffff00000000000000000000000082169050919050565b60006117c88383611485565b826117d38135611790565b925060148210156118135761180e7fffffffffffffffffffffffffffffffffffffffff00000000000000000000000083601403600802611490565b831692505b505092915050565b7f73657373696f6e206b6579207265766f6b656400000000000000000000000000600082015250565b6000611851601383611601565b915061185c8261181b565b602082019050919050565b6000602082019050818103600083015261188081611844565b9050919050565b7f6e6f6e6365206d69736d61746368000000000000000000000000000000000000600082015250565b60006118bd600e83611601565b91506118c882611887565b602082019050919050565b600060208201905081810360008301526118ec816118b0565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600081905092915050565b60006119398385611922565b935061194683858461128c565b82840190509392505050565b600061195f82848661192d565b91508190509392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6119a38261129b565b810181811067ffffffffffffffff821117156119c2576119c161196b565b5b80604052505050565b60006119d56110f6565b90506119e1828261199a565b919050565b600067ffffffffffffffff821115611a0157611a0061196b565b5b602082029050602081019050919050565b6000611a25611a20846119e6565b6119cb565b90508083825260208201905060208402830185811115611a4857611a476111d3565b5b835b81811015611a715780611a5d888261135a565b845260208401935050602081019050611a4a565b5050509392505050565b600082601f830112611a9057611a8f6111c9565b5b8135611aa0848260208601611a12565b91505092915050565b600060208284031215611abf57611abe611100565b5b600082013567ffffffffffffffff811115611add57611adc611105565b5b611ae984828501611a7b565b91505092915050565b7f696e76616c69642073657373696f6e206b657900000000000000000000000000600082015250565b6000611b28601383611601565b9150611b3382611af2565b602082019050919050565b60006020820190508181036000830152611b5781611b1b565b9050919050565b6000611b6b82848661192d565b91508190509392505050565b7f696e76616c6964206c656166206c656e67746800000000000000000000000000600082015250565b6000611bad601383611601565b9150611bb882611b77565b602082019050919050565b60006020820190508181036000830152611bdc81611ba0565b9050919050565b7f696e76616c696465206d65726b6c6520726f6f74000000000000000000000000600082015250565b6000611c19601483611601565b9150611c2482611be3565b602082019050919050565b60006020820190508181036000830152611c4881611c0c565b9050919050565b6000611c5a82611195565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203611c8c57611c8b6114fc565b5b600182019050919050565b611ca081611339565b82525050565b6000606082019050611cbb6000830186611c97565b611cc86020830185611c97565b611cd5604083018461119f565b949350505050565b7f6163636f756e743a20696e76616c6964207369676e6174757265000000000000600082015250565b6000611d13601a83611601565b9150611d1e82611cdd565b602082019050919050565b60006020820190508181036000830152611d4281611d06565b9050919050565b600081905092915050565b7f1901000000000000000000000000000000000000000000000000000000000000600082015250565b6000611d8a600283611d49565b9150611d9582611d54565b600282019050919050565b6000819050919050565b611dbb611db682611339565b611da0565b82525050565b6000611dcc82611d7d565b9150611dd88285611daa565b602082019150611de88284611daa565b6020820191508190509392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b7f45434453413a20696e76616c6964207369676e61747572650000000000000000600082015250565b6000611e5d601883611601565b9150611e6882611e27565b602082019050919050565b60006020820190508181036000830152611e8c81611e50565b9050919050565b7f45434453413a20696e76616c6964207369676e6174757265206c656e67746800600082015250565b6000611ec9601f83611601565b9150611ed482611e93565b602082019050919050565b60006020820190508181036000830152611ef881611ebc565b9050919050565b7f45434453413a20696e76616c6964207369676e6174757265202773272076616c60008201527f7565000000000000000000000000000000000000000000000000000000000000602082015250565b6000611f5b602283611601565b9150611f6682611eff565b604082019050919050565b60006020820190508181036000830152611f8a81611f4e565b9050919050565b611f9a8161112a565b82525050565b600060a082019050611fb56000830188611c97565b611fc26020830187611c97565b611fcf6040830186611c97565b611fdc606083018561119f565b611fe96080830184611f91565b9695505050505050565b600060ff82169050919050565b61200981611ff3565b82525050565b60006080820190506120246000830187611c97565b6120316020830186612000565b61203e6040830185611c97565b61204b6060830184611c97565b9594505050505056fea2646970667358221220f1caf336c937aacec0d5aa6003a96a3b485a288311e0590ac72a1d477a4e6cd864736f6c63430008120033";
    static readonly abi: readonly [{
        readonly inputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "constructor";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: true;
            readonly internalType: "address";
            readonly name: "key";
            readonly type: "address";
        }];
        readonly name: "SessionKeyRevoked";
        readonly type: "event";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "bytes";
            readonly name: "_packed";
            readonly type: "bytes";
        }];
        readonly name: "parseDataAndSignature";
        readonly outputs: readonly [{
            readonly internalType: "bytes";
            readonly name: "data";
            readonly type: "bytes";
        }, {
            readonly internalType: "bytes";
            readonly name: "signature";
            readonly type: "bytes";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "_key";
            readonly type: "address";
        }];
        readonly name: "revokeSessionKey";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "_key";
            readonly type: "address";
        }];
        readonly name: "revoked";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "_key";
            readonly type: "address";
        }];
        readonly name: "sessionNonce";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "address";
                readonly name: "sender";
                readonly type: "address";
            }, {
                readonly internalType: "uint256";
                readonly name: "nonce";
                readonly type: "uint256";
            }, {
                readonly internalType: "bytes";
                readonly name: "initCode";
                readonly type: "bytes";
            }, {
                readonly internalType: "bytes";
                readonly name: "callData";
                readonly type: "bytes";
            }, {
                readonly internalType: "uint256";
                readonly name: "callGasLimit";
                readonly type: "uint256";
            }, {
                readonly internalType: "uint256";
                readonly name: "verificationGasLimit";
                readonly type: "uint256";
            }, {
                readonly internalType: "uint256";
                readonly name: "preVerificationGas";
                readonly type: "uint256";
            }, {
                readonly internalType: "uint256";
                readonly name: "maxFeePerGas";
                readonly type: "uint256";
            }, {
                readonly internalType: "uint256";
                readonly name: "maxPriorityFeePerGas";
                readonly type: "uint256";
            }, {
                readonly internalType: "bytes";
                readonly name: "paymasterAndData";
                readonly type: "bytes";
            }, {
                readonly internalType: "bytes";
                readonly name: "signature";
                readonly type: "bytes";
            }];
            readonly internalType: "struct UserOperation";
            readonly name: "userOp";
            readonly type: "tuple";
        }, {
            readonly internalType: "bytes32";
            readonly name: "userOpHash";
            readonly type: "bytes32";
        }, {
            readonly internalType: "uint256";
            readonly name: "missingAccountFunds";
            readonly type: "uint256";
        }];
        readonly name: "validatePluginData";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "validated";
            readonly type: "bool";
        }];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }];
    static createInterface(): ZeroDevSessionKeyPluginInterface;
    static connect(address: string, signerOrProvider: Signer | Provider): ZeroDevSessionKeyPlugin;
}
export {};
