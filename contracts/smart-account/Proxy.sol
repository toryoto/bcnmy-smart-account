// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

/**
 * @title Proxy // This is the user's Smart Account
 * @notice Basic proxy that delegates all calls to a fixed implementation contract.
 * @dev    Implementation address is stored in the slot defined by the Proxy's address
 */
 // プロキシコントラクトは、実際のロジックを持つ実装コントラクトに全ての呼び出しをdelegateする役割を持つ
contract Proxy {
    // コンストラクタではプロキシが参照する実装コントラクトのアドレスを設定
    // 実装コントラクトは全てのウォレット作成を通して1回だけで良い
    constructor(address _implementation) {
        require(
            _implementation != address(0),
            "Invalid implementation address"
        );
        // プロキシのアドレスをキーとして実装コントラクトのアドレスを保存
        assembly {
            sstore(address(), _implementation)
        }
    }
    // 全ての呼び出しを実装コントラクトに転送する
    fallback() external payable {
        address target;
        assembly {
            target := sload(address())
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }
}
