// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

// プロキシコントラクトは、実際のロジックを持つ実装コントラクトに全ての呼び出しをdelegateする役割を持つ
// 実装コントラクトはProxyアドレスのストレージスロットに持つ
// 現在のコードでは実装コントラクトを変更できる機能を持たない
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
            // コントラクトアドレスをキーとして、ストレージスロットに保存されている値を取得する（実装コントラクトのアドレス）
            target := sload(address())
            calldatacopy(0, 0, calldatasize())
            // target（実装コントラクトのアドレス）に対してdelegatecallを行う
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
