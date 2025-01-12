// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.17;

// IAccountは、アカウント抽象化におけるスマートコントラクトウォレットが満たすべき最低限の機能
// これを継承してvalidateUserOpやentryPointを実装していればERC4337のSCAにできる
import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperationLib, UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {BaseSmartAccountErrors} from "./common/Errors.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
 
// IAccountを実装したスマートコントラクトアカウントの基本的な機能を提供する基底クラス
// validationUserOpやentryPointといった重要な関数を抽象定義している（実装はSmartAccount.sol）
// abstractとして定義されているので、直接デプロイされることはなく、他のコントラクト(SmartAccount.sol)が継承してデプロイする
abstract contract BaseSmartAccount is IAccount, BaseSmartAccountErrors {
    using UserOperationLib for UserOperation;

    // Return value in case of signature failure, with no time-range.
    // equivalent to _packValidationData(true,0,0);
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    function init(
        address handler,
        address moduleSetupContract,
        bytes calldata moduleSetupData
    ) external virtual returns (address);

    // UserOperationに含まれる署名（userOp.signature）が正しいかどうかを検証する
    // 署名が無効であれば、トランザクションを拒否する
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual override returns (uint256);

    // アカウントの次に使用されるべきnonceを取得するためのメソッド
    function nonce(uint192 _key) public view virtual returns (uint256) {
        // entryPointコントラクトのgetNouneを呼び出す
        // getNoune関数は、指定されたアドレスとキーに対応する次のナンスを返す
        return entryPoint().getNonce(address(this), _key);
    }

    // このコントラクトで使用されるEntryPointを返す
    function entryPoint() public view virtual returns (IEntryPoint);

    /**
     * sends to the entrypoint (msg.sender) the missing funds for this transaction.
     * subclass MAY override this method for better funds management
     * (e.g. send to the entryPoint more than the minimum required, so that in future transactions
     * it will not be required to send again)
     * @param missingAccountFunds the minimum value this method should send the entrypoint.
     *  this value MAY be zero, in case there is enough deposit, or the userOp has a paymaster.
     */
    function _payPrefund(uint256 missingAccountFunds) internal virtual {
        if (missingAccountFunds != 0) {
            payable(msg.sender).call{
                value: missingAccountFunds,
                gas: type(uint256).max
            }("");
            //ignore failure (its EntryPoint's job to verify, not account.)
        }
    }
}
