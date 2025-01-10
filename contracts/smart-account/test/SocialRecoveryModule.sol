// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;
import "../SmartAccount.sol";
import {Enum} from "../common/Enum.sol";
import {IAuthorizationModule} from "../interfaces/IAuthorizationModule.sol";

// TODO: To be rebuilt for an ownerless setup => like which validation method does it recover?
// socail：信頼できる関係性を持つ複数のエンティティ

contract SocialRecoveryModule is IAuthorizationModule {
    struct Friends {
        address[] friends;
        uint256 threshold;
    }

    string public constant NAME = "Social Recovery Module";
    string public constant VERSION = "0.1.0";
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    // @review
    // すでに処理されたuserOpHashを管理 → リプレイ攻撃を防ぐ
    mapping(bytes32 => bool) public opsSeen;

    // @todo
    // Notice validateAndUpdateNonce in just skipped in case of modules. To avoid replay of same userOpHash I think it should be done.

    mapping(address => Friends) internal _friendsEntries;
    mapping(address => mapping(address => bool)) public isFriend;

    // isConfirmed - map of [recoveryHash][friend] to bool
    mapping(bytes32 => mapping(address => bool)) public isConfirmed;
    mapping(address => uint256) internal _walletsNonces;

    /**
     * @dev Setup function sets initial storage of contract.
     */
    // ウォレットの所有者が信頼できるアドレスリストとリカバリーの閾値を登録する
    function setup(
        address[] memory _friends,
        uint256 _threshold
    ) public returns (address) {
        require(
            _threshold <= _friends.length,
            "Threshold exceeds friends count"
        );
        require(_threshold >= 2, "At least 2 friends required"); // 閾値は2以上である必要がある
        Friends storage entry = _friendsEntries[msg.sender]; // msg.senderのFriends構造体（友人リストと閾値）を取得
        // Friendに登録するアドレスは重複できない
        for (uint256 i = 0; i < _friends.length; i++) {
            address friend = _friends[i];
            require(friend != address(0), "Invalid friend address provided");
            require(
                !isFriend[msg.sender][friend],
                "Duplicate friends provided"
            );
            isFriend[msg.sender][friend] = true;
        }
        // update friends list and threshold for smart account
        entry.friends = _friends;
        entry.threshold = _threshold;
        return address(this);
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external virtual returns (uint256) {
        (bytes memory moduleSignature, ) = abi.decode(
            userOp.signature,
            (bytes, address)
        );
        return _validateSignature(userOp, userOpHash, moduleSignature);
    }

    /**
     * @dev standard validateSignature for modules to validate and mark userOpHash as seen
     * @param userOp the operation that is about to be executed.
     * @param userOpHash hash of the user's request data. can be used as the basis for signature.
     * @return sigValidationResult sigAuthorizer to be passed back to trusting Account, aligns with validationData
     */
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        bytes memory moduleSignature
    ) internal virtual returns (uint256 sigValidationResult) {
        (userOp, moduleSignature);
        if (opsSeen[userOpHash] == true) return SIG_VALIDATION_FAILED;
        opsSeen[userOpHash] = true;
        // can perform it's own access control logic, verify agaisnt expected signer and return SIG_VALIDATION_FAILED
        return 0;
    }

    /**
     * @dev Confirm friend recovery transaction. Only by friends.
     */
    // 指定された回復者（Friend）が回復リクエストトランザクションを承認するメソッド
    function confirmTransaction(address _wallet, address _newOwner) public {
        require(onlyFriends(_wallet, msg.sender), "sender not a friend");
        bytes32 recoveryHash = getRecoveryHash(
            _wallet,
            _newOwner,
            _walletsNonces[_wallet]
        );
        isConfirmed[recoveryHash][msg.sender] = true;
    }

    // _wallet：リカバリー対象のアドレス
    // _newOwner：EOAアドレスなど新しい所有者のアドレス
    // コントラクト（スマートアカウント）で「トランザクション実行はownerのみ」といった制限あるからオンチェーンに保存されてるownerを変えるだけでウォレットのリカバリーになる
    function recoverAccess(address payable _wallet, address _newOwner) public {
        // require(onlyFriends(_wallet, msg.sender), "sender not a friend");
        bytes32 recoveryHash = getRecoveryHash(
            _wallet,
            _newOwner,
            _walletsNonces[_wallet]
        );
        // 十分な数の友達が回復を承認しているかどうか
        // 承認はconfirmTransactionで友人が行う
        require(
            isConfirmedByRequiredFriends(recoveryHash, _wallet),
            "Not enough confirmations"
        );
        // リカバリー対象のウォレットアドレスを使用してスマートアカウントのインスタンスを作成
        SmartAccount smartAccount = SmartAccount(payable(_wallet));
        require(
            // スマートアカウントコントラクトのexecTransactionFromModuleを飛び出す（スマートアカウントの代わりにトランザクションを実行できるようにするためのもの）
            smartAccount.execTransactionFromModule(
                _wallet,
                0,
                // abi.encodeCall("setOwner", (newOwner)),
                abi.encodeWithSignature("setOwner(address)", _newOwner), // SmartAccountコントラクトのsetOwner関数を呼び出すためのエンコードされたデータ
                Enum.Operation.Call // 実行する操作の種類
            ),
            "Could not execute recovery"
        );
        // _walletのナンスを更新
        _walletsNonces[_wallet]++;
    }

    function isConfirmedByRequiredFriends(
        bytes32 recoveryHash,
        address _wallet
    ) public view returns (bool) {
        uint256 confirmationCount;
        Friends storage entry = _friendsEntries[_wallet];
        for (uint256 i = 0; i < entry.friends.length; i++) {
            if (isConfirmed[recoveryHash][entry.friends[i]])
                confirmationCount++;
            if (confirmationCount == entry.threshold) return true;
        }
        return false;
    }

    function onlyFriends(
        address _wallet,
        address _friend
    ) public view returns (bool) {
        Friends storage entry = _friendsEntries[_wallet];
        for (uint256 i = 0; i < entry.friends.length; i++) {
            if (entry.friends[i] == _friend) return true;
        }
        return false;
    }

    /// @dev Returns hash of data encoding owner replacement.
    /// @return Data hash.
    function getRecoveryHash(
        address _wallet,
        address _newOwner,
        uint256 _nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(_wallet, _newOwner, _nonce));
    }
}
