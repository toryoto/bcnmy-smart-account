// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "../Proxy.sol";
import "../BaseSmartAccount.sol";
import {DefaultCallbackHandler} from "../handler/DefaultCallbackHandler.sol";
import {Stakeable} from "../common/Stakeable.sol";

 // ファクトリーコントラクトがユーザに変わってウォレットコントラクト（Proxy）をデプロイする
 // ファクトリーコントラクトのアドレスやナンスなどから一意のアドレスが生成される
 // ソーシャルログインではソーシャルアカウントの認証情報などから署名を生成して、ファクトリーコントラクトにウォレットの作成を依頼する
 // CREATE2を使用するとデプロイ時に入力値が同じであれば、出力値が必ず同じになる
 // よって、1度アカウントを作成（デプロイ）すると、その情報を使用して2回目以降でも異なるチェーンでも同じウォレットアドレスを使用できるようになる
 // （スマートコントラクトウォレットのウォレットアドレスは、そのスマートコントラクトのデプロイアドレスだから予測可能だと同じアカウント使える
contract SmartAccountFactory is Stakeable {
    // Proxyが参照するロジックコントラクトのアドレス（Smart Account.solのデプロイアドレス）
    // 全てのProxyはbasicImplementationを通じてスマートアカウントのロジックを実行する
    // 全てのProxyが同じbasicImplementationを参照するため、ロジックコードを一回だけデプロイすれば済む
    // 各Proxyは独自のストレージを持つため、独立したウォレットとして機能する
    address public immutable basicImplementation;
    DefaultCallbackHandler public immutable minimalHandler;

    event AccountCreation(
        address indexed account,
        address indexed initialAuthModule,
        uint256 indexed index
    );
    event AccountCreationWithoutIndex(
        address indexed account,
        address indexed initialAuthModule
    );

    constructor(
        address _basicImplementation,
        address _newOwner
    ) Stakeable(_newOwner) {
        require(
            _basicImplementation != address(0),
            "implementation cannot be zero"
        );
        basicImplementation = _basicImplementation;
        minimalHandler = new DefaultCallbackHandler();
    }

    // CREATE2によって生成されるアドレス（デプロイされたアドレス）を計算するメソッド
    // デプロイ前にアカウントのアドレスを取得できる
    // アドレス作成に必要なindexはソーシャルログインの場合、googleアカウントのuserIdなどが使える
    function getAddressForCounterFactualAccount(
        address moduleSetupContract,
        bytes calldata moduleSetupData,
        uint256 index
    ) external view returns (address _account) {
        // create initializer data based on init method, _owner and minimalHandler
        bytes memory initializer = _getInitializer(
            moduleSetupContract,
            moduleSetupData
        );
        bytes memory code = abi.encodePacked(
            type(Proxy).creationCode,
            uint256(uint160(basicImplementation))
        );
        bytes32 salt = keccak256(
            abi.encodePacked(keccak256(initializer), index)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(code))
        );
        _account = address(uint160(uint256(hash)));
    }

    // CREATE2 opcodeを使用して、事前に決定可能なアドレスにスマートアカウントをデプロイする
    // 戻り値：デプロイされたスマートアカウント（Proxyコントラクト）のアドレス
    function deployCounterFactualAccount(
        address moduleSetupContract, // モジュール管理のコントラクトアドレス（ModuleManager.sol）
        bytes calldata moduleSetupData, // moduleSetupContractに渡すcalldata
        uint256 index
    ) public returns (address proxy) {
        // スマートアカウントの初期化に必要なデータを生成
        bytes memory initializer = _getInitializer(
            moduleSetupContract,
            moduleSetupData
        );
        // CREATE2で使用するソルトを生成
        // 初期化データのハッシュとindexを連結してハッシュ化することで生成する
        // このindexによって同じ初期化データでも異なるアドレスを生成することが可能
        bytes32 salt = keccak256(
            abi.encodePacked(keccak256(initializer), index)
        );

        // デプロイに必要なデータを生成
        // Proxyコントラクトの作成コードとスマートアカウントの実装コードを含む
        bytes memory deploymentData = abi.encodePacked(
            type(Proxy).creationCode,
            uint256(uint160(basicImplementation))
        );

        // インラインアセンブリを使用してCREATE2 opcodeを呼び出してデプロイ
        assembly {
            proxy := create2(
                0x0,
                add(0x20, deploymentData),
                mload(deploymentData),
                salt
            )
        }
        require(address(proxy) != address(0), "Create2 call failed");

        address initialAuthorizationModule;

        if (initializer.length > 0) {
            assembly {
                let success := call(
                    gas(),
                    proxy,
                    0,
                    add(initializer, 0x20),
                    mload(initializer),
                    0,
                    0
                )
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                if iszero(success) {
                    revert(ptr, returndatasize())
                }
                initialAuthorizationModule := mload(ptr)
            }
        }
        // アカウント作成のイベント発行
        emit AccountCreation(proxy, initialAuthorizationModule, index);
    }

    /**
     * @notice Deploys account using create and points it to _implementation
     
     * @return proxy address of the deployed account
     */
    function deployAccount(
        address moduleSetupContract,
        bytes calldata moduleSetupData
    ) public returns (address proxy) {
        bytes memory deploymentData = abi.encodePacked(
            type(Proxy).creationCode,
            uint256(uint160(basicImplementation))
        );

        assembly {
            proxy := create(
                0x0,
                add(0x20, deploymentData),
                mload(deploymentData)
            )
        }
        require(address(proxy) != address(0), "Create call failed");

        bytes memory initializer = _getInitializer(
            moduleSetupContract,
            moduleSetupData
        );
        address initialAuthorizationModule;

        if (initializer.length > 0) {
            assembly {
                let success := call(
                    gas(),
                    proxy,
                    0,
                    add(initializer, 0x20),
                    mload(initializer),
                    0,
                    0
                )
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                if iszero(success) {
                    revert(ptr, returndatasize())
                }
                initialAuthorizationModule := mload(ptr)
            }
        }
        emit AccountCreationWithoutIndex(proxy, initialAuthorizationModule);
    }

    /**
     * @dev Allows to retrieve the creation code used for the Proxy deployment.
     * @return The creation code for the Proxy.
     */
    function accountCreationCode() public pure returns (bytes memory) {
        return type(Proxy).creationCode;
    }

    /**
     * @dev Allows to retrieve the initializer data for the account.
     * @param moduleSetupContract Initializes the auth module; can be a factory or registry for multiple accounts.
     * @param moduleSetupData modules setup data (a standard calldata for the module setup contract)
     * @return initializer bytes for init method
     */
    function _getInitializer(
        address moduleSetupContract,
        bytes calldata moduleSetupData
    ) internal view returns (bytes memory) {
        return
            abi.encodeCall(
                BaseSmartAccount.init,
                (address(minimalHandler), moduleSetupContract, moduleSetupData)
            );
    }
}
