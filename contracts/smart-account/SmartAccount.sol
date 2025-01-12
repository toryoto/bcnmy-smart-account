// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {BaseSmartAccount, IEntryPoint, UserOperation} from "./BaseSmartAccount.sol";
import {ModuleManager} from "./base/ModuleManager.sol";
import {FallbackManager} from "./base/FallbackManager.sol";
import {LibAddress} from "./libs/LibAddress.sol";
import {ISignatureValidator} from "./interfaces/ISignatureValidator.sol";
import {IERC165} from "./interfaces/IERC165.sol";
import {SmartAccountErrors} from "./common/Errors.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IAuthorizationModule} from "./interfaces/IAuthorizationModule.sol";

// SmartAccount - EIP-4337 compatible smart contract wallet.

// ERC4337トランザクション処理流れ
// ユーザ（スマートアカウントを含む）がUserOpを作成
// バンドラーがまとめてEntryPointに送信
// EntryPointがUserOperatioの検証を開始
// EntryPointがスマートアカウントのvalidateUserOpを呼び出し
// スマートアカウントが検証結果をEntryPointに返す
// EntryPointが検証結果に基づいて処理を続行

// スマートアカウントがModuleManagerを継承することでモジュール管理とその使用ができるようになる
// Solidityでは継承元のストレージ（_modulesなど）は継承先（SmartAccount）のストレージに統合される
contract SmartAccount is
    BaseSmartAccount,
    ModuleManager, 
    FallbackManager,
    IERC165,
    SmartAccountErrors,
    ISignatureValidator
{
    using ECDSA for bytes32;
    using LibAddress for address;

    // Storage Version
    string public constant VERSION = "2.0.0";

    // Owner storage. Deprecated. Left for storage layout compatibility
    address public ownerDeprecated;

    // changed to 2D nonce below
    // @notice there is no _nonce
    // Deprecated. Left for storage layout compatibility
    mapping(uint256 => uint256) public noncesDeprecated;

    // AA immutable storage
    IEntryPoint private immutable ENTRY_POINT;
    address private immutable SELF;

    // Events
    event ImplementationUpdated(
        address indexed oldImplementation,
        address indexed newImplementation
    );
    event SmartAccountReceivedNativeToken(
        address indexed sender,
        uint256 indexed value
    );

    constructor(IEntryPoint anEntryPoint) {
        SELF = address(this);
        if (address(anEntryPoint) == address(0))
            revert EntryPointCannotBeZero();
        // 引数として渡されたEntryPointを保存する
        ENTRY_POINT = anEntryPoint;
        // 継承元（ModuleManager.sol）の_modulesを初期化する
        _modules[SENTINEL_MODULES] = SENTINEL_MODULES;
    }

    /**
     * @dev This function is a special fallback function that is triggered when the contract receives Ether.
     * It logs an event indicating the amount of Ether received and the sender's address.
     * @notice This function is marked as external and payable, meaning it can be called from external
     * sources and accepts Ether as payment.
     */
    receive() external payable {
        if (address(this) == SELF) revert DelegateCallsOnly();
        emit SmartAccountReceivedNativeToken(msg.sender, msg.value);
    }

     // スマートアカウントを初期化するためのメソッド
     // 1度しか実行できないようにするべき
    function init(
        address handler,
        address moduleSetupContract,
        bytes calldata moduleSetupData
    ) external virtual override returns (address) {
        if (
            _modules[SENTINEL_MODULES] != address(0) ||
            getFallbackHandler() != address(0)
        ) revert AlreadyInitialized();
        _setFallbackHandler(handler);
        return _initialSetupModules(moduleSetupContract, moduleSetupData);
    }

    // コントラクト内で外部のコントラクトやアドレスに対してトランザクションを実行するためのインターフェイスメソッド
    function execute(
        address dest, // トランザクションの送信先アドレス
        uint256 value, // 送信するネイティブトークン量
        bytes calldata func // 実行するトランザクションのcalldata
    ) external {
        execute_ncC(dest, value, func);
    }

    // バッチトランザクションを実行するためのインターフェイスメソッド
    function executeBatch(
        address[] calldata dest,
        uint256[] calldata value,
        bytes[] calldata func
    ) external {
        executeBatch_y6U(dest, value, func);
    }

    // ERC4337のUserOperationを検証するためのロジックを実装
    // スマートアカウントがEntryPoint(EOA)の依頼を受けて行う検証処理
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual override returns (uint256 validationData) {
        // エントリーポイントからの呼び出しか確認
        // → ERC4337において、userOpの検証実行はentryPoint(EOA)からのみ呼び出される
        if (msg.sender != address(entryPoint()))
            revert CallerIsNotAnEntryPoint(msg.sender);

        // 署名をデコードして署名データと検証モジュールのアドレスを取得
        (, address validationModule) = abi.decode(
            userOp.signature,
            (bytes, address)
        );
        // 指定されたvalidationModuleが有効かどうかを確認
        if (address(_modules[validationModule]) != address(0)) {
            // 有効であればvalidationModuleのvalidateUserOp関数を呼び出す
            validationData = IAuthorizationModule(validationModule)
                .validateUserOp(userOp, userOpHash);
        } else {
            revert WrongValidationModule(validationModule);
        }
        // Check nonce requirement if any
        _payPrefund(missingAccountFunds);
    }

    // シンプルなモジュール追加に使う
    function enableModule(address module) external virtual override {
        _requireFromEntryPointOrSelf(); // entryPointまたは自分からの呼び出しであることを確認
        _enableModule(module); // 内部関数で指定されたモジュールを有効化
    }

    // モジュールが初期設定を必要する場合に使用（例：モジュールが特定のパラメータなどを必要とする）
    function setupAndEnableModule(
        address setupContract,
        bytes memory setupData
    ) external virtual override returns (address) {
        _requireFromEntryPointOrSelf();
        return _setupAndEnableModule(setupContract, setupData);
    }

    /**
     * @dev Sets the fallback handler.
     * @notice This can only be done via a UserOp sent by EntryPoint.
     * @param handler Handler to be set.
     */
    function setFallbackHandler(address handler) external virtual override {
        _requireFromEntryPointOrSelf();
        _setFallbackHandler(handler);
    }

    /**
     * @dev Returns the address of the implementation contract associated with this contract.
     * @notice The implementation address is stored in the contract's storage slot with index 0.
     */
    function getImplementation()
        external
        view
        returns (address _implementation)
    {
        assembly {
            _implementation := sload(address())
        }
    }

    /**
     * @notice Query if a contract implements an interface
     * @param _interfaceId The interface identifier, as specified in ERC165
     * @return `true` if the contract implements `_interfaceID`
     */
    function supportsInterface(
        bytes4 _interfaceId
    ) external view virtual override returns (bool) {
        return _interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
    }

    /**
     * @notice All the new implementations MUST have this method!
     * @notice Updates the implementation of the base wallet
     * @param _implementation New wallet implementation
     */
    function updateImplementation(address _implementation) public virtual {
        _requireFromEntryPointOrSelf();
        require(_implementation != address(0), "Address cannot be zero");
        if (!_implementation.isContract())
            revert InvalidImplementation(_implementation);
        address oldImplementation;

        assembly {
            oldImplementation := sload(address())
            sstore(address(), _implementation)
        }
        emit ImplementationUpdated(oldImplementation, _implementation);
    }

    /* solhint-disable func-name-mixedcase */

    // EntryPointからの呼び出しであることを確認して、実行（call）する
    function execute_ncC(
        address dest,
        uint256 value,
        bytes calldata func
    ) public {
        _requireFromEntryPoint();
        _call(dest, value, func);
    }

    /**
     * @dev Execute a sequence of transactions
     * @notice Name is optimized for this method to be cheaper to be called
     * @param dest Addresses of the contracts to call
     * @param value Amounts of native tokens to send along with the transactions
     * @param func Data of the transactions
     */
    function executeBatch_y6U(
        address[] calldata dest,
        uint256[] calldata value,
        bytes[] calldata func
    ) public {
        _requireFromEntryPoint();
        if (
            dest.length == 0 ||
            dest.length != value.length ||
            value.length != func.length
        ) revert WrongBatchProvided(dest.length, value.length, func.length, 0);
        for (uint256 i; i < dest.length; ) {
            _call(dest[i], value[i], func[i]);
            unchecked {
                ++i;
            }
        }
    }

    /* solhint-enable func-name-mixedcase */

    /**
     * @dev Deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * @dev Withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(
        address payable withdrawAddress,
        uint256 amount
    ) public payable {
        _requireFromEntryPointOrSelf();
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /**
     * @dev Removes a module from the allowlist.
     * @notice This can only be done via a wallet transaction.
     * @notice Disables the module `module` for the wallet.
     * @param prevModule Module that pointed to the module to be removed in the linked list
     * @param module Module to be removed.
     */
    function disableModule(address prevModule, address module) public virtual {
        _requireFromEntryPointOrSelf();
        _disableModule(prevModule, module);
    }

    /**
     * @dev Returns the current entry point used by this account.
     * @return EntryPoint as an `IEntryPoint` interface.
     * @dev This function should be implemented by the subclass to return the current entry point used by this account.
     */
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /**
     * @dev Check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * Implementation of ISignatureValidator (see `interfaces/ISignatureValidator.sol`)
     * @dev Forwards the validation to the module specified in the signature
     * @param dataHash 32 bytes hash of the data signed on the behalf of address(msg.sender)
     * @param signature Signature byte array associated with dataHash
     * @return bytes4 value.
     */
    function isValidSignature(
        bytes32 dataHash,
        bytes memory signature
    ) public view override returns (bytes4) {
        (bytes memory moduleSignature, address validationModule) = abi.decode(
            signature,
            (bytes, address)
        );
        if (address(_modules[validationModule]) != address(0)) {
            return
                ISignatureValidator(validationModule).isValidSignature(
                    dataHash,
                    moduleSignature
                );
        } else {
            revert WrongValidationModule(validationModule);
        }
    }

    // スマートコントラクトから外部のアドレスに対してトランザクションを実行するメソッド
    function _call(address target, uint256 value, bytes memory data) internal {
        // アセンブリを使用してトランザションの実行結果を真偽値で取得
        assembly {
            let success := call(
                gas(),
                target,
                value,
                add(data, 0x20),
                mload(data),
                0,
                0
            )
            let ptr := mload(0x40)
            returndatacopy(ptr, 0, returndatasize())
            // 失敗していたらエラーメッセージをrevert
            if iszero(success) {
                revert(ptr, returndatasize())
            }
        }
    }

    /**
     * @dev This function allows entry point or SA itself to execute certain actions.
     * If the caller is not authorized, the function will revert with an error message.
     * @notice This function acts as modifier and is marked as internal to be be called
     * within the contract itself only.
     */
    function _requireFromEntryPointOrSelf() internal view {
        if (msg.sender != address(entryPoint()) && msg.sender != address(this))
            revert CallerIsNotEntryPointOrSelf(msg.sender);
    }

    // 実行がEntryPointかを確認
    // ERC4337では、スマートコントラクトが直接外部から呼び出されることを想定していない（UserOp→EntryPoint→SmartAccount）
    // 常にEntryPoint（EOA）から内部のメソッドが呼び出される
    function _requireFromEntryPoint() internal view {
        if (msg.sender != address(entryPoint()))
            revert CallerIsNotEntryPoint(msg.sender);
    }
}
