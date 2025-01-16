// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.17;

import {SelfAuthorized} from "../common/SelfAuthorized.sol";
import {Executor, Enum} from "./Executor.sol";
import {ModuleManagerErrors} from "../common/Errors.sol";

// スマートアカウントに機能を追加するためのモジュール（リカバリーモジュールなど他のコントラクト）の追加、削除、および実行を管理
// モジュールはリンクリストで管理
// 根底の仕組みは execTransactionFromModuleがモジュール内のメソッドを実行することにあり、その結果として、元のスマートアカウントがそのモジュールのメソッドを実行しているように見える
// abstractとして定義されているので、直接デプロイされることはなく、他のコントラクト(SmartAccount.sol)が継承してデプロイする
abstract contract ModuleManager is
    SelfAuthorized,
    Executor,
    ModuleManagerErrors
{
    // リンクリストの終端を表すアドレス
    address internal constant SENTINEL_MODULES = address(0x1);
    // モジュールはリンクリストとして管理されており、_modulesマッピングで管理されている
    // キー：現在のモジュールアドレス、値：次のモジュールアドレス
    mapping(address => address) internal _modules;
    uint256[24] private __gap;

    // Events
    event EnabledModule(address module);
    event DisabledModule(address module);
    event ExecutionFromModuleSuccess(address indexed module);
    event ExecutionFromModuleFailure(address indexed module);
    event ModuleTransaction(
        address module,
        address to,
        uint256 value,
        bytes data,
        Enum.Operation operation
    );

    /**
     * @dev Adds a module to the allowlist.
     * @notice This SHOULD only be done via userOp or a selfcall.
     */
    function enableModule(address module) external virtual;

    /**
     * @dev Setups module for this Smart Account and enables it.
     * @notice This SHOULD only be done via userOp or a selfcall.
     */
    function setupAndEnableModule(
        address setupContract,
        bytes memory setupData
    ) external virtual returns (address);

    /**
     * @dev Returns array of modules. Useful for a widget
     * @param start Start of the page.
     * @param pageSize Maximum number of modules that should be returned.
     * @return array Array of modules.
     * @return next Start of the next page.
     */
    function getModulesPaginated(
        address start,
        uint256 pageSize
    ) external view returns (address[] memory array, address next) {
        // Init array with max page size
        array = new address[](pageSize);

        // Populate return array
        uint256 moduleCount;
        address currentModule = _modules[start];
        while (
            currentModule != address(0x0) &&
            currentModule != SENTINEL_MODULES &&
            moduleCount < pageSize
        ) {
            array[moduleCount] = currentModule;
            currentModule = _modules[currentModule];
            moduleCount++;
        }
        next = currentModule;
        // Set correct size of returned array

        assembly {
            mstore(array, moduleCount)
        }
    }

    // 有効化されたモジュール（リンクリストに含まれるモジュール）がスマートアカウントの代わりにトランザクションを実行するメソッド
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 txGas
    ) public virtual returns (bool success) {
        // 有効化されたモジュールのみが実行可能
        if (
            msg.sender == SENTINEL_MODULES || _modules[msg.sender] == address(0)
        ) revert ModuleNotEnabled(msg.sender);
        // モジュールが有効化されていれば、スマートアカウントの所有者の介入なしにトランザクションを実行可能
        // _executeの戻り値（成功可否）がそのまま返される
        // _executeには送信者アドレスやABIに基づいたコントラクトのメソッドを呼び出すためのエンコード済みのデータなど、トランザクション実行に必要なものが渡される
        success = _execute(
            to,
            value,
            data,
            operation,
            txGas == 0 ? gasleft() : txGas
        );
    }

    // 1つ目のexecTransactionFromModuleをオーバーロードして使用する
    // これにより、同じ機能を異なる使い方で提供できる
    // 1つ目：ガス代を細かく制御、2つ目：デフォルトのガス代で呼び出す
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) public virtual returns (bool) {
        return execTransactionFromModule(to, value, data, operation, 0);
    }

    /**
     * @dev Allows a Module to execute a wallet transaction without any further confirmations and returns data
     * @param to Destination address of module transaction.
     * @param value Ether value of module transaction.
     * @param data Data payload of module transaction.
     * @param operation Operation type of module transaction.
     */
    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) public returns (bool success, bytes memory returnData) {
        success = execTransactionFromModule(to, value, data, operation);

        assembly {
            // Load free memory location
            let ptr := mload(0x40)
            // We allocate memory for the return data by setting the free memory location to
            // current free memory location + data size + 32 bytes for data size value
            mstore(0x40, add(ptr, add(returndatasize(), 0x20)))
            // Store the size
            mstore(ptr, returndatasize())
            // Store the data
            returndatacopy(add(ptr, 0x20), 0, returndatasize())
            // Point the return data to the correct memory location
            returnData := ptr
        }
    }

    // モジュールがバッチトランザクションを実行するメソッド
    // ループで1つずつ実行
    function execBatchTransactionFromModule(
        address[] calldata to,
        uint256[] calldata value,
        bytes[] calldata data,
        Enum.Operation[] calldata operations
    ) public virtual returns (bool success) {
        if (
            to.length == 0 ||
            to.length != value.length ||
            value.length != data.length ||
            data.length != operations.length
        )
            revert WrongBatchProvided(
                to.length,
                value.length,
                data.length,
                operations.length
            );

        // Only whitelisted modules are allowed.
        if (
            msg.sender == SENTINEL_MODULES || _modules[msg.sender] == address(0)
        ) revert ModuleNotEnabled(msg.sender);

        for (uint256 i; i < to.length; ) {
            // Execute transaction without further confirmations.
            success = _executeFromModule(
                to[i],
                value[i],
                data[i],
                operations[i]
            );
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Returns if a module is enabled
     * @return True if the module is enabled
     */
    function isModuleEnabled(address module) public view returns (bool) {
        return SENTINEL_MODULES != module && _modules[module] != address(0);
    }

    // モジュールを許可リストに追加する内部関数
    function _enableModule(address module) internal virtual {
        // モジュールアドレスが0またはSENTINEL_MODULES出ないことを確認
        if (module == address(0) || module == SENTINEL_MODULES)
            revert ModuleCannotBeZeroOrSentinel(module);
        // 指定されたモジュールがすでに有効化されていないことを確認
        if (_modules[module] != address(0)) revert ModuleAlreadyEnabled(module);

        _modules[module] = _modules[SENTINEL_MODULES];
        _modules[SENTINEL_MODULES] = module; //リンクリストの終点が新しいモジュールを指すように更新

        emit EnabledModule(module);
    }

    /**
     * @dev Setups module for this Smart Account and enables it.
     * @notice This can only be done via userOp or a selfcall.
     */
    function _setupAndEnableModule(
        address setupContract,
        bytes memory setupData
    ) internal virtual returns (address) {
        address module = _setupModule(setupContract, setupData);
        _enableModule(module);
        return module;
    }

    function _disableModule(
        address prevModule, // 削除対象の直前のモジュール
        address module // 削除対処のモジュール
    ) internal virtual {
        // モジュールアドレスの検証
        if (module == address(0) || module == SENTINEL_MODULES)
            revert ModuleCannotBeZeroOrSentinel(module);
        if (_modules[prevModule] != module)
            revert ModuleAndPrevModuleMismatch(
                module,
                _modules[prevModule],
                prevModule
            );
        // prevModuleの次のモジュールを、削除対象のmoduleの次のモジュールに更新する
        // これにより、moduleがリンクリストから切り離される
        _modules[prevModule] = _modules[module];
        // _modules マッピングから、削除対象の module のエントリを削除
        delete _modules[module];
        emit DisabledModule(module);
    }

    // TODO: can use not executor.execute, but SmartAccount._call for the unification

    // バッチトランザクション内で各々のトランザクションを実行するための内部関数
    // execTransactionFromModuleとやっていることは同じだが、内部関数のため有効性チェックは不要
    function _executeFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) internal returns (bool success) {
        success = _execute(to, value, data, operation, gasleft());
        if (success) {
            emit ModuleTransaction(msg.sender, to, value, data, operation);
            emit ExecutionFromModuleSuccess(msg.sender);
        } else emit ExecutionFromModuleFailure(msg.sender);
    }

    /**
     * @notice Setup function sets the initial storage of the contract.
     * @param setupContract initializing the auth module; can be a module factory or a registry for multiple accounts.
     * @param setupData modules setup data (a standard calldata for the module setup contract)
     */
    function _initialSetupModules(
        address setupContract,
        bytes memory setupData
    ) internal virtual returns (address) {
        address initialAuthorizationModule = _setupModule(
            setupContract,
            setupData
        );

        // Module address cannot be null or sentinel.
        if (
            initialAuthorizationModule == address(0) ||
            initialAuthorizationModule == SENTINEL_MODULES
        ) revert ModuleCannotBeZeroOrSentinel(initialAuthorizationModule);

        _modules[initialAuthorizationModule] = SENTINEL_MODULES;
        _modules[SENTINEL_MODULES] = initialAuthorizationModule;
        return initialAuthorizationModule;
    }

    function _setupModule(
        address setupContract,
        bytes memory setupData
    ) internal returns (address module) {
        if (setupContract == address(0)) revert("Wrong Module Setup Address");
        assembly {
            let success := call(
                gas(),
                setupContract,
                0,
                add(setupData, 0x20),
                mload(setupData),
                0,
                0
            )
            let ptr := mload(0x40)
            returndatacopy(ptr, 0, returndatasize())
            if iszero(success) {
                revert(ptr, returndatasize())
            }
            module := mload(ptr)
        }
    }
}
