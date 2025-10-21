// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Malicious Token Library for Fuzzing
 * These tokens simulate real-world attack vectors and edge cases
 */

// ============================================================================
// 1. REENTRANCY TOKEN - Calls back on transfer
// ============================================================================
contract ReentrantToken {
    mapping(address => uint256) public balances;
    address public target;
    bytes public callData;
    bool public attacking;

    function setTarget(address _target, bytes memory _callData) external {
        target = _target;
        callData = _callData;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount;

        // Reentrancy attack on transfer
        if (target != address(0) && !attacking) {
            attacking = true;
            (bool success,) = target.call(callData);
            attacking = false;
        }

        return true;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

// ============================================================================
// 2. FEE-ON-TRANSFER TOKEN - Takes fee on every transfer
// ============================================================================
contract FeeOnTransferToken {
    mapping(address => uint256) public balances;
    uint256 public feePercent = 10; // 10% fee
    address public feeCollector;

    constructor() {
        feeCollector = msg.sender;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        uint256 fee = (amount * feePercent) / 100;
        uint256 amountAfterFee = amount - fee;

        balances[msg.sender] -= amount;
        balances[to] += amountAfterFee;
        balances[feeCollector] += fee;

        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balances[from] >= amount, "Insufficient balance");

        uint256 fee = (amount * feePercent) / 100;
        uint256 amountAfterFee = amount - fee;

        balances[from] -= amount;
        balances[to] += amountAfterFee;
        balances[feeCollector] += fee;

        return true;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

// ============================================================================
// 3. APPROVAL-ATTACK TOKEN - Steals on approve
// ============================================================================
contract ApprovalAttackToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    address public attacker;

    function setAttacker(address _attacker) external {
        attacker = _attacker;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;

        // Attack: drain all tokens when approve is called
        if (attacker != address(0) && balances[msg.sender] > 0) {
            uint256 stolenAmount = balances[msg.sender];
            balances[msg.sender] = 0;
            balances[attacker] += stolenAmount;
        }

        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

// ============================================================================
// 4. RETURN-FALSE TOKEN - Returns false instead of reverting
// ============================================================================
contract ReturnFalseToken {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external returns (bool) {
        if (balances[msg.sender] < amount) {
            return false; // Returns false instead of reverting
        }

        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (balances[from] < amount) {
            return false;
        }

        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

// ============================================================================
// 5. NO-REVERT TOKEN - Silently fails without return value
// ============================================================================
contract NoRevertToken {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // Silently fails - no return, no revert
        if (balances[msg.sender] >= amount) {
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

// ============================================================================
// 6. UPGRADE-ATTACK TOKEN - Changes behavior mid-execution
// ============================================================================
contract UpgradeAttackToken {
    mapping(address => uint256) public balances;
    bool public evil = false;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function toggleEvil() external {
        require(msg.sender == owner, "Not owner");
        evil = !evil;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (evil) {
            // Evil mode: reverse the transfer
            balances[msg.sender] += amount;
            balances[to] -= amount;
        } else {
            // Normal mode
            require(balances[msg.sender] >= amount, "Insufficient balance");
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
        return true;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

// ============================================================================
// 7. PAUSABLE-ATTACK TOKEN - Can freeze mid-transaction
// ============================================================================
contract PausableAttackToken {
    mapping(address => uint256) public balances;
    bool public paused = false;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function pause() external {
        require(msg.sender == owner, "Not owner");
        paused = true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(!paused, "Paused");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;

        // Attack: pause in the middle of transfer
        if (amount > 1000 ether) {
            paused = true;
        }

        balances[to] += amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

// ============================================================================
// 8. DEFLATION TOKEN - Balance decreases over time
// ============================================================================
contract DeflationToken {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastUpdate;
    uint256 public deflationRate = 1; // 1% per block

    function transfer(address to, uint256 amount) external returns (bool) {
        _applyDeflation(msg.sender);
        _applyDeflation(to);

        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;

        return true;
    }

    function _applyDeflation(address account) internal {
        if (lastUpdate[account] > 0 && balances[account] > 0) {
            uint256 blocksPassed = block.number - lastUpdate[account];
            uint256 deflation = (balances[account] * deflationRate * blocksPassed) / 10000;
            if (deflation < balances[account]) {
                balances[account] -= deflation;
            }
        }
        lastUpdate[account] = block.number;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        lastUpdate[to] = block.number;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

// ============================================================================
// 9. BLACKLIST TOKEN - Can block addresses
// ============================================================================
contract BlacklistToken {
    mapping(address => uint256) public balances;
    mapping(address => bool) public blacklisted;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function blacklist(address account) external {
        require(msg.sender == owner, "Not owner");
        blacklisted[account] = true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(!blacklisted[msg.sender], "Sender blacklisted");
        require(!blacklisted[to], "Recipient blacklisted");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount;

        return true;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

// ============================================================================
// 10. HOOKS-EVERYWHERE TOKEN - Calls hooks on every operation
// ============================================================================
contract HooksEverywhereToken {
    mapping(address => uint256) public balances;

    event BeforeTransfer(address from, address to, uint256 amount);
    event AfterTransfer(address from, address to, uint256 amount);

    function transfer(address to, uint256 amount) external returns (bool) {
        _beforeTransferHook(msg.sender, to, amount);

        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;

        _afterTransferHook(msg.sender, to, amount);

        return true;
    }

    function _beforeTransferHook(address from, address to, uint256 amount) internal {
        emit BeforeTransfer(from, to, amount);
        // Could call external contracts here
        if (from.code.length > 0) {
            // Potential reentrancy point
            (bool success,) = from.call(abi.encodeWithSignature("beforeTransfer(address,uint256)", to, amount));
        }
    }

    function _afterTransferHook(address from, address to, uint256 amount) internal {
        emit AfterTransfer(from, to, amount);
        if (to.code.length > 0) {
            // Another reentrancy point
            (bool success,) = to.call(abi.encodeWithSignature("afterTransfer(address,uint256)", from, amount));
        }
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}
