// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * VULNERABLE VAULT CONTRACT - FOR TESTING ONLY
 * Contains multiple intentional vulnerabilities for demonstration
 * DO NOT USE IN PRODUCTION
 */

contract VulnerableVault {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    uint256 public totalShares;

    address public owner;
    bool private locked;

    event Deposit(address indexed user, uint256 amount, uint256 shares);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /**
     * VULNERABILITY 1: First Depositor Inflation Attack (ERC-4626)
     * Attacker can manipulate share price on first deposit
     */
    function deposit(uint256 amount) public {
        require(amount > 0, "Amount must be positive");

        uint256 shares;
        if (totalShares == 0) {
            // VULNERABLE: First deposit gets 1:1 ratio
            // Attacker can deposit 1 wei, then donate large amount
            shares = amount;
        } else {
            // Share price can be manipulated via donation
            shares = (amount * totalShares) / totalSupply;
        }

        balances[msg.sender] += amount;
        totalSupply += amount;
        totalShares += shares;

        emit Deposit(msg.sender, amount, shares);
    }

    /**
     * VULNERABILITY 2: Reentrancy - State Update After External Call
     * Classic reentrancy vulnerability
     */
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABLE: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call - reentrancy possible
        balances[msg.sender] -= amount;
        totalSupply -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * VULNERABILITY 3: Missing Slippage Protection
     * Vulnerable to sandwich attacks
     */
    function swap(uint256 amountIn) public {
        // VULNERABLE: No minAmountOut parameter
        // No deadline parameter
        // Vulnerable to MEV sandwich attacks

        uint256 amountOut = calculateSwapOutput(amountIn);

        // Perform swap without slippage check
        _executeSwap(amountIn, amountOut);
    }

    /**
     * VULNERABILITY 4: Oracle Price Manipulation
     * Uses spot price without TWAP or validation
     */
    function getPrice() public view returns (uint256) {
        // VULNERABLE: Using spot price from single source
        // Can be manipulated with flash loans
        // No staleness check, no TWAP

        return _getSpotPrice();
    }

    /**
     * VULNERABILITY 5: Integer Overflow (in older Solidity)
     * Unchecked arithmetic
     */
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        unchecked {
            // VULNERABLE: Overflow possible without checks
            return a + b;
        }
    }

    /**
     * VULNERABILITY 6: Access Control Issues
     * Missing onlyOwner modifier
     */
    function emergencyWithdraw() public {
        // VULNERABLE: No access control!
        // Anyone can call this function

        payable(msg.sender).transfer(address(this).balance);
    }

    /**
     * VULNERABILITY 7: Donation Attack
     * Uses balanceOf for calculations
     */
    function getSharePrice() public view returns (uint256) {
        // VULNERABLE: Uses actual balance instead of internal accounting
        // Attacker can donate tokens to manipulate share price

        uint256 actualBalance = address(this).balance;
        return (actualBalance * 1e18) / totalShares;
    }

    /**
     * VULNERABILITY 8: Unchecked External Call
     * Return value not checked
     */
    function unsafeTransfer(address to, uint256 amount) public {
        // VULNERABLE: Return value not checked
        // Silent failure possible

        to.call{value: amount}("");
        // No check if call succeeded
    }

    /**
     * VULNERABILITY 9: Block Timestamp Manipulation
     * Uses block.timestamp for critical logic
     */
    function timeLock(uint256 unlockTime) public view returns (bool) {
        // VULNERABLE: Miners can manipulate timestamp ~15 seconds
        // Short time windows are especially vulnerable

        return block.timestamp > unlockTime + 5 minutes;
    }

    /**
     * VULNERABILITY 10: Cross-Function Reentrancy
     * State can be inconsistent across functions
     */
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABLE: External call in middle of state transition
        // Another function could be called during callback
        if (to.code.length > 0) {
            (bool success, ) = to.call("");
            require(success);
        }

        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    /**
     * VULNERABILITY 11: Unbounded Loop (Gas Griefing)
     * Array can grow unbounded
     */
    address[] public users;

    function distributeRewards() public {
        // VULNERABLE: Loop over unbounded array
        // Attacker can add many addresses to cause out-of-gas

        for (uint i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether);
        }
    }

    /**
     * VULNERABILITY 12: Delegatecall to User-Controlled Address
     * Complete contract takeover possible
     */
    function delegateCall(address target, bytes memory data) public {
        // VULNERABLE: Delegatecall to user-controlled address
        // Attacker can execute arbitrary code in this contract's context

        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // Helper functions
    function calculateSwapOutput(uint256 amountIn) internal pure returns (uint256) {
        // Simplified swap calculation
        return amountIn * 99 / 100; // 1% fee
    }

    function _executeSwap(uint256 amountIn, uint256 amountOut) internal {
        // Swap execution logic
    }

    function _getSpotPrice() internal view returns (uint256) {
        // Simplified spot price
        return 1000 * 1e18;
    }

    receive() external payable {}
}
