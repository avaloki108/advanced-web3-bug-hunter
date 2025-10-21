// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableDeFiProtocol {
    // Existing state
    mapping(address => uint256) public balances;
    mapping(address => bool) public isAuthorized;
    address public owner;
    bool private locked;
    uint256 public totalSupply;
    address public priceOracle;

    // New for bridge-like flaws
    mapping(uint256 => bool) public processedMessages;  // Uninitialized - defaults to false, but vuln if assume true
    mapping(bytes32 => bool) public confirmations;  // Uninitialized mapping for bridge confirmations (Nomad-like)
    uint256 public currentNonce;  // Nonce for messages, but no strict check
    address public bridgeGuardian;  // Guardian for bridge ops, but not used properly

    // New for governance
    mapping(address => uint256) public votingPower;  // Flash loan manipulable
    uint256 public totalVotingPower;
    mapping(uint256 => Proposal) public proposals;  // Simple proposals
    uint256 public proposalCount;
    uint256 public quorumThreshold = 100;  // Low for exploit
    uint256 public timelockDelay = 0;  // No delay - vuln

    struct Proposal {
        address proposer;
        uint256 votesFor;
        uint256 votesAgainst;
        bool executed;
        string description;
    }

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event MessageProcessed(uint256 indexed nonce, bytes32 messageHash, bool success);  // Bridge event
    event ProposalCreated(uint256 indexed id, string description);
    event Voted(uint256 indexed proposalId, address voter, uint256 votes);
    event ProposalExecuted(uint256 indexed id);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
        isAuthorized[msg.sender] = true;
        bridgeGuardian = msg.sender;  // Set but not enforced
        votingPower[msg.sender] = 1000;  // Initial voting power
        totalVotingPower = 1000;
    }

    // Existing vulnerable withdraw (reentrancy)
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call first (potential reentrancy)
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call - VULNERABLE to reentrancy!
        balances[msg.sender] -= amount;
        totalSupply -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    // Existing access bypass
    function emergencyWithdraw() external {
        // Missing proper access control - anyone can call! VULNERABLE
        uint256 balance = balances[msg.sender];
        balances[msg.sender] = 0;
        totalSupply -= balance;

        (bool success,) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, balance);
    }

    // Existing complex transfer with potential overflow
    function complexTransfer(address to, uint256 amount, uint256 fee) external {
        require(balances[msg.sender] >= amount + fee, "Insufficient balance");

        // Potential overflow in fee calculation if amount + fee > max
        uint256 totalDeduction = amount + fee;

        balances[msg.sender] -= totalDeduction;
        balances[to] += amount;

        // Fee goes to owner - but what if owner is compromised via governance?
        balances[owner] += fee;

        emit Transfer(msg.sender, to, amount);
    }

    // Existing oracle issue
    function adjustBalanceBasedOnPrice(address user, uint256 multiplier) external onlyOwner {
        // External oracle call - potential manipulation via flash loan or stale price
        uint256 price = getPriceFromOracle();
        uint256 adjustment = price * multiplier / 100;  // Vuln if price manipulated high

        balances[user] += adjustment;
        totalSupply += adjustment;  // Unbacked if oracle wrong
    }

    function getPriceFromOracle() internal returns (uint256) {
        // Simplified oracle call - no staleness check, no bounds
        (bool success, bytes memory data) = priceOracle.call(abi.encodeWithSignature("getPrice()"));
        require(success, "Oracle call failed");
        return abi.decode(data, (uint256));
    }

    // Existing governance-like, but enhance with full vuln
    function updateAuthorization(address user, bool status) external {
        // No timelock, no quorum - flash loan can change during vote
        isAuthorized[user] = status;
    }

    // Existing deposit
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    // NEW: Bridge-like processMessage with uninitialized mapping and validation gaps
    function processMessage(uint256 nonce, bytes32 messageHash, uint256 amount, address token) external {
        // Gap 1: No sender authorization check - anyone can process
        // Gap 2: Nonce check weak - currentNonce not strictly enforced
        require(nonce >= currentNonce, "Invalid nonce");  // Allows future nonces, out-of-order possible
        currentNonce = nonce;  // Update after, but no prevention of skips

        // Vuln: Uninitialized confirmations mapping - defaults to false, but if assume confirmed, exploit
        // Nomad-like: if confirmations[messageHash] defaults false, but code assumes true if not set
        if (confirmations[messageHash]) {  // Defaults false, but vuln if code path assumes default safe
            // But to make vuln, add path that uses default
            balances[msg.sender] += amount;  // Mint without lock if "confirmed" (default false, but test bypass)
            totalSupply += amount;  // Unbacked mint VULNERABLE
        } else {
            // Gap: No revert, just skip - but attacker can call with unconfirmed to probe
            // Real vuln: If guardian not checked, and uninitialized guardian allows
            require(msg.sender == bridgeGuardian, "Not guardian");  // Enforced, but set to attacker via governance
        }

        processedMessages[nonce] = true;  // But if nonce skipped, gap
        emit MessageProcessed(nonce, messageHash, true);
    }

    // Bridge withdraw simulation with validation gap
    function bridgeWithdraw(uint256 nonce, uint256 amount) external {
        // Gap: No check if message processed on source chain
        // Uninitialized processedMessages[nonce] defaults false, but code doesn't require true
        // Vuln: Anyone can withdraw without corresponding deposit/lock
        balances[msg.sender] -= amount;  // Could underflow if not deposited
        totalSupply -= amount;

        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // No confirmation update - allows multiple withdraw if nonce not checked properly
        emit Withdrawal(msg.sender, amount);
    }

    // NEW: Governance proposal creation (simple, vuln to spam)
    function createProposal(string memory description) external {
        proposalCount++;
        proposals[proposalCount] = Proposal({
            proposer: msg.sender,
            votesFor: 0,
            votesAgainst: 0,
            executed: false,
            description: description
        });
        emit ProposalCreated(proposalCount, description);
    }

    // NEW: Vote function vulnerable to flash loan (votingPower manipulable)
    function vote(uint256 proposalId, bool support) external {
        uint256 votes = votingPower[msg.sender];  // Flash loan can borrow tokens to inflate
        Proposal storage prop = proposals[proposalId];
        require(!prop.executed, "Already executed");
        require(block.timestamp < prop.votesFor + timelockDelay, "Voting closed");  // No real close

        if (support) {
            prop.votesFor += votes;  // No double-vote prevention
        } else {
            prop.votesAgainst += votes;
        }
        emit Voted(proposalId, msg.sender, votes);
    }

    // NEW: Execute proposal without quorum or timelock check - VULNERABLE
    function executeProposal(uint256 proposalId) external {
        Proposal storage prop = proposals[proposalId];
        // Gap: No quorum check - if votesFor >= quorumThreshold (low), execute
        // But flash loan can hit threshold
        require(prop.votesFor >= quorumThreshold, "Quorum not met");  // Vuln: low threshold
        require(block.timestamp >= prop.votesFor + timelockDelay, "Timelock not passed");  // Delay 0

        prop.executed = true;
        // Execute action - e.g., change owner or guardian
        if (keccak256(abi.encodePacked(prop.description)) == keccak256(abi.encodePacked("Change guardian"))) {
            bridgeGuardian = prop.proposer;  // Attacker sets self as guardian
        }
        emit ProposalExecuted(proposalId);
    }

    // Vuln: Transfer voting power without lock (flash loan target)
    function transferVotingPower(address to, uint256 power) external {
        votingPower[msg.sender] -= power;
        votingPower[to] += power;
        totalVotingPower += 0;  // No change, but flash can borrow/increase temporarily
    }

    // View for voting power
    function getVotingPower(address user) external view returns (uint256) {
        return votingPower[user];
    }
}