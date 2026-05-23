// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RobotFleetGovernance
 * @dev Decentralized Robot Fleet Governance & Tasking System
 * @author DecodeLabs Batch 2026
 * Implements: Authentication, Capability Bitmask, 3-Checkpoint Security Gate
 */
contract RobotFleetGovernance {

    // ─────────────────────────────────────────────
    //  STATE VARIABLES
    // ─────────────────────────────────────────────

    address public owner;
    uint256 public taskCounter;

    // Maps robot address → is it registered/authenticated?
    mapping(address => bool) public authenticated;

    // Maps robot address → its capability bitmask (uint128)
    // Bits represent hardware features: bit2=LiDAR, bit64=HighMomentumMotor, bit96=HeavyPayload
    mapping(address => uint128) public capabilities;

    // Maps robot address → currently active taskId (0 = idle)
    mapping(address => uint256) public activeTask;

    // Task record struct
    struct Task {
        uint256 taskId;
        address robot;           // assigned robot
        uint256 payload;         // encoded task data (uint256, no floats in Solidity)
        string  metadataURI;     // IPFS link for heavy data
        bool    completed;
        bytes32 completionHash;  // ZK-proof / completion hash submitted by robot
    }

    // Maps taskId → Task struct
    mapping(uint256 => Task) public tasks;

    // ─────────────────────────────────────────────
    //  EVENTS (on-chain logs)
    // ─────────────────────────────────────────────

    event RobotRegistered(address indexed robot, uint128 capabilities);
    event RobotRemoved(address indexed robot);
    event TaskAssigned(uint256 indexed taskId, address indexed robot, uint256 payload);
    event TaskCompleted(uint256 indexed taskId, address indexed robot, bytes32 completionHash);

    // ─────────────────────────────────────────────
    //  MODIFIERS
    // ─────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "Access Denied: Only fleet owner");
        _;
    }

    modifier onlyAuthenticated(address robot) {
        // CHECKPOINT 1: Invalid Robot Validation
        require(authenticated[robot], "Auth Failed: Robot not in authorized fleet");
        _;
    }

    // ─────────────────────────────────────────────
    //  CONSTRUCTOR
    // ─────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
        taskCounter = 0;
    }

    // ─────────────────────────────────────────────
    //  LOGICAL ACTUATOR FUNCTIONS
    //  (Administrative - manage fleet membership)
    // ─────────────────────────────────────────────

    /**
     * @dev Register a new robot into the authorized fleet
     * @param robot  Ethereum address representing the robot
     * @param caps   uint128 bitmask encoding hardware capabilities
     *               bit 2  → LiDAR Sensor
     *               bit 64 → High-Momentum Motor
     *               bit 96 → Heavy Payload Capacity
     */
    function registerRobot(address robot, uint128 caps) external onlyOwner {
        require(robot != address(0), "Invalid address");
        require(!authenticated[robot], "Robot already registered");

        authenticated[robot] = true;
        capabilities[robot]  = caps;

        emit RobotRegistered(robot, caps);
    }

    /**
     * @dev Remove a robot from the authorized fleet
     */
    function removeRobot(address robot) external onlyOwner {
        require(authenticated[robot], "Robot not in fleet");
        authenticated[robot] = false;
        capabilities[robot]  = 0;
        emit RobotRemoved(robot);
    }

    // ─────────────────────────────────────────────
    //  BEHAVIORAL TASK LOGIC
    //  (Operational - task assignment & verification)
    // ─────────────────────────────────────────────

    /**
     * @dev Check if a robot is authenticated
     */
    function checkRobotAuth(address robot) external view returns (bool) {
        return authenticated[robot];
    }

    /**
     * @dev Assign a task to a specific robot
     *      Passes through all 3 Security Checkpoints
     * @param targetRobot  Address of the robot to assign
     * @param payload      uint256 encoded task data
     *                     (Solidity has no floats! Scale sensor values × 10^7)
     *                     e.g., 0.3524 → 3524000
     * @param metadataURI  IPFS URI for full task details (keeps on-chain data light)
     */
    function assignTask(
        address targetRobot,
        uint256 payload,
        string calldata metadataURI
    )
        external
        onlyAuthenticated(targetRobot)   // CHECKPOINT 1: must be in fleet
        returns (uint256)
    {
        // CHECKPOINT 2: Concurrency Shield — Robot must be idle
        require(activeTask[targetRobot] == 0, "Robot Busy: task already in progress");

        // All checkpoints passed → create task
        taskCounter++;
        uint256 newTaskId = taskCounter;

        tasks[newTaskId] = Task({
            taskId:         newTaskId,
            robot:          targetRobot,
            payload:        payload,
            metadataURI:    metadataURI,
            completed:      false,
            completionHash: bytes32(0)
        });

        // Mark robot as busy
        activeTask[targetRobot] = newTaskId;

        emit TaskAssigned(newTaskId, targetRobot, payload);
        return newTaskId;
    }

    /**
     * @dev Robot reports task completion with a proof hash
     *      Only the exact assigned robot can call this
     * @param taskId         ID of the task being completed
     * @param completionHash Hash representing ZK-proof or completion evidence
     */
    function completeTask(uint256 taskId, bytes32 completionHash) external {
        Task storage t = tasks[taskId];

        // CHECKPOINT 3: Mismatched Completion
        // Only the assigned robot can report completion
        require(t.robot == msg.sender, "Auth Failed: Not the assigned robot");
        require(!t.completed, "Task already marked complete");
        require(completionHash != bytes32(0), "Invalid completion proof");

        // On-chain logic gate: verify proof is non-zero (basic check)
        // In enterprise scale this would call a ZK-SNARK verifier contract
        bool proofValid = _verifyOutcome(completionHash);
        require(proofValid, "Outcome verification failed");

        // Update state immutably on-chain
        t.completed      = true;
        t.completionHash = completionHash;

        // Free the robot for next task
        activeTask[msg.sender] = 0;

        emit TaskCompleted(taskId, msg.sender, completionHash);
    }

    /**
     * @dev Internal on-chain logic gate for outcome verification
     *      (Simplified: checks hash is non-zero. In production: ZK-SNARK verifier)
     */
    function _verifyOutcome(bytes32 proof) internal pure returns (bool) {
        return proof != bytes32(0);
    }

    // ─────────────────────────────────────────────
    //  VIEW FUNCTIONS (read fleet state)
    // ─────────────────────────────────────────────

    function getTask(uint256 taskId) external view returns (Task memory) {
        return tasks[taskId];
    }

    function isRobotBusy(address robot) external view returns (bool) {
        return activeTask[robot] != 0;
    }

    function getRobotCapabilities(address robot) external view returns (uint128) {
        return capabilities[robot];
    }
}