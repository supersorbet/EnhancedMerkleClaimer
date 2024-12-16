// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MerkleProofLib} from "solady/src/utils/MerkleProofLib.sol";
import {Ownable} from "solady/src/auth/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title MerkleClaimer - A contract for handling V1 Farm token claims
/// @notice This contract manages the claim process for V1 Farm tokens using both merkle proofs and manual claims
/// @dev Implements EIP-712 for secure message signing and merkle proofs for efficient claim verification
contract MerkleClaimer is Ownable, ReentrancyGuard, Pausable, EIP712 {
    using ECDSA for bytes32;
    using SafeTransferLib for address;

    /// @notice Error thrown when attempting to interact before claim period starts
    error ClaimPeriodNotStarted();
    /// @notice Error thrown when attempting to start an already started claim period
    error ClaimPeriodAlreadyStarted();
    /// @notice Error thrown when user attempts to acknowledge an already acknowledged claim
    error AlreadyAcknowledged();
    /// @notice Error thrown when user attempts to claim already claimed tokens
    error AlreadyClaimed();
    /// @notice Error thrown when provided merkle proof is invalid
    error InvalidProof();
    /// @notice Error thrown when user's staked balance is insufficient
    error InsufficientStakedBalance();
    /// @notice Error thrown when attempting to claim without acknowledging first
    error MustAcknowledgeFirst();
    /// @notice Error thrown when total claims would exceed allocation
    error ExceedsTotalAllocation();
    /// @notice Error thrown when signature verification fails
    error InvalidSignature();
    /// @notice Error thrown for invalid amount parameters
    error InvalidAmount();
    /// @notice Error thrown when contract is in emergency stop state
    error EmergencyShutdown();
    /// @notice Error thrown when root updates are disabled
    error RootUpdateDisabled();
    /// @notice Error thrown when contract balance is insufficient for claim
    error InsufficientContractBalance();
    /// @notice Error thrown when attempting to set invalid claimable amount
    error InvalidClaimableAmount();
    /// @notice Error thrown when user already has an existing claim
    error UserHasExistingClaim();
    /// @notice Error thrown when no manual claim exists for user
    error NoManualClaimExists();
    /// @notice Error thrown when claim is already in progress
    error ClaimInProgress();

    /// @notice Type hash for EIP-712 acknowledgment signing
    /// @dev Computed as keccak256("Acknowledgment(address user,uint256 amount,string message,uint256 nonce)")
    bytes32 private constant ACKNOWLEDGMENT_TYPEHASH = keccak256(
        "Acknowledgment(address user,uint256 amount,string message,uint256 nonce)"
    );
    
    /// @notice Message that users must acknowledge when claiming
    /// @dev Used in signature verification process
    string private constant ACKNOWLEDGMENT_MESSAGE = 
        "I agree to receive Pepecoin equivalent to the amount staked by this address in the V1 Staking Contract. Upon receipt of this claim, I acknowledge that I will no longer be entitled to the staked amount.";

    /// @notice Address of the PEPECOIN token contract
    address public constant TOKEN = 0xA9E8aCf069C58aEc8825542845Fd754e41a9489A;
    
    /// @notice Address of the BasedFarm contract
    IBasedFarm public constant BASED_AIFARM = IBasedFarm(0xA6B816010Ab51e088C4F19c71ABa87E54b422E14);
    
    /// @notice Pool ID for the V1 farm in the BasedFarm contract
    uint256 public constant POOL_ID = 0;

    /// @notice Current merkle root for verifying claims
    /// @dev Updated through setRoot or updateMerkleRoot functions
    bytes32 public merkleRoot;

    /// @notice Total amount of tokens claimed so far
    uint256 public totalClaimed;

    /// @notice Timestamp when claim period started
    /// @dev Set through startClaimPeriod function
    uint256 public claimPeriodStart;

    /// @notice Flag indicating if contract is in emergency stop state
    bool public stopped;

    /// @notice Flag indicating if merkle root updates are enabled
    bool public rootUpdateEnabled;
    
    /// @notice Struct containing user claim data
    /// @dev Packed for gas optimization
    struct UserData {
        bool hasAcknowledged;      // Whether user has acknowledged their claim
        bool hasClaimed;           // Whether user has claimed their tokens
        uint64 acknowledgeTimestamp; // When user acknowledged their claim
        uint64 claimTimestamp;      // When user claimed their tokens
        uint128 amountClaimed;      // Amount of tokens claimed
        uint64 nonce;               // Nonce for signature verification
        uint256 manualClaimAmount;  // Amount for manual claims
        bool isManuallyAdded;       // Whether user was manually added
    }
    
    /// @notice Mapping of user addresses to their claim data
    mapping(address => UserData) public userData;

    /// @notice Emitted when new merkle root is set
    /// @param merkleRoot New merkle root
    /// @param totalAllocation Total token allocation (kept for compatibility)
    event RootSet(bytes32 merkleRoot, uint256 totalAllocation);

    /// @notice Emitted when merkle root is updated
    /// @param oldRoot Previous merkle root
    /// @param newRoot New merkle root
    event RootUpdated(bytes32 oldRoot, bytes32 newRoot);

    /// @notice Emitted when root update status changes
    /// @param enabled New status of root updates
    event RootUpdateStatusChanged(bool enabled);

    /// @notice Emitted when manual claim is added
    /// @param user Address of user
    /// @param amount Claimable amount
    event ManualClaimAdded(address indexed user, uint256 amount);

    /// @notice Emitted when manual claim is updated
    /// @param user Address of user
    /// @param oldAmount Previous claimable amount
    /// @param newAmount New claimable amount
    event ManualClaimUpdated(address indexed user, uint256 oldAmount, uint256 newAmount);

    /// @notice Emitted when user acknowledges claim
    /// @param claimant Address of claimer
    /// @param amount Amount acknowledged
    /// @param messageHash Hash of acknowledgment message
    /// @param nonce Nonce used in acknowledgment
    event Acknowledged(
        address indexed claimant, 
        uint256 amount, 
        bytes32 messageHash,
        uint256 nonce
    );

    /// @notice Emitted when tokens are claimed
    /// @param claimant Address of claimer
    /// @param amount Amount claimed
    /// @param timestamp When claim occurred
    event Claimed(
        address indexed claimant, 
        uint256 amount, 
        uint256 timestamp
    );

    /// @notice Emitted when claim period starts
    /// @param startTime Timestamp when period started
    event ClaimPeriodStarted(uint256 startTime);

    /// @notice Emitted when emergency stop status changes
    /// @param status New emergency stop status
    event EmergencyShutdownSet(bool status);

    /// @notice Emitted when reimbursement is claimed
    /// @param user Address of user
    /// @param amount Amount claimed
    /// @param stakedBalance User's staked balance
    /// @param timestamp When claim occurred
    event ReimbursementClaimed(
        address indexed user,
        uint256 amount,
        uint256 stakedBalance,
        uint256 timestamp
    );

    /// @notice Contract constructor
    /// @dev Initializes EIP-712 domain separator and enables root updates
    constructor() EIP712("claimer", "1") {
        _initializeOwner(msg.sender);
        rootUpdateEnabled = true;
    }

    /// @notice Adds a manual claim for a user
    /// @dev Only callable by owner, reverts if user already has a claim
    /// @param _user Address of user to add claim for
    /// @param _amount Amount of tokens claimable
    function addManualClaim(address _user, uint256 _amount) external onlyOwner {
        if (_user == address(0)) revert InvalidAmount();
        if (_amount == 0) revert InvalidClaimableAmount();
        
        UserData storage user = userData[_user];
        if (user.hasAcknowledged || user.hasClaimed) revert UserHasExistingClaim();
        if (user.isManuallyAdded) revert UserHasExistingClaim();

        user.manualClaimAmount = _amount;
        user.isManuallyAdded = true;
        
        emit ManualClaimAdded(_user, _amount);
    }

    /// @notice Updates existing manual claim amount
    /// @dev Only callable by owner, reverts if user hasn't been manually added
    /// @param _user Address of user to update claim for
    /// @param _newAmount New claimable amount
    function updateManualClaim(address _user, uint256 _newAmount) external onlyOwner {
        if (_newAmount == 0) revert InvalidClaimableAmount();
        
        UserData storage user = userData[_user];
        if (!user.isManuallyAdded) revert NoManualClaimExists();
        if (user.hasAcknowledged || user.hasClaimed) revert ClaimInProgress();

        uint256 oldAmount = user.manualClaimAmount;
        user.manualClaimAmount = _newAmount;
        
        emit ManualClaimUpdated(_user, oldAmount, _newAmount);
    }

    /// @notice Gets claimable amount for a user
    /// @dev Checks both manual claims and merkle proof claims
    /// @param _user Address to check
    /// @param _amount Amount to verify against merkle proof
    /// @param _merkleProof Merkle proof to verify
    /// @return claimableAmount Amount user can claim
    /// @return isManual Whether claim is manual or merkle-based
    function getClaimableAmount(
        address _user,
        uint256 _amount,
        bytes32[] memory _merkleProof
    ) public view returns (uint256 claimableAmount, bool isManual) {
        UserData storage user = userData[_user];
        
        if (user.isManuallyAdded) {
            return (user.manualClaimAmount, true);
        }
        
        if (verifyClaim(_user, _amount, _merkleProof)) {
            return (_amount, false);
        }
        
        return (0, false);
    }

    /// @notice Creates typed data hash for acknowledgment signing
    /// @dev Implements EIP-712 typed data hashing
    /// @param _user Address of user acknowledging
    /// @param _amount Amount being acknowledged
    /// @return Typed data hash for signing
    function getAcknowledgmentHash(
        address _user,
        uint256 _amount
    ) public view returns (bytes32) {
        UserData storage user = userData[_user];
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    ACKNOWLEDGMENT_TYPEHASH,
                    _user,
                    _amount,
                    keccak256(bytes(ACKNOWLEDGMENT_MESSAGE)),
                    user.nonce
                )
            )
        );
    }

    /// @notice Verifies a signature against an acknowledgment hash
    /// @dev Uses ECDSA recovery to verify signer
    /// @param _user Address of intended signer
    /// @param _amount Amount being acknowledged
    /// @param _signature Signature to verify
    /// @return bool indicating if signature is valid
    function verifySignature(
        address _user,
        uint256 _amount,
        bytes calldata _signature
    ) public view returns (bool) {
        bytes32 hash = getAcknowledgmentHash(_user, _amount);
        return ECDSA.recover(hash, _signature) == _user;
    }

    /// @notice Allows users to acknowledge their claim
    /// @dev Requires valid signature and proof, updates user data
    /// @param _amount Amount being acknowledged
    /// @param _merkleProof Proof of inclusion in merkle tree
    /// @param _signature Signed acknowledgment message
    function acknowledgeReimbursement(
        uint256 _amount,
        bytes32[] calldata _merkleProof,
        bytes calldata _signature
    ) external whenNotPaused nonReentrant {
        if (stopped) revert EmergencyShutdown();
        if (_amount == 0) revert InvalidAmount();
        if (claimPeriodStart == 0) revert ClaimPeriodNotStarted();
            
        UserData storage user = userData[msg.sender];
        if (user.hasAcknowledged) revert AlreadyAcknowledged();

        (uint256 claimableAmount, bool isManual) = getClaimableAmount(msg.sender, _amount, _merkleProof);
        if (claimableAmount == 0) revert InvalidAmount();
        if (claimableAmount != _amount) revert InvalidAmount();

        if (!isManual && !verifyClaim(msg.sender, _amount, _merkleProof))
            revert InvalidProof();
        
        if (!verifySignature(msg.sender, _amount, _signature))
            revert InvalidSignature();

        uint256 stakedBalance = getStakedPepecoinBalance(msg.sender);
        if (stakedBalance < _amount)
            revert InsufficientStakedBalance();

        user.hasAcknowledged = true;
        user.acknowledgeTimestamp = uint64(block.timestamp);
        user.amountClaimed = uint128(_amount); 
        user.nonce++;
        
        emit Acknowledged(
            msg.sender, 
            _amount, 
            getAcknowledgmentHash(msg.sender, _amount),
            user.nonce - 1
        );
    }

    /// @notice Allows users to claim their tokens after acknowledgment
    /// @dev Requires prior acknowledgment and sufficient contract balance
    /// @dev Transfers tokens directly to user upon successful claim
    function claim() external nonReentrant whenNotPaused {
        if (stopped) revert EmergencyShutdown();

        UserData storage user = userData[msg.sender];
        
        if (claimPeriodStart == 0)
            revert ClaimPeriodNotStarted();
        if (!user.hasAcknowledged)
            revert MustAcknowledgeFirst();
        if (user.hasClaimed) 
            revert AlreadyClaimed();
            
        uint256 _amount = user.amountClaimed;
        if (_amount == 0) revert InvalidAmount();

        uint256 contractBalance = TOKEN.balanceOf(address(this));
        if (contractBalance < _amount)
            revert InsufficientContractBalance();
        
        uint256 stakedBalance = getStakedPepecoinBalance(msg.sender);
        if (stakedBalance < _amount)
            revert InsufficientStakedBalance();
            
        user.hasClaimed = true;
        user.claimTimestamp = uint64(block.timestamp);
        totalClaimed += _amount;
        
        TOKEN.safeTransfer(msg.sender, _amount);
        
        emit Claimed(msg.sender, _amount, block.timestamp);
        emit ReimbursementClaimed(
            msg.sender,
            _amount,
            stakedBalance,
            block.timestamp
        );
    }

    /// @notice Gets detailed claim status for a user
    /// @dev Returns all relevant timestamps and amounts
    /// @param _user Address to check status for
    /// @return acknowledged Whether user has acknowledged
    /// @return claimed Whether user has claimed
    /// @return acknowledgeTime When user acknowledged
    /// @return claimTime When user claimed
    /// @return amountClaimed Amount user claimed/can claim
    /// @return stakedBalance User's current staked balance
    /// @return nonce Current nonce for user's signatures
    function getDetailedClaimStatus(address _user) 
        external 
        view 
        returns (
            bool acknowledged,
            bool claimed,
            uint256 acknowledgeTime,
            uint256 claimTime,
            uint256 amountClaimed,
            uint256 stakedBalance,
            uint256 nonce
        )
    {
        UserData storage user = userData[_user];
        return (
            user.hasAcknowledged,
            user.hasClaimed,
            user.acknowledgeTimestamp,
            user.claimTimestamp,
            user.amountClaimed,
            getStakedPepecoinBalance(_user),
            user.nonce
        );
    }

    /// @notice Verifies a claim against the merkle tree
    /// @dev Uses Solady MerkleProofLib
    /// @param _claimant Address of claimer
    /// @param _amount Amount being claimed
    /// @param _merkleProof Proof of inclusion in merkle tree
    /// @return bool indicating if claim is valid
    function verifyClaim(
        address _claimant,
        uint256 _amount,
        bytes32[] memory _merkleProof
    ) public view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(_claimant, _amount));
        return MerkleProofLib.verify(_merkleProof, merkleRoot, leaf);
    }

    /// @notice Gets user's staked balance from V1 farm
    /// @dev Queries the BASED_AIFARM contract
    /// @param _user Address to check balance for
    /// @return uint256 Staked balance of user
    function getStakedPepecoinBalance(
        address _user
    ) public view returns (uint256) {
        (uint256 amount, ) = BASED_AIFARM.userInfo(POOL_ID, _user);
        return amount;
    }

    /// @notice Sets new merkle root
    /// @dev Only callable by owner when root updates are enabled
    /// @param _merkleRoot New root to set
    function setRoot(bytes32 _merkleRoot) external onlyOwner {
        if (!rootUpdateEnabled && merkleRoot != bytes32(0)) revert RootUpdateDisabled();
        if (_merkleRoot == bytes32(0)) revert InvalidProof();
        
        merkleRoot = _merkleRoot;
        emit RootSet(_merkleRoot, 0);
    }

    /// @notice Updates existing merkle root
    /// @dev Only callable by owner when root updates are enabled
    /// @param _newRoot New root to set
    function updateMerkleRoot(bytes32 _newRoot) external onlyOwner {
        if (!rootUpdateEnabled) revert RootUpdateDisabled();
        if (_newRoot == bytes32(0)) revert InvalidProof();
        
        bytes32 oldRoot = merkleRoot;
        merkleRoot = _newRoot;
        
        emit RootUpdated(oldRoot, _newRoot);
    }

    /// @notice Enables/disables ability to update merkle root
    /// @dev Only callable by owner
    /// @param _enabled Whether root updates should be enabled
    function setRootUpdateStatus(bool _enabled) external onlyOwner {
        rootUpdateEnabled = _enabled;
        emit RootUpdateStatusChanged(_enabled);
    }

    /// @notice Sets emergency stop status
    /// @dev Only callable by owner
    /// @param _status Whether to enable emergency stop
    function emergencyStop(bool _status) external onlyOwner {
        stopped = _status;
        emit EmergencyShutdownSet(_status);
    }

    /// @notice Allows owner to withdraw tokens
    /// @dev Only callable in emergency stop state
    /// @param _token Token address to withdraw
    /// @param _amount Amount to withdraw
    function withdrawTokens(
        address _token,
        uint256 _amount
    ) external onlyOwner {
        if (_token == address(0)) revert InvalidAmount();
        if (_amount == 0) revert InvalidAmount();
        if (!stopped) revert EmergencyShutdown();
        
        SafeTransferLib.safeTransfer(_token, owner(), _amount);
    }

    /// @notice Starts the claim period
    /// @dev Only callable once by owner
    function startClaimPeriod() external onlyOwner {
        if (claimPeriodStart != 0) revert ClaimPeriodAlreadyStarted();
        if (merkleRoot == bytes32(0)) revert InvalidProof();
        
        claimPeriodStart = block.timestamp;
        emit ClaimPeriodStarted(claimPeriodStart);
    }

    /// @notice Pauses all claim functionality
    /// @dev Only callable by owner
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses all claim functionality
    /// @dev Only callable by owner
    function unpause() external onlyOwner {
        _unpause();
    }
}

/// @title IBasedFarm Interface
/// @notice Interface for interacting with the V1 Based Farm contract
interface IBasedFarm {
    /// @notice Gets user's staking information
    /// @param _pid Pool ID to query
    /// @param _user Address to query
    /// @return amount Amount staked
    /// @return rewardDebt Reward debt for user
    function userInfo(uint256 _pid, address _user)
        external
        view
        returns (uint256 amount, uint256 rewardDebt);
}