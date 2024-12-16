# safe merkle claim contract w/ security && legal signature protection

 secure implementation for handling token claims with merkle proofs and legal signature acknowledgement

## Interface example

The example contract verifies user balances through a farming contract interface before processing claims. (that got stuck)

### Current Interface
```solidity
interface IYourFarm {
    function userInfo(uint256 _pid, address _user)
        external 
        view
        returns (uint256 amount, uint256 rewardDebt);
}

//update these to interface your external contract
IYourFarm public constant YOUR_FARM = IYourFarm(address);
uint256 public constant POOL_ID = yourPoolId;

function getStakedBalance(address _user) public view returns (uint256) {
    //implement your balance check logic
    return userBalance;
}
