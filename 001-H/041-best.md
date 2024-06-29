Great Leather Tarantula

high

# when a validator is kicked out of the bonded validator set ,unstake funds will remain in the contract

## Summary
when a validator is kicked out of the bonded validator set, auto unbonding of all their delegations
This portion of the funds will eventually be transferred to the contract and remain in the contract

## Vulnerability Detail
in `andromeda-validator-staking`
We can only get the stake funds back in the following ways

1. call execute_unstake( 100)
    - UNSTAKING_QUEUE.push_back(100)
2. wait UnbondingTime ,  `x/staking` transfer funds to `andromeda-validator-staking`
3. call execute_withdraw_fund()
    - UNSTAKING_QUEUE.pop_front(100)
    - transfer 100  to `sender` from `andromeda-validator-staking`


but when a validator is kicked out of the bonded validator set, it will auto unbonding of all their delegations
This doesn't go through the above process, it will come directly from `x/staking` transfer funds to `andromeda-validator-staking`
https://github.com/cosmos/cosmos-sdk/tree/main/x/staking#validator
when validator from `Bonded` -> `Unbonding`
>## Validator
>..
>- Unbonding: When a validator leaves the active set, either by choice or due to slashing, jailing or tombstoning, an unbonding of all their delegations begins. All delegations must then wait the UnbondingTime before their tokens are moved to their accounts from the BondedPool.

## Impact
when a validator is kicked out of the bonded validator set 
This portion of the funds will eventually be transferred to the contract and remain in the contract

## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L34
## Tool used

Manual Review

## Recommendation
in `execute_stake()` , call `ADOContract::default().add_withdrawable_token()`