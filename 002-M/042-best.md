Great Leather Tarantula

Medium

# execute_stake() without setting DistributionMsg::SetWithdrawAddress, partial reward may remain in the contract

## Summary
in `andromeda-validator-staking`
After executing `execute_stake()`, the default reward recipient is the contract itself
if triggers a reward distribution, rewards will deposited into the contract and remains in the contract

## Vulnerability Detail
in `andromeda-validator-staking`
After executing `execute_stake()`, the reward recipient `DistributionMsg::SetWithdrawAddress` is not set, so the default reward recipient is the contract itself
```rust
fn execute_stake(ctx: ExecuteContext, validator: Option<Addr>) -> Result<Response, ContractError> {
..
    let res = Response::new()
        .add_message(StakingMsg::Delegate {
            validator: validator.to_string(),
            amount: funds.clone(),
        })
        .add_attribute("action", "validator-stake")
        .add_attribute("from", info.sender)
        .add_attribute("to", validator.to_string())
        .add_attribute("amount", funds.amount);

    Ok(res)
}
```
`DistributionMsg::SetWithdrawAddress` is only set if `execute_claim()` is actively executed

But after some time has passed , `owner` doesn't execute `execute_claim()`, so the default recipient is the contract itself
`execute_stake()` again or any other case can trigger a reward auto distribution to transfer the reward to the contract 

https://github.com/cosmos/cosmos-sdk/tree/main/x/distribution#create-or-modify-delegation-distribution
>## Create or modify delegation distribution
>triggered-by: staking.MsgDelegate, staking.MsgBeginRedelegate, staking.MsgUndelegate
>Before
>The delegation rewards are withdrawn to the withdraw address of the delegator. The rewards include the current period and exclude the starting period.
The validator period is incremented. The validator period is incremented because the validator's power and share distribution might have changed.
The reference count for the delegator's starting period is decremented.


>## Validator removed
>triggered-by: staking.RemoveValidator
>Outstanding commission is sent to the validator's self-delegation withdrawal address. Remaining delegator rewards get sent to the community pool.

>Note: The validator gets removed only when it has no remaining delegations. At that time, all outstanding delegator rewards will have been withdrawn. Any remaining rewards are dust amounts.


## Impact

Until `DistributionMsg::SetWithdrawAddress` is set, the triggered reward distribution is left in the contract

## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L34
## Tool used

Manual Review

## Recommendation

like `andromeda-vesting`, when `execute_stake()` , set `DistributionMsg::SetWithdrawAddress` to sender