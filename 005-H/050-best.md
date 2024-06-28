Radiant Burlap Gibbon

High

# Attacker can freeze users first rewards

## Summary

The `andromeda-validator-staking` contract has a vulnerability related to the staking rewards withdrawal process. If the withdrawal address is not set correctly, rewards can be unintentionally distributed to the contract itself, causing them to become stuck. This can be exploited by an attacker who can front-run the owner's first claim transaction and cause the rewards to be irretrievably sent to the contract. The impact of this issue is the loss of all rewards accrued before un-bonding.

## Vulnerability Detail

The `andromeda-validator-staking` allows the owner to stake tokens to a chosen validator. The delegation will then generate staking rewards. To allow the contract owner to withdraw these rewards, the `execute_claim()` function is implemented. To be able to claim the tokens correctly, two messages have to be sent:

1. `DistributionMsg::SetWithdrawAddress` - sets the address to withdraw to the recipients address
2. `DistributionMsg::WithdrawDelegatorReward` - withdraws the rewards

If the first message is not sent, the withdrawal address is set to the [delegator](https://docs.cosmos.network/v0.47/build/modules/distribution#msgsetwithdrawaddress) which in our case is the `andromeda-validator-staking` contract. When the owner calls the `execute_claim()` function directly, this leads to no issues, as the two functions are called correctly.

The issues occur as there are multiple other scenarios why rewards will be distributed besides the direct call via `DistributionMsg::WithdrawDelegatorReward`. Rewards will be distributed if a user's stake [increases](https://docs.cosmos.network/v0.47/build/modules/distribution#common-distribution-operations). The other option is that an un-bonding occurs, in which case rewards are also [distributed](https://docs.cosmos.network/v0.47/build/modules/distribution#create-or-modify-delegation-distribution). In total there are four scenarios why rewards will be distributed without a call to `DistributionMsg::WithdrawDelegatorReward`:

1. Owner stakes or un-stakes
2. Validator is jailed/tombstoned
3. The validator leaves the set willingly
4. Attacker stakes on behalf of the owner (which works as `execute_stake()` is not restricted)

For this case, we will only consider 2., 3., and 4. as 1. would require some owner wrongdoing. If one of these cases occurs before the owner has claimed rewards for the first time, the rewards will be sent directly to the `andromeda-validator-staking` contract. The tokens will become stuck there as the contract does not implement a way to retrieve/re-stake funds.

For the fourth scenario, a malicious attacker can intentionally abuse this and wait until the owner tries to call `execute_claim()` for the first time. When he sees the tx, he front-runs it and stakes 1 token on behalf of the owner, which will result in the owner's rewards getting sent to the `andromeda-validator-staking` contract and getting stuck. As the `SetWithdrawAddress`  message will only be sent afterward, the recipient is still the `andromeda-validator-staking` contract.

## Impact

The issue results in all rewards accruing before the un-bonding getting stuck in the contract and being effectively lost. As the `andromeda-validator-staking` contract does not implement a `migrate()` function, the funds can not be rescued by upgrading the contract.

## Code Snippet

https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L186-L242

## Tool used

Manual Review

## Recommendation

We recommend mitigating this issue by setting a `withdrawal_address` when calling `instantiate()`. This withdrawal address should then be set on each call to `execute_stake()`, `execute_unstake()`, and `execute_withdraw_fund()`. This way, tokens can never be lost due to an unset withdrawal address.