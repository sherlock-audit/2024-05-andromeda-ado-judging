Radiant Burlap Gibbon

High

# Rewards will get stuck if `withdrawaddrenabled` is set to false on the target chain

## Summary

The `distribution` module of the `cosmos-sdk` has parameters that configure its behavior, including the `withdrawaddrenabled` parameter. This parameter allows setting a separate withdrawal address for claiming staking rewards. If this parameter is set to `false`, the contract's functionality to set a withdrawal address is ineffective, causing rewards to be distributed to the default delegator address, leading to rewards being stuck in the contract. The impact is that all rewards get stuck in the `andromeda-validator-staking` module, and in the `andromeda-vesting` contract.

## Vulnerability Detail

The `distribution` module of the `cosmos-sdk` has [parameters](https://docs.cosmos.network/v0.47/build/modules/distribution#parameters) which make up its configuration. 

| Key                 | Type         | Example                    |
| ------------------- | ------------ | -------------------------- |
| communitytax        | string (dec) | "0.020000000000000000" [0] |
| withdrawaddrenabled | bool         | true                       |

Each of these parameters can be set for each cosmos chain. The governance can change this parameter at any time via a [`MsgUpdateParams`](https://docs.cosmos.network/v0.47/build/modules/staking#msgupdateparams )message. The parameter we are focusing on is the `withdrawaddrenabled` parameter. It defines whether a separate withdrawal address can be chosen to claim staking rewards. If this parameter is `false` [no withdraw address can be set](https://docs.cosmos.network/v0.47/build/modules/distribution#msgsetwithdrawaddress) when a `MsgSetWithdrawAddress` is received. 

The `withdrawaddrenabled` parameter is essential for the contract's functionality, as the contract tries to set a withdrawal address in both modules before rewards are withdrawn. The process for this consists of the two messages:

1. `DistributionMsg::SetWithdrawAddress`
2. `DistributionMsg::WithdrawDelegatorReward`

If the `withdrawaddrenabled` config parameter is set to false, the first message will not change anything. As a result, the default address, [which is the delegator's address](https://docs.cosmos.network/v0.47/build/modules/distribution#msgsetwithdrawaddress), will persist. When the following message is executed, all rewards will be distributed to the delegator address, which in our case would be the two contracts. As the claim functions do not directly distribute those rewards but expect them to be sent to the "newly set" withdrawal address, the rewards will get stuck inside the contracts.

## Impact

The issue results in all rewards getting stuck in the `andromeda-validator-staking` module. For the `andromeda-vesting` contract, they will also get stuck, but the owner could rescue them with an instantly expiring vesting of the value of the stuck tokens. As the `andromeda-validator-staking` contract does not implement a `migrate()` function, the funds can not be rescued by upgrading the contract.

## Code Snippet

https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L231-L233

https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L523-L525

## Tool used

Manual Review

## Recommendation

We recommend adapting the claiming functionality so it queries the config of the `distribution` module. If the `withdrawaddrenabled` parameter is set to true, it should keep working as it is now. If it is set to false, it should implement a mode to account for the claims it will receive on behalf of the user so that the user can later on claim the rewards through an additional function. This could work as follows:
1. User calls claim
2. Flag is set to false, so additional behavior is needed
3. Users ` DistributionMsg::WithdrawDelegatorReward` message is sent
4. Once rewards are received, they are tracked inside the contract and associated with the claimant's address
5. The claimant can claim them through an additional function.