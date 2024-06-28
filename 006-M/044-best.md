Great Leather Tarantula

Medium

# if Slash Validator occurs, UNSTAKING_QUEUE's unstake amount will not be accurate

## Summary
`UNSTAKING_QUEUE` holds `UnbondingDelegationEntry.initial_balance`.
If a `Slash Validator` occurs, which actually unstake amount is `UnbondingDelegationEntry.balance`, this value will be smaller than `UnbondingDelegationEntry.initial_balance`
which will cause `execute_withdraw_fund()` to fail.

## Vulnerability Detail
in `andromeda-validator-staking`
We can get the stake funds back in the following ways
1. call execute_unstake(100)  , UnbondingDelegationEntry.initial_balance = 100 , 
    - UNSTAKING_QUEUE.push_back(100)
2. wait UnbondingTime ,  `x/staking` transfer funds (UnbondingDelegationEntry.balance=100)  to `andromeda-validator-staking`
3. call execute_withdraw_fund()
    - UNSTAKING_QUEUE.pop_front(100)
    - transfer 100  to `sender` from `andromeda-validator-staking`

If it doesn't happen` Slash Validator`， balance == initial_balance
https://github.com/cosmos/cosmos-sdk/blob/207b30262fc4ae62cb6fc7c2f6df1dfaf7bc1c4d/x/staking/proto/cosmos/staking/v1beta1/staking.proto#L238
```proto
message UnbondingDelegationEntry {
...
  google.protobuf.Timestamp completion_time = 2
      [(gogoproto.nullable) = false, (amino.dont_omitempty) = true, (gogoproto.stdtime) = true];
  // initial_balance defines the tokens initially scheduled to receive at completion.
@>string initial_balance = 3 [
    (cosmos_proto.scalar)  = "cosmos.Int",
    (gogoproto.customtype) = "cosmossdk.io/math.Int",
    (gogoproto.nullable)   = false
  ];
  // balance defines the tokens to receive at completion.
@>string balance = 4 [
    (cosmos_proto.scalar)  = "cosmos.Int",
    (gogoproto.customtype) = "cosmossdk.io/math.Int",
    (gogoproto.nullable)   = false
  ];
...
}
```

However, happen` Slash Validator`, the actual funds received will be less than the value recorded in the `UNSTAKING_QUEUE' record.
https://github.com/cosmos/cosmos-sdk/tree/main/x/staking#slash-unbonding-delegation
>## Slash Unbonding Delegation
>When a validator is slashed, so are those unbonding delegations from the validator that began unbonding after the time of the infraction. Every entry in every unbonding delegation from the validator is slashed by slashFactor. The amount slashed is calculated from the InitialBalance of the delegation and is capped to prevent a resulting negative balance. Completed (or mature) unbondings are not slashed.

## Impact

If a `Slash Validator` occurs, the value of the `UNSTAKING_QUEUE` record will be less than the actual value received
Resulting in
1. failure due to insufficient balance
2. blocking the normal queue behind

## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L333
## Tool used

Manual Review

## Recommendation

when the balance is insufficient, only the balance is returned
