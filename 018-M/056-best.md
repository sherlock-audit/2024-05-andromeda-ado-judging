Radiant Burlap Gibbon

Medium

# Slashing of Unbondings is not accounted for and can lead to DOS of withdrawals

## Summary

The `andromeda-validator-staking` contract has a vulnerability in the unstaking process when a validator is slashed. If a slashing event occurs while tokens are in the unbonding period, the amount recorded in the `UNSTAKING_QUEUE` remains unchanged, leading to a mismatch between the expected and actual unstaked tokens. This prevents users from successfully withdrawing their tokens. 

## Vulnerability Detail

When the owner of the `andromeda-validator-staking` contract wants to unstake his tokens he calls to the [`execute_unstake()`](https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L138-L184) function. When the user calls this function, a `StakingMsg::Undelegate` is created. 

```rust
let undelegate_msg = CosmosMsg::Staking(StakingMsg::Undelegate {
	validator: validator.to_string(),
	amount: res.amount,
});
```

When this message gets received by the `cosmos-sdk` the function [`Undelegate()`](https://github.com/cosmos/cosmos-sdk/blob/d21620d1280538ddb1129af4979d62878850ff99/x/staking/keeper/msg_server.go#L397C20-L397C30) of the message server gets called. This function will then forward the call to the keepers [`Undelegate()`](https://github.com/cosmos/cosmos-sdk/blob/d21620d1280538ddb1129af4979d62878850ff99/x/staking/keeper/delegation.go#L923-L971) function. This function does not directly unstake the tokens. Instead it calls [`SetUnbondingDelegationEntry`](https://github.com/cosmos/cosmos-sdk/blob/d21620d1280538ddb1129af4979d62878850ff99/x/staking/keeper/delegation.go#L309) and [generates](https://docs.cosmos.network/v0.46/modules/staking/02_state_transitions.html#begin-unbonding) a `UnbondingDelegation` entry. This entry keeps track of the un-bonding while waiting for its completion. After creating the entry, a [`MsgUndelegateResponse`](https://github.com/cosmos/cosmos-sdk/blob/b03a2c6b0a4ad3794e2d50dd1354c7022cdd5826/x/staking/proto/cosmos/staking/v1beta1/tx.proto#L162) is sent to the user. 

```rust
// MsgUndelegateResponse defines the Msg/Undelegate response type.
message MsgUndelegateResponse {
  google.protobuf.Timestamp completion_time = 1
      [(gogoproto.nullable) = false, (amino.dont_omitempty) = true, (gogoproto.stdtime) = true];

  // amount returns the amount of undelegated coins
  cosmos.base.v1beta1.Coin amount = 2
      [(gogoproto.nullable) = false, (amino.dont_omitempty) = true, (cosmos_proto.field_added_in) = "cosmos-sdk 0.50"];
}
```

Once the completion time has passed, the bonding will be fully unstaked, and the tokens will be transferred to the staker. 

The escrowing of un-stakings is also considered in the design of the contract as the `UNSTAKING_QUEUE` is used to keep track of these un-stakings, and the user is only able to withdraw the tokens again once the completion time has passed, and they were refunded to the contract. So the contract waits for the `MsgUndelegateResponse`, which it receives after the `UnbondingDelegation` entry is created, and then pushes a struct containing the amount and completion time of the un-bonding into the `UNSTAKING_QUEUE`. When the completion time has passed, the user can call `execute_withdraw_fund()` to transfer the amount saved in the struct.

The problem is that the `cosmos-sdk` allows for the slashing of validators. When a validator gets slashed, the [`Slash()`](https://github.com/cosmos/cosmos-sdk/blob/d21620d1280538ddb1129af4979d62878850ff99/x/staking/keeper/slash.go#L37) function is called. If the invalidator's incorrect behavior did not occur in the same block as the slashing, the `UnbondingDelegation` entries will also be slashed.

```go
for _, unbondingDelegation := range unbondingDelegations {
	amountSlashed, err := k.SlashUnbondingDelegation(ctx, unbondingDelegation, infractionHeight, slashFactor)
	if err != nil {
		return math.ZeroInt(), err
	}
	if amountSlashed.IsZero() {
		continue
	}

	remainingSlashAmount = remainingSlashAmount.Sub(amountSlashed)
}
```

The slashing takes place in the [`SlashUnbondingDelegation()`](https://github.com/cosmos/cosmos-sdk/blob/d21620d1280538ddb1129af4979d62878850ff99/x/staking/keeper/slash.go#L243) function. This function will reduce the amount in the `UnbondingDelegation` entry by the `slashFactor`. 

When a slashing occurs while an unbonding is pending, and a user then tries to withdraw the tokens by calling to `execute_withdraw_fund()`, the tokens will not be withdrawable. This is because the entry in the `UNSTAKING_QUEUE` still contains the total amount of unstaked tokens, while the contract only received the slashed amount. 

### Exemplary scenario

An exemplary scenario can be added to make the issue easier to understand.

1. User stakes 1000 tokens
2. The user tries to unstake the 1000 tokens again
3. A struct with a completion time of 1 week and 1000 tokens gets pushed to the `UNSTAKING_QUEUE`
4. Slashing occurs while the unstake  is pending, and 50% are slashed
5. The completion time passes, and 500 tokens are transferred to the contract
6. The user tries calling `execute_withdraw_fund()`, but the call reverts as the contract tries to transfer 1000 tokens to him while only having 500

## Impact

The issue results in staked tokens getting stuck in the contract. As the `andromeda-validator-staking` contract does not implement a `migrate()` function, the funds can not be rescued by upgrading the contract. 

## Code Snippet

https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L138

## Tool used

Manual Review

## Recommendation

We recommend adapting the `execute_withdraw_fund()` function to transfer the minimum of the actual balance and the combined funds. To do this, the amount of all `Coin` objects in the `funds` vector must first be summed up. Afterward, the contract must query its actual balance of the native asset and then transfer the minimum of both.