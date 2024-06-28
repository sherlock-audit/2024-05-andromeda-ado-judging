Radiant Burlap Gibbon

High

# Staked tokens can never be retrieved due to old `cosmos-sdk` version on targeted chains

## Summary

The Andromeda protocol will be deployed on several cosmos chains, including its own, using a `cosmos-sdk` version below 0.50. This outdated version lacks the `amount` parameter in the `MsgUndelegateResponse` message, causing the `andromeda-validator-staking` contract to push zero-value entries into the `UNSTAKING_QUEUE`. As a result, when users try to withdraw unstaked tokens, the tokens cannot be retrieved, leading to their loss. This issue affects all tokens staked through the `andromeda-validator-staking` contract, rendering them unrecoverable.

## Vulnerability Detail

The Andromeda protocol will be deployed on the protocols [own cosmos chain as well as multiple external cosmos chains](https://docs.andromedaprotocol.io/andromeda/platform-and-framework/deployed-contracts). The Andromeda chain as well as multiple of the targeted other chains, use a `cosmos-sdk` version that is below 0.50:
- [Andromeda](https://github.com/andromedaprotocol/andromedad/blob/e93e48e0101b3408803d6b1e1cdd14bd1920160c/go.mod#L9) uses 0.47.8
- [Injective](https://github.com/InjectiveFoundation/injective-core/blob/e1ab66c240524b05b872f63890fefcd4fced5f7a/go.mod#L12) uses 0.47.5
- [Archway](https://github.com/archway-network/archway/blob/e815f983724d1a61ab41f405b5a085b605f04df3/go.mod#L19) uses 0.47.10
- [Terra](https://github.com/terra-money/core/blob/7dce06b225b2ef57ddd69f7ac729a98c6257e5a1/go.mod#L14) uses 0.47.5

Due to the outdated version being used, an issue occurs in the unstaking process of the `andromeda-validator-staking` module. The unstaking process works as follows. 

The tokens aren't directly retrieved whenever the owner un-stakes some of his tokens. Instead, the number of tokens unstaked and the completion time are pushed into the `UNSTAKING_QUEUE` once the `MsgUndelegateResponse` is received by the contract. After the completion time, the owner can retrieve his tokens again using the `execute_withdraw_fund()` function.

On all chains that use a version below `0.50`, the `MsgUndelegateResponse` message does not include an `amount` parameter. The amount parameter was added to the `MsgUndelegateResponse` message [later](https://github.com/cosmos/cosmos-sdk/pull/14590/commits). The amount parameter is only available for the newer `comsomos-sdk` version, which is 0.50. 

```go
// amount returns the amount of undelegated coins
//
// Since: cosmos-sdk 0.50
cosmos.base.v1beta1.Coin amount            = 2 [(gogoproto.nullable) = false, (amino.dont_omitempty) = true];
```

Due to this the `cosmos-sdk` does not include a `amount` parameter into its `MsgUndelegateResponse` messages on version [0.47.X](https://github.com/cosmos/cosmos-sdk/blob/d1b5b0c5ae2c51206cc1849e09e4d59986742cc3/proto/cosmos/staking/v1beta1/tx.proto#L154-L158). 

```rust
// MsgUndelegateResponse defines the Msg/Undelegate response type.
message MsgUndelegateResponse {
  google.protobuf.Timestamp completion_time = 1
      [(gogoproto.nullable) = false, (amino.dont_omitempty) = true, (gogoproto.stdtime) = true];
}
```

As a result of the outdated version, when the `on_validator_unstake()` function gets called, the response's attributes will not include an `amount` attribute. This will result in the `Coin::default()` (0) being used to create the struct that is pushed into the `UNSTAKING_QUEUE`.

```rust
let mut fund = Coin::default();
let mut payout_at = Timestamp::default();
for attr in attributes {
	if attr.key == "amount" {
		fund = Coin::from_str(&attr.value).unwrap();
	} else if attr.key == "completion_time" {
		let completion_time = DateTime::parse_from_rfc3339(&attr.value).unwrap();
		let seconds = completion_time.timestamp() as u64;
		let nanos = completion_time.timestamp_subsec_nanos() as u64;
		payout_at = Timestamp::from_seconds(seconds);
		payout_at = payout_at.plus_nanos(nanos);
	}
}
UNSTAKING_QUEUE.push_back(deps.storage, &UnstakingTokens { fund, payout_at })?;
```

When the user/owner tries to withdraw the un-staked tokens again, this will not be possible as the `Coin` objects stored in the queue all have an amount of 0. 

```rust
fn execute_withdraw_fund(ctx: ExecuteContext) -> Result<Response, ContractError> {
	...

    let mut funds = Vec::<Coin>::new();
    loop {
        match UNSTAKING_QUEUE.front(deps.storage).unwrap() {
            Some(UnstakingTokens { payout_at, .. }) if payout_at <= env.block.time => {
                if let Some(UnstakingTokens { fund, .. }) =
                    UNSTAKING_QUEUE.pop_front(deps.storage)?
                {
                    funds.push(fund)
                }
            }
            _ => break,
        }
    }

    ensure!(
        !funds.is_empty(),
        ContractError::InvalidWithdrawal {
            msg: Some("No unstaked funds to withdraw".to_string())
        }
    );

    let res = Response::new()
        .add_message(BankMsg::Send {
            to_address: info.sender.to_string(),
            amount: funds,
        })
        .add_attribute("action", "withdraw-funds")
        .add_attribute("from", env.contract.address)
        .add_attribute("to", info.sender.into_string());

    Ok(res)
} 
```

As a result, all unstaked tokens will become stuck in the contract and can not be retrieved.

## Impact

This issue impacts all tokens staked through the `andromeda-validator-staking` contract, which will be lost and not recoverable. The module can not be upgraded using `migrate(),` so the tokens will stay locked forever. 

## Code Snippet

https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L314-L345

## Tool used

Manual Review

## Recommendation

We recommend manually noting the amount of unstaked tokens and not relying on the amount returned in the `MsgUndelegateResponse` message.