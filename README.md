# Issue H-1: when a validator is kicked out of the bonded validator set ,unstake funds will remain in the contract 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/41 

## Found by 
J4X\_, Yashar, bin2chen
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

# Issue H-2: verify_origin() previous_sender may be forged 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/45 

## Found by 
bin2chen, g
## Summary
in `AMPPkt.verify_origin()` does not verify the legitimacy of the `previous_sender` and can be specified at will, leading to security risks.
## Vulnerability Detail
The `execute()` method of most current ado's can handle two types of ExecuteMsg
`ExecuteMsg::AMPReceive` or `other Msg`
```rust
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let ctx = ExecuteContext::new(deps, info, env);

    match msg {
        ExecuteMsg::AMPReceive(pkt) => {
@>          ADOContract::default().execute_amp_receive(ctx, pkt, handle_execute)
        }
        _ => handle_execute(ctx, msg),
    }
}
```
If the request is for an `AMPReceive` it checks the legality of the `AMPCtx` at `execute_amp_receive()`.
`execute_amp_receive()`->`verify_origin()`
```rust
   pub fn verify_origin(&self, info: &MessageInfo, deps: &Deps) -> Result<(), ContractError> {
        let kernel_address = ADOContract::default().get_kernel_address(deps.storage)?;
@>      if info.sender == self.ctx.origin || info.sender == kernel_address {
            Ok(())
        } else {
            let adodb_address: Addr =
                deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                    contract_addr: kernel_address.to_string(),
                    msg: to_json_binary(&KernelQueryMsg::KeyAddress {
                        key: ADO_DB_KEY.to_string(),
                    })?,
                }))?;

            // Get the sender's Code ID
            let contract_info: ContractInfoResponse =
                deps.querier
                    .query(&QueryRequest::Wasm(WasmQuery::ContractInfo {
                        contract_addr: info.sender.to_string(),
                    }))?;

            let sender_code_id = contract_info.code_id;

            // We query the ADO type in the adodb, it will return an error if the sender's Code ID doesn't exist.
            AOSQuerier::verify_code_id(&deps.querier, &adodb_address, sender_code_id)
        }
    }
```
The main task is to check the legitimacy of `AMPCtx.origin` and `AMPCtx.previous_sender`
There are three cases
1. sender == kernel_address -> pass (trusted by default, not malicious)
2. sender == ADO type in the adodb -> pass (trusted by default, not malicious)
3. sender == user (user submits AMPReceive directly) -> check `AMPCtx.origin == sender

In the third case, only `AMPCtx.origin == user` is checked and there is no restriction on `AMPCtx.previous_sender == user`.
So the user can submit `ExecuteMsg::AMPReceive` and specify `previous_sender` as they wish.
## Impact

If `AMPCtx.previous_sender` can be specified arbitrarily, security checks that depend on it will have security implications
Example: `ExecuteContext.contains_sender()`
```rust
    pub fn contains_sender(&self, addr: &str) -> bool {
        if self.info.sender == addr {
            return true;
        }
        match &self.amp_ctx {
            None => false,
@>          Some(ctx) => ctx.ctx.get_origin() == addr || ctx.ctx.get_previous_sender() == addr,
        }
    }
```
The one that currently has the ability to determine permissions using this method is `andromeda-cw721`.
```rust
fn execute_mint(
    ctx: ExecuteContext,
    token_id: String,
    token_uri: Option<String>,
    owner: String,
    extension: TokenExtension,
) -> Result<Response, ContractError> {
    let minter = ANDR_MINTER
        .load(ctx.deps.storage)?
        .get_raw_address(&ctx.deps.as_ref())?;
    ensure!(
@>      ctx.contains_sender(minter.as_str())
            | is_context_permissioned_strict(
                ctx.deps.storage,
                &ctx.info,
                &ctx.env,
                &ctx.amp_ctx,
                MINT_ACTION
            )?,
        ContractError::Unauthorized {}
    );
```
## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/packages/std/src/amp/messages.rs#L297
## Tool used

Manual Review

## Recommendation
```diff
    pub fn verify_origin(&self, info: &MessageInfo, deps: &Deps) -> Result<(), ContractError> {
        let kernel_address = ADOContract::default().get_kernel_address(deps.storage)?;
-       if info.sender == self.ctx.origin || info.sender == kernel_address {
+       if (info.sender == self.ctx.origin && info.sender == self.ctx.previous_sender) || info.sender == kernel_address { 
            Ok(())
        } else {
            let adodb_address: Addr =
                deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                    contract_addr: kernel_address.to_string(),
                    msg: to_json_binary(&KernelQueryMsg::KeyAddress {
                        key: ADO_DB_KEY.to_string(),
                    })?,
                }))?;
```

# Issue H-3: Attacker can freeze users first rewards 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/50 

## Found by 
J4X\_
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

# Issue H-4: Rewards will get stuck if `withdrawaddrenabled` is set to false on the target chain 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/52 

## Found by 
J4X\_
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

# Issue H-5: Staked tokens can never be retrieved due to old `cosmos-sdk` version on targeted chains 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/53 

## Found by 
J4X\_
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

# Issue M-1: execute_stake() without setting DistributionMsg::SetWithdrawAddress, partial reward may remain in the contract 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/42 

## Found by 
bin2chen
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

# Issue M-2: If WithdrawAddrEnabled = false, execute_claim() will fail 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/43 

## Found by 
bin2chen
## Summary
Currently, contracts that execute `execute_claim()` set `DistributionMsg::SetWithdrawAddress` first.
If `WithdrawAddrEnabled = false`, the execution will not succeed and the `claim` will not be executed.

## Vulnerability Detail
Currently the contract executes claims rewards by setting `DistributionMsg::SetWithdrawAddress` first.
```rust
fn execute_claim(
    ctx: ExecuteContext,
    validator: Option<Addr>,
    recipient: Option<AndrAddr>,
) -> Result<Response, ContractError> {
...
    let res = Response::new()
@>      .add_message(DistributionMsg::SetWithdrawAddress {
            address: recipient.to_string(),
        })
        .add_message(DistributionMsg::WithdrawDelegatorReward {
            validator: validator.to_string(),
        })
        .add_attribute("action", "validator-claim-reward")
        .add_attribute("recipient", recipient)
        .add_attribute("validator", validator.to_string());

    Ok(res)
}
```

If the configuration `WithdrawAddrEnabled` is changed to `false`, setting `DistributionMsg::SetWithdrawAddress` will fail!
This will prevent the execution of the `claim`
https://github.com/cosmos/cosmos-sdk/tree/main/x/distribution#msgsetwithdrawaddress
> # MsgSetWithdrawAddress
>By default, the withdraw address is the delegator address. To change its withdraw address, a delegator must send a MsgSetWithdrawAddress message. Changing the withdraw address is possible **only if the parameter WithdrawAddrEnabled is set to true.**
```rust
func (k Keeper) SetWithdrawAddr(ctx context.Context, delegatorAddr sdk.AccAddress, withdrawAddr sdk.AccAddress) error
 if k.blockedAddrs[withdrawAddr.String()] {
  fail with "`{withdrawAddr}` is not allowed to receive external funds"
 }

 if !k.GetWithdrawAddrEnabled(ctx) {
  fail with `ErrSetWithdrawAddrDisabled`
 }

 k.SetDelegatorWithdrawAddr(ctx, delegatorAddr, withdrawAddr)
```



## Impact
can't  claim reward
## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L231
## Tool used

Manual Review

## Recommendation

when set `DistributionMsg::SetWithdrawAddress` , `SubMsg` using `ReplyOn.Error`, which is ignored when this message returns an error, to avoid the whole `execute_claim` from failing!

# Issue M-3: if Slash Validator occurs, UNSTAKING_QUEUE's unstake amount will not be accurate 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/44 

## Found by 
J4X\_, bin2chen
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

# Issue M-4: is_permissioned() may underflow 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/46 

## Found by 
Kow, bin2chen, g
## Summary
`is_permissioned()`, if `permissioned_action` is changed from `true` to `false`.
Users who were previously set to `Permission::Limited` may be `underflowed`.

## Vulnerability Detail
`is_permissioned()` is used to implement the permission check, which is implemented as follows
```rust
    pub fn is_permissioned(
...
        let permission = Self::get_permission(store, action_string.clone(), actor_string.clone())?;
@>      let permissioned_action = self
            .permissioned_actions
            .may_load(store, action_string.clone())?
            .unwrap_or(false);
        match permission {
            Some(mut permission) => {
                ensure!(
                    permission.is_permissioned(&env, permissioned_action),
                    ContractError::Unauthorized {}
                );

                // Consume a use for a limited permission
@>              if let Permission::Limited { .. } = permission {
@>                  permission.consume_use()?;
                    permissions().save(
                        store,
                        (action_string.clone() + actor_string.as_str()).as_str(),
                        &PermissionInfo {
                            action: action_string,
                            actor: actor_string,
                            permission,
                        },
                    )?;
                }

                Ok(())
            }

```

From the above code, we know that if the user has `Permission::Limited `, it will be reduced by 1 regardless of whether the `action` needs permission or not.
This `permission.consume_use()` can be `underflow` in the following cases

1. `action1` needs permission at first, i.e. `permissioned_action=true`
2. the administrator grants `alice` `Permission::Limited` permission and ` Limited.uses = 3`.
3. alice used up 3 times, `Limited.uses = 0`
4. the administrator adjusts the `action1` permissions configuration to not require permissions, i.e. `permissioned_action=false`
5. at this point `alice` wants to execute `action1`, but `is_permissioned(Alice,action1`) will revert,
because `permission.consume_use()` will be executed, resulting in underflow (Limited.uses ==0 ,Limited.uses-=1)

## Impact
`is_permissioned()` may underflow, causing the permission check to fail and the corresponding action to can't be executed

## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/packages/std/src/ado_contract/permissioning.rs#L71
## Tool used

Manual Review

## Recommendation

only `permissioned_action==true`, then execute `permission.consume_use()`. 

```diff
    pub fn is_permissioned(
...
            Some(mut permission) => {
                ensure!(
                    permission.is_permissioned(&env, permissioned_action),
                    ContractError::Unauthorized {}
                );

                // Consume a use for a limited permission
+          if permissioned_action {
                if let Permission::Limited { .. } = permission {
                    permission.consume_use();
                    permissions().save(
                        store,
                        (action_string.clone() + actor_string.as_str()).as_str(),
                        &PermissionInfo {
                            action: action_string,
                            actor: actor_string,
                            permission,
                        },
                    )?;
                }
+           }
                Ok(())
            }
```

# Issue M-5: is_permissioned() It doesn't make sense to have permissions by default after Blacklisted expires. 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/47 

## Found by 
bin2chen, g
## Summary
in `is_permissioned()`, returns `true` if `Permission::Blacklisted` has expired
it is not correct

## Vulnerability Detail
in `is_permissioned()` to determine if a permission is granted.
```rust
    pub fn is_permissioned(&self, env: &Env, strict: bool) -> bool {
        match self {
            Self::Blacklisted(expiration) => {
                if let Some(expiration) = expiration {
                    if expiration.is_expired(&env.block) {
@>                       return true;
                    }
                }
                false
            }
            Self::Limited { expiration, uses } => {
                if let Some(expiration) = expiration {
                    if expiration.is_expired(&env.block) {
@>                      return !strict;
                    }
                }
                if *uses == 0 {
                    return !strict;
                }
                true
            }
            Self::Whitelisted(expiration) => {
                if let Some(expiration) = expiration {
                    if expiration.is_expired(&env.block) {
                        return !strict;
                    }
                }
                true
            }
        }
    }
```
The current implementation returns `true` if the blacklist has expired, regardless of `strict`.
The following scenarios are problematic

1. `action1` doesn't need permission at the beginning, i.e.: strict = false
2. the administrator has blacklisted `alice` for 1 month, i.e.: alice has Permission::Blacklisted
3. after some time (> 1 month)
4. the administrator changes the permissions configuration of `action1` to `action1` requires permissions, i.e.: strict = true
5. at this point `is_permissioned(alice)` returns true, and `alice` becomes permitted by default, which is not correct!


It is reasonable to return `!strict` when it expires, just like `Limited` and `Whitelisted`.

## Impact

`Permission::Blacklisted` expires and returns `true`, causing users to have permissions that shouldn't have them.

## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/packages/std/src/ado_base/permissioning.rs#L55
## Tool used

Manual Review

## Recommendation
```diff
    pub fn is_permissioned(&self, env: &Env, strict: bool) -> bool {
        match self {
            Self::Blacklisted(expiration) => {
                if let Some(expiration) = expiration {
                    if expiration.is_expired(&env.block) {
-                       return true;
+                       return  !strict;
                    }
                }
                false
            }
            Self::Limited { expiration, uses } => {
                if let Some(expiration) = expiration {
                    if expiration.is_expired(&env.block) {
                        return !strict;
                    }
                }
                if *uses == 0 {
                    return !strict;
                }
                true
            }
```

# Issue M-6: claim_batch() last_claimed_release_time is set too large when the balance is not enough 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/48 

## Found by 
bin2chen
## Summary

`claim_batch()` last_claimed_release_time is incorrectly set when the balance is not enough, causing the user to wait for a long time again to get their funds back.


## Vulnerability Detail
`claim_batch()` is used to retrieve funds

```rust
fn claim_batch(
...
    let current_time = env.block.time.seconds();
    ensure!(
        batch.lockup_end <= current_time,
        ContractError::FundsAreLocked {}
    );
    let amount_per_claim = batch.release_amount.get_amount(batch.amount)?;

@>  let total_amount = AssetInfo::native(config.denom.to_owned())
        .query_balance(querier, env.contract.address.to_owned())?;

    let elapsed_time = current_time - batch.last_claimed_release_time;
    let num_available_claims = elapsed_time / batch.release_unit;

    let number_of_claims = cmp::min(
        number_of_claims.unwrap_or(num_available_claims),
        num_available_claims,
    );

    let amount_to_send = amount_per_claim * Uint128::from(number_of_claims);
@>  let amount_available = cmp::min(batch.amount - batch.amount_claimed, total_amount);

    let amount_to_send = cmp::min(amount_to_send, amount_available);

    // We dont want to update the last_claim_time when there are no funds to claim.
    if !amount_to_send.is_zero() {
        batch.amount_claimed += amount_to_send;
@>      batch.last_claimed_release_time += number_of_claims * batch.release_unit;
    }

    Ok(amount_to_send)
}

```

We will calculate the amount of funds that can be claimed based on the elapsed time `elapsed_time = current_time - batch.last_claimed_release_time`.

There is a limitation: if the current balance is not enough, only the current balance can be claimed.

But the problem is: `last_claimed_release_time` is still modified to the current time.

This leads to a problem: suppose 1 token can be claimed in 1 day.

1. after 1 year, the user executes `claim_batch()` , expecting to get 365 back.
2. But the current balance is only 10, so `10` is claimed.
3. `last_claimed_release_time` is changed to `now`.

So the user has to wait for another year to get the remaining amount back.

We should dynamically adjust the `last_claimed_release_time` based on the actual amount of money retrieved.

## Impact

If the current balance is insufficient, the user will have to wait for a long time for the funds to be retrieved

## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L483
## Tool used

Manual Review

## Recommendation

Recalculate `number_of_claims` based on `amount_to_send`.


```diff
fn claim_batch(
...

    if !amount_to_send.is_zero() {
        batch.amount_claimed += amount_to_send;
+      let number_of_claims = .... recalculate by amount_to_send
        batch.last_claimed_release_time += number_of_claims * batch.release_unit;
    }

    Ok(amount_to_send)
}

```

# Issue M-7: execute_claim() possible loss of accuracy or even inability to retrieve funds 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/49 

## Found by 
bin2chen
## Summary
`claim_batch()` dividing and then multiplying may result in loss of precision, and in the worst case may not retrieve funds
## Vulnerability Detail
`claim_batch()` is used to calculate the amount of money that can be retrieved.
```rust
fn claim_batch(
    querier: &QuerierWrapper,
    env: &Env,
    batch: &mut Batch,
    config: &Config,
    number_of_claims: Option<u64>,
) -> Result<Uint128, ContractError> {
    let current_time = env.block.time.seconds();
    ensure!(
        batch.lockup_end <= current_time,
        ContractError::FundsAreLocked {}
    );
@>  let amount_per_claim = batch.release_amount.get_amount(batch.amount)?;

    let total_amount = AssetInfo::native(config.denom.to_owned())
        .query_balance(querier, env.contract.address.to_owned())?;

    let elapsed_time = current_time - batch.last_claimed_release_time;
    let num_available_claims = elapsed_time / batch.release_unit;

    let number_of_claims = cmp::min(
        number_of_claims.unwrap_or(num_available_claims),
        num_available_claims,
    );

@>  let amount_to_send = amount_per_claim * Uint128::from(number_of_claims);
    let amount_available = cmp::min(batch.amount - batch.amount_claimed, total_amount);

    let amount_to_send = cmp::min(amount_to_send, amount_available);

    // We dont want to update the last_claim_time when there are no funds to claim.
    if !amount_to_send.is_zero() {
        batch.amount_claimed += amount_to_send;
        batch.last_claimed_release_time += number_of_claims * batch.release_unit;
    }

    Ok(amount_to_send)
}
```
From the code above we know that the calculation is
1. amount_per_claim = batch.amount * release_amount (release_amount is Decimal, Precision = 1e18)
2. number_of_claims = elapsed_time / batch.release_unit
3. amount_to_send = amount_per_claim * number_of_claims

i.e.: `amount_to_send = (batch.amount * release_amount / 1e18) * number_of_claims`

Since it is dividing and then multiplying, it may lead to loss of precision, even amount_per_claim = 0
Assumption: it takes 5 years to claim 1 btc, 
batch.amount = 1e8 btc
release_unit = 1 second
release_amount = 1e8 * 1e18 / 157680000(seconds) / 1e8 = 6341958396 (6341958396 percent per second, precision 1e18)

Following the existing formula, divide and multiply. 

amount_to_send = (1e8 * 6341958396 / 1e18) * 157680000(seconds)  = 0

If modified to multiply before dividing:

amount_to_send = (1e8 * 6341958396 * 157680000(seconds)  / 1e18 = 99999999

## Impact

`claim_batch()` dividing and then multiplying may result in a loss of precision, and in the worst case it may not be possible to retrieve the funds

## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L462
## Tool used

Manual Review

## Recommendation
In case of `WithdrawalType::Percentage`, multiply then divide
Example: `batch.amount * number_of_claims * release_amount / 1e18

# Issue M-8: Changes of the `UnbondingTime` are not accounted for 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/54 

## Found by 
J4X\_
## Summary

The `andromeda-validator-staking` contract allows the owner to stake and unstake tokens, adding unstaking entries to an `UNSTAKING_QUEUE`. The unstaking process is dependent on the `UnbondingTime` parameter of the chain, which can be changed by governance. If the `UnbondingTime` is reduced while unstakings are already queued, it can result in a denial-of-service (DoS) situation where newer entries cannot be withdrawn until older entries expire. This could lead to tokens being stuck in the contract for a significant period.

## Vulnerability Detail

The `andromeda-validator-staking` contract implements a way to allow the owner of the contract to stake tokens. When the owner of the contract wants to unstake tokens again he can do this by calling the `execute_unstake()` function. The contract will then, on response from the staking module, add an entry to the `UNSTAKING_QUEUE`. 

```rust
pub fn on_validator_unstake(deps: DepsMut, msg: Reply) -> Result<Response, ContractError> {
    let attributes = &msg.result.unwrap().events[0].attributes;
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

    Ok(Response::default())
}
```

Once the completion time has passed, the user can now call `execute_withdraw_fund()` to withdraw the funds. The function loops over the `UNSTAKING_QUEUE` and adds all unstakings until it fins one that has not expired. Afterwards all of the found expired unstakings are payed out to the user.

```rust
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
```
The completion time that the loop is based upon is the UnbondingTime which is one of the [params](https://docs.cosmos.network/v0.47/build/modules/staking#parameters) of the x/staking module. The governance can change this parameter at any time via a [`MsgUpdateParams`](https://docs.cosmos.network/v0.47/build/modules/staking#msgupdateparams )message.

The issue occurs as the loop expects that for each item in it $item_n.completionTime >= item_{n-1}.completionTime$ . Unfortunately this is not the case if the governance reduces the `UnbondingTime`parameter while unstakings are already queued. In that case it can occur that $item_n.completionTime < item_{n-1}.completionTime$. This will result in $item_n$ being unable to withdraw until $item_{n-1}$ has expired. 

This DOS can be anwhere in the range from $0-UnbondingTime$. For most of the targeted chains the `UnbondingTime` is set to 21 days ( [Incetive, Archway and Terra](https://docs.andromedaprotocol.io/andromeda/platform-and-framework/deployed-contracts)). While it is not a reasonable scenario that the `UnbondingTime` will be reduced to 0, a deduction of 1-2 weeks is possible. The default value of the `UnbondingTime` is only [3 days](https://docs.cosmos.network/v0.47/build/modules/staking#parameters), and some other chains also user 1-2 weeks shorter unbonding times:
- [Axelar](https://atomscan.com/axelar/parameters) - 7 days
- [Bitcanna](https://atomscan.com/bitcanna/parameters) - 14 days
- [Stargaze](https://atomscan.com/stargaze/parameters) - 14 days 

Based on this we can assume that a reduction by 1-2 weeks is a possible scenario. As the protocol will not only be deployed on andromeda's own chain but also on multiple other cosmos chains, the Andromeda Governance has no possibility to prevent such a change if it occurs.
## Impact

The issue results in tokens getting stuck in the contract until the messages before them expire. This can result in a DOS of 1-2 weeks depending on the change of the `UnbondingTime`.

## Code Snippet

https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L256-L267

## Tool used

Manual Review

## Recommendation

We recommend adapting the loop to not break if the `payout_at > env.block.time`. Instead in that case it should just do nothing and go on to the next element. 

```rust
loop {
	match UNSTAKING_QUEUE.front(deps.storage).unwrap() {
		Some(UnstakingTokens { payout_at, .. }) if payout_at <= env.block.time => {
			if let Some(UnstakingTokens { fund, .. }) =
				UNSTAKING_QUEUE.pop_front(deps.storage)?
			{
				funds.push(fund)
			}
		}
		_ => continue,
	}
}
```

# Issue M-9: Slashing allows users to bypass the lockup period of vestings 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/55 

## Found by 
J4X\_
## Summary

The vesting module allows owners to create and manage multiple vestings, which can be claimed independently. The vestings are tracked using the `Batch` structure. However, if tokens are staked and the chosen validator is slashed, the protocol does not adjust the `amount` parameter in the `Batch` structure. This oversight allows users to claim the original total amount, even if some tokens were slashed, potentially leading to bypassing the lockup period of other vestings.

## Vulnerability Detail

The vesting module allows the owner to create multiple vestings, which should be claimable independently of each other. The vestings are tracked using the `Batch` structure.

```rust
pub struct Batch {
    /// The amount of tokens in the batch
    pub amount: Uint128,
    /// The amount of tokens that have been claimed.
    pub amount_claimed: Uint128,
    /// When the lockup ends.
    pub lockup_end: u64,
    /// How often releases occur.
    pub release_unit: u64,
    /// Specifies how much is to be released after each `release_unit`. If
    /// it is a percentage, it would be the percentage of the original amount.
    pub release_amount: WithdrawalType,
    /// The time at which the last claim took place in seconds.
    pub last_claimed_release_time: u64,
}
```

This struct's `amount` parameter tracks the total vesting. The `amount_claimed` increases on every claim until it reaches the `amount`. After that, no more tokens can be claimed. 

The protocol allows the owner/user to stake the tokens while they are vesting. By doing this, users can gain staking rewards while their vesting matures. The rewards can be claimed through the `execute_withdraw_rewards()`. 

The problem is that the chosen validator can be [slashed](https://docs.cosmos.network/main/build/modules/slashing#abstract) while the tokens are staked. If the selected validator is slashed, the tokens delegated to him will also get slashed. The protocol does not account for this, as even if the tokens are slashed, the `amount` of the vesting stays the same. As a result, the user, even after slashing, can claim the total `amount` of the batch. This is fine if only one batch is used, but it leads to issues if multiple batches are used. The slashed user can claim his total amount if multiple batches are used. The difference between his slashed amount and the actual amount will be taken from one of the other batches. This leads to issues if the other issue that the tokens are taken from is still in its lockup period, as this way, tokens will be taken from it before the `lockup_end` has been reached.

### Exemplary Scenario

To showcase this issue, we can use a simple example.
1. A vesting (`VestingA`) of 100 tokens is generated
2. The user stakes the tokens of `VestingA`
3. Another 100 token vesting batch (`VestingB`), which is locked for the next 10 years, gets added
4. The staked tokens get slashed by 20%
5. The user unstakes all his tokens again
6. `VestingA` matures
7. The user claims the full 100 tokens
8. There are now only 80 tokens left for `VestingB`

In this case, the user can recoup his slashing losses from a vesting still in lockup. This should never be possible.
## Impact

The issue results in a slashed user being able to funnel funds from a locked vesting into an unlocked vesting to recoup slashing losses.

## Code Snippet

https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-vesting/src/state.rs#L14-L28
## Tool used

Manual Review

## Recommendation

We recommend adapting the `amount` parameter of the `Batch` struct if the un-staked tokens are less than the staked ones. This mitigation is crucial as it ensures accurate accounting for slashing, thereby preventing the potential loss of tokens.

# Issue M-10: Staked tokens will get stuck after claim 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/57 

## Found by 
J4X\_
## Summary

The Andromeda protocol includes a vesting functionality allowing the owner to vest and stake tokens. However, if the owner attempts to claim vested tokens while still staked, the contract only transfers the unstaked amount, resetting the `batch.last_claimed_release_time`. This results in the staked tokens being locked until they are vested again, effectively extending the vesting period and causing a denial-of-service (DoS) scenario. The duration of this DoS is dependent on the `release_unit` time set in the `execute_create_batch()` function.

## Vulnerability Detail

The Andromeda protocol implements a vesting functionality. In the current implementation, the owner can vest tokens for himself, but this will be adapted to allow the owner to let tokens vest for other users. While those tokens are vesting, they can be staked by calling [`execute_delegate()`](https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L306), and the owner can withdraw their rewards by calling [`execute_withdraw_rewards()`](https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L422). 

The problem is that the owner/user can try to claim his tokens while they are staked. When the call occurs, the contract will take the minimum of its current balance and the tokens it should distribute. It will only transfer the minimum, not the actual amount.

```rust
let total_amount = AssetInfo::native(config.denom.to_owned())
	.query_balance(querier, env.contract.address.to_owned())?;

//Other calculations

let amount_to_send = amount_per_claim * Uint128::from(number_of_claims);
let amount_available = cmp::min(batch.amount - batch.amount_claimed, total_amount);

let amount_to_send = cmp::min(amount_to_send, amount_available);
```

This will result in the owner/user only receiving the tokens that are currently not staked and the `batch.last_claimed_release_time` being [reset](https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L483). As a result of this the users staked tokens (which he should be able to access) will be locked until they are vested once again, resulting in extending the intended vesting period.

###  Exemplary scenario

An exemplary scenario can describe the vulnerability more:

1. Vesting gets generated with a total of 1.2 billion tokens, of which 100 million are distributed monthly. (effectively vesting over one year)
2. The user decides to stake 900 million of these tokens
3. At the end of the year, the user calls `execute_claim()` to claim all tokens
4. The call passes, but the user only receives 300 million tokens as the rest are staked
5. `batch.last_claimed_release_time` is set to the current date
6. If the user unstakes his tokens now, he will still need to wait another nine months to be able to retrieve them fully

## Impact

If a user tries to claim his vesting while some of the tokens of that vesting are still staked, the staked tokens will become locked. The duration of this DOS is dependent on the time set in the `execute_create_batch()` function as `release_unit`. As vesting is usually done over multiple years, we can safely assume the DOS will be above seven days.

## Code Snippet

```rust
fn claim_batch(
    querier: &QuerierWrapper,
    env: &Env,
    batch: &mut Batch,
    config: &Config,
    number_of_claims: Option<u64>,
) -> Result<Uint128, ContractError> {
    let current_time = env.block.time.seconds();
    ensure!(
        batch.lockup_end <= current_time,
        ContractError::FundsAreLocked {}
    );
    let amount_per_claim = batch.release_amount.get_amount(batch.amount)?;

    let total_amount = AssetInfo::native(config.denom.to_owned())
        .query_balance(querier, env.contract.address.to_owned())?;

    let elapsed_time = current_time - batch.last_claimed_release_time;
    let num_available_claims = elapsed_time / batch.release_unit;

    let number_of_claims = cmp::min(
        number_of_claims.unwrap_or(num_available_claims),
        num_available_claims,
    );

    let amount_to_send = amount_per_claim * Uint128::from(number_of_claims);
    let amount_available = cmp::min(batch.amount - batch.amount_claimed, total_amount);

    let amount_to_send = cmp::min(amount_to_send, amount_available);

    // We dont want to update the last_claim_time when there are no funds to claim.
    if !amount_to_send.is_zero() {
        batch.amount_claimed += amount_to_send;
        batch.last_claimed_release_time += number_of_claims * batch.release_unit;
    }

    Ok(amount_to_send)
}
```

## Tool used

Manual Review

## Recommendation

We recommend adapting the `claim_batch()` to revert if `amount_available < amount_to_send`. Alternatively, it could also check how many tokens are transferred and only move the `last_claimed_release_time` up by `ceil(transferred_tokens/batch.release_unit)`. This way, the user would, at max, incur a DOS of one `batch.release_unit`.

# Issue M-11: Lockup of vestings or completion time can be bypassed due to missing check for staked tokens 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/58 

## Found by 
J4X\_
## Summary

The vesting module in the Andromeda protocol allows multiple vestings to be created. Currently restricted to the owner, it will be extended to any user. While tokens are vesting, they can be staked to earn rewards. However, the protocol does not account for the staked tokens when claiming vestings. This allows users to withdraw staked tokens, potentially circumventing the lockup period and withdrawing tokens from other vestings that are not yet matured. This issue results in the ability to bypass vesting schedules and access locked tokens prematurely.

## Vulnerability Detail

The vesting module allows for the creation of multiple vestings. This is restricted to the owner for now, but it will be extended to anyone. The current version can be used to proof lockup periods & vesting schedules to users. This is done by the owner depositing tokens into the contract and setting parameters for the vesting. While the tokens are vesting, they can be staked to a delegator to earn rewards by calling the [`execute_delegate()`](https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L306) function. The vestings are tracked using batch struct.

```rust
pub struct Batch {
    /// The amount of tokens in the batch
    pub amount: Uint128,
    /// The amount of tokens that have been claimed.
    pub amount_claimed: Uint128,
    /// When the lockup ends.
    pub lockup_end: u64,
    /// How often releases occur.
    pub release_unit: u64,
    /// Specifies how much is to be released after each `release_unit`. If
    /// it is a percentage, it would be the percentage of the original amount.
    pub release_amount: WithdrawalType,
    /// The time at which the last claim took place in seconds.
    pub last_claimed_release_time: u64,
}
```

The problem occurs because the batches do not account for how many of their tokens were staked. As a result, the recipient can still withdraw tokens from a vesting that is currently staked. This can be seen when looking at the function handling the claiming.

```rust
fn claim_batch(
    querier: &QuerierWrapper,
    env: &Env,
    batch: &mut Batch,
    config: &Config,
    number_of_claims: Option<u64>,
) -> Result<Uint128, ContractError> {
    let current_time = env.block.time.seconds();
    ensure!(
        batch.lockup_end <= current_time,
        ContractError::FundsAreLocked {}
    );
    let amount_per_claim = batch.release_amount.get_amount(batch.amount)?;

    let total_amount = AssetInfo::native(config.denom.to_owned())
        .query_balance(querier, env.contract.address.to_owned())?;

    let elapsed_time = current_time - batch.last_claimed_release_time;
    let num_available_claims = elapsed_time / batch.release_unit;

    let number_of_claims = cmp::min(
        number_of_claims.unwrap_or(num_available_claims),
        num_available_claims,
    );

    let amount_to_send = amount_per_claim * Uint128::from(number_of_claims);
    let amount_available = cmp::min(batch.amount - batch.amount_claimed, total_amount);

    let amount_to_send = cmp::min(amount_to_send, amount_available);

    // We dont want to update the last_claim_time when there are no funds to claim.
    if !amount_to_send.is_zero() {
        batch.amount_claimed += amount_to_send;
        batch.last_claimed_release_time += number_of_claims * batch.release_unit;
    }

    Ok(amount_to_send)
}
```

The vulnerability leads to further issues if multiple vestings exist. In that case, the user will actually be sent tokens from one of the other vestings, which are not currently staked. This is an issue as the other vesting from which the tokens will originate might still be in its lockup period, and the tokens should not be withdrawable.

### Exemplary scenario

1. `VestingA` (100 tokens) gets created with a `lockup_end` in 1 month and full claiming after that
2. User stakes all 100 tokens
3. `VestingB` (100 tokens) with `lockup_end` in 10 years is added
4.  One month passes, and `VestingA` matures
5. The user does not want to wait for the completion time when unstaking his tokens from `VestingA`, so he just calls to claim `VestingA` while they are still staked
6. As it is not checked which tokens are staked, the claim passes
7. The user has effectively bypassed the completion time/lockup period.

## Impact

This issue allows the recipient to circumvent the lockup duration of his vestings by withdrawing the tokens through another staked vesting.

## Code Snippet

## Tool used

Manual Review

## Recommendation

We recommend adding the parameter `staked_tokens` to the `batch` struct. 

```rust
pub struct Batch {
    /// The amount of tokens in the batch
    pub amount: Uint128,
    /// The amount of tokens that have been claimed.
    pub amount_claimed: Uint128,
    /// The amount of tokens that have been staked.
    pub amount_staked: Uint128, // <--- New variable
    /// When the lockup ends.
    pub lockup_end: u64,
    /// How often releases occur.
    pub release_unit: u64,
    /// Specifies how much is to be released after each `release_unit`. If
    /// it is a percentage, it would be the percentage of the original amount.
    pub release_amount: WithdrawalType,
    /// The time at which the last claim took place in seconds.
    pub last_claimed_release_time: u64,
}
```

This variable should be updated on each call to `executed_delegate()` and `execute_undelegate`. When a user tries to withdraw funds from his batch, the function must check if `amount - (amount_claimed + staked_tokens) >= tokens_to_withdraw`.  

```rust
fn claim_batch(
    querier: &QuerierWrapper,
    env: &Env,
    batch: &mut Batch,
    config: &Config,
    number_of_claims: Option<u64>,
) -> Result<Uint128, ContractError> {
    let current_time = env.block.time.seconds();
    ensure!(
        batch.lockup_end <= current_time,
        ContractError::FundsAreLocked {}
    );
    let amount_per_claim = batch.release_amount.get_amount(batch.amount)?;

    let total_amount = AssetInfo::native(config.denom.to_owned())
        .query_balance(querier, env.contract.address.to_owned())?;

    let elapsed_time = current_time - batch.last_claimed_release_time;
    let num_available_claims = elapsed_time / batch.release_unit;

    let number_of_claims = cmp::min(
        number_of_claims.unwrap_or(num_available_claims),
        num_available_claims,
    );

    let amount_to_send = amount_per_claim * Uint128::from(number_of_claims);
    let amount_available = cmp::min(batch.amount - (batch.amount_claimed + batch.amount_staked), total_amount); // <---- Changed LOC

    let amount_to_send = cmp::min(amount_to_send, amount_available);

    // We dont want to update the last_claim_time when there are no funds to claim.
    if !amount_to_send.is_zero() {
        batch.amount_claimed += amount_to_send;
        batch.last_claimed_release_time += number_of_claims * batch.release_unit;
    }

    Ok(amount_to_send)
}
```


# Issue M-12: Batch creation will break if vestings are opened to recipients 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/59 

## Found by 
J4X\_, cu5t0mPe0
## Summary

The `andromeda-vesting` contract allows the owner to create vestings (batches) for freezing tokens. The planned update will enable the recipient to claim or delegate tokens instead of the owner. However, this change introduces a conflict in the delegation process during batch creation, where the `execute_delegate()` function will check for both owner and recipient roles, causing it to always revert. This issue makes it impossible to create batches with direct delegation.

## Vulnerability Detail

The `andromeda-vesting` contract allows for creating vestings, aka `batches.` The current contract is fully restricted to the `owner`. Effectively it only allows the owner to freeze his tokens in vestings to recover them later. To include some real functionality, the team plans to adapt the functionality so that the owner still creates the batches, but they can be claimed or delegated by the recipient. This is also described in the contest description:

```txt
For the vesting contract the current recipient is the owner, this would be quite likely to be changed to be a recipient address and the delegation methods would be restricted to the recipient rather than the owner.
```

As per my communication with the team, the only change that will occur is that the restriction for the `owner` in the claiming and delegation functions will be replaced with a restriction for the `recipient`. For the following reason, it will be impossible to create vestings with a direct delegation. 

When a vesting gets created, it can only be done by the owner due to the following [check](https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L126-L129) 

```rust
fn execute_create_batch(
    ctx: ExecuteContext,
    lockup_duration: Option<u64>,
    release_unit: u64,
    release_amount: WithdrawalType,
    validator_to_delegate_to: Option<String>,
) -> Result<Response, ContractError> {
    let ExecuteContext {
        deps, info, env, ..
    } = ctx;
    ensure!(
        ADOContract::default().is_owner_or_operator(deps.storage, info.sender.as_str())?,
        ContractError::Unauthorized {}
    );
```

The batch creator can pass a `validator_to_delegate_to` parameter, resulting in the vested tokens being directly staked to a validator. To do this, the `execute_create_batch()` will call the [`execute_delegate()`](https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L188-L194) function.  This function is currently restricted to the [owner](https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L314-L317), but will be changed to be restricted to the recipient, as based on the contest description. The problem is that in this case the delegation as well as the creation of batches will always revert as it will check `info.sender == owner` and `info.sender == recipient`.

## Impact

This issue results in the creation of batches becoming impossible with a direct delegation. 
## Code Snippet

https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/bbbf73e5d1e4092ab42ce1f827e33759308d3786/andromeda-core/contracts/finance/andromeda-vesting/src/contract.rs#L314-L317
## Tool used

Manual Review

## Recommendation

We recommend adapting the `execute_delegate` function to be callable by the owner or recipient instead of just the owner.

```rust
fn execute_delegate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Option<Uint128>,
    validator: String,
) -> Result<Response, ContractError> {
    let sender = info.sender.to_string();
    ensure!(
        ADOContract::default().is_contract_owner(deps.storage, &sender)? || sender ==  recipient,
        ContractError::Unauthorized {}
    );
```

# Issue M-13: set_permission() using string splicing may cause key conflicts 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/69 

## Found by 
bin2chen
## Summary
set_permission() uses string splicing, which may lead to key conflicts and security risks.
## Vulnerability Detail
The `set_permission()` is used to set permissions with the following code.
```rust
    pub fn set_permission(
        store: &mut dyn Storage,
        action: impl Into<String>,
        actor: impl Into<String>,
        permission: Permission,
    ) -> Result<(), ContractError> {
        let action = action.into();
        let actor = actor.into();
@>      let key = action.clone() + &actor;
        permissions().save(
            store,
            &key,
            &PermissionInfo {
                action,
                actor,
                permission,
            },
        )?;
        Ok(())
    }
```

Using string splicing may lead to key conflicts
Example: "abc+efg" = "ab "+"cefg"

`action`: is arbitrary
`actor`: is an addr, this address is also not guaranteed for string length and content
`cosmwasm-std.address.rs`
>// A human readable address.
///
/// In Cosmos, this is typically bech32 encoded. But for multi-chain smart contracts no /// assumptions should be made.
/// Assumptions should be made other than being UTF-8 encoded and of reasonable length.
///


Because of the correct permissions, security should be paramount, and any potential pitfalls need to be avoided.

## Impact

Possible maliciously constructed key conflicts that could lead to security risks.

## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/packages/std/src/ado_contract/permissioning.rs#L166
## Tool used

Manual Review

## Recommendation

Don't use string splicing as a key;  Recommended Use MultiIndex

# Issue M-14: execute_withdraw_fund() Funds arrive at End-Block, so the time judgment should be > instead of >= 

Source: https://github.com/sherlock-audit/2024-05-andromeda-ado-judging/issues/70 

## Found by 
bin2chen
## Summary
`execute_withdraw_fund()` uses `env.block.time>=payout_at` to determine that the funds are in the contract.
but the funds actual arrival occurs at `End-Block`, so the current time is not yet available.

## Vulnerability Detail
After `execute_unstake()` we write the `completion_time` to `UNSTAKING_QUEUE`.
```rust
    UNSTAKING_QUEUE.push_back(deps.storage, &UnstakingTokens { fund, payout_at })? ;
```
When executing `execute_withdraw_fund()`, we use `env.block.time>=payout_at` to determine if the fund has arrived or not
```rust
fn execute_withdraw_fund(ctx: ExecuteContext) -> Result<Response, ContractError> {
...
        match UNSTAKING_QUEUE.front(deps.storage).unwrap() {
            Some(UnstakingTokens { payout_at, .. }) if payout_at <= env.block.time => {
                if let Some(UnstakingTokens { fund, .. }) =
                    UNSTAKING_QUEUE.pop_front(deps.storage)?
                {
```

But with `payout_at == env.block.time`, the funds don't actually get there
Because the `hooks` are executed at `End-Block` and the funds are only credited to the contract
https://github.com/cosmos/cosmos-sdk/tree/b03a2c6b0a4ad3794e2d50dd1354c7022cdd5826/x/staking#end-block
>## End-Block
>Unbonding Delegations
>- transfer the balance coins to the delegator's wallet address

## Impact
1. `execute_withdraw_fund()` may be revert due to insufficient funds, causing `UNSTAKING_QUEUE[0..i]`, which should have succeeded earlier, to fail as well.

2. or there may be other remaining funds (not belonging to this queue) that will be used up

## Code Snippet
https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/finance/andromeda-validator-staking/src/contract.rs#L258
## Tool used

Manual Review

## Recommendation
```diff
fn execute_withdraw_fund(ctx: ExecuteContext) -> Result<Response, ContractError> {
    let ExecuteContext {
        deps, info, env, ..
    } = ctx;

    // Ensure sender is the contract owner
    ensure!(
        ADOContract::default().is_contract_owner(deps.storage, info.sender.as_str())?,
        ContractError::Unauthorized {}
    );

    let mut funds = Vec::<Coin>::new();
    loop {
        match UNSTAKING_QUEUE.front(deps.storage).unwrap() {
-           Some(UnstakingTokens { payout_at, .. }) if payout_at <= env.block.time => {
+           Some(UnstakingTokens { payout_at, .. }) if payout_at < env.block.time => {
                if let Some(UnstakingTokens { fund, .. }) =
                    UNSTAKING_QUEUE.pop_front(deps.storage)?
                {
                    funds.push(fund)
                }
            }
            _ => break,
        }
    }
```

