Radiant Burlap Gibbon

Medium

# Batch creation will break if vestings are opened to recipients

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