Great Leather Tarantula

Medium

# execute_claim() possible loss of accuracy or even inability to retrieve funds

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