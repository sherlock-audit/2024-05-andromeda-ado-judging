Crazy Silver Anteater

medium

# Outaded versions of ADO contracts are considered valid senders

## Summary
AMP messaging treats ADOs as valid senders. However, even outdated versions of ADO contracts are accepted as valid senders.

## Vulnerability Detail
AMP messaging uses `verify_origin()` to validate the sender of an AMP packet. A sender is valid if:

1. The origin matches the sender
2. The sender is the kernel
3. The sender has a code ID stored within the ADODB (and as such is a valid ADO)

The code ID of the sender is validated by calling the ADODB to check if its storage contains the specified code ID.

ref: https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/packages/std/src/amp/messages.rs#L295-L320
```rust
AOSQuerier::verify_code_id(&deps.querier, &adodb_address, sender_code_id)
```

ref: https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/packages/std/src/os/aos_querier.rs#L87-L100
```rust
pub fn verify_code_id(
    querier: &QuerierWrapper,
    adodb_addr: &Addr,
    code_id: u64,
) -> Result<(), ContractError> {
    let key = AOSQuerier::get_map_storage_key("ado_type", &[code_id.to_string().as_bytes()])?;
    let verify: Option<String> = AOSQuerier::query_storage(querier, adodb_addr, &key)?;

    if verify.is_some() {
        Ok(())
    } else {
        Err(ContractError::Unauthorized {})
    }
}
```

The ADODB's raw storage is queried for the code ID in the `"ado_type"` storage namespace. That storage namespace only gets [written to](https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/os/andromeda-adodb/src/contract.rs#L158) when a new ADO version gets published. Older ADO versions do not get removed from storage. 

## Impact
Older versions of ADO contracts are still allowed to interact with newer versions of ADO contracts. Interactions between older and newer ADOs are untested and can open up vulnerabilities that do not exist in the latest ADO contracts.

## Code Snippet
- https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/packages/std/src/amp/messages.rs#L295-L320
- https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/packages/std/src/os/aos_querier.rs#L87-L100
- https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/os/andromeda-adodb/src/contract.rs#L158

## Tool used
Manual Review

## Recommendation
Consider restricting access to only the latest code IDs of each ADO type. 