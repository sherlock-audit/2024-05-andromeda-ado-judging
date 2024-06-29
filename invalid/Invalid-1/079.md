Crazy Silver Anteater

medium

# App Components can use older ADO versions

## Summary
When instantiating an App ADO, its components are also instantiated. The code used for the component will be based on its ADO type fetched from the ADODB. The ADO type, however, can refer to an old version of the ADO.

## Vulnerability Detail

When the App ADO instantiates components, it uses `generate_instantiate_msg()` to do that.

ref: https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/packages/std/src/ado_contract/instantiate.rs#L8-L36
```rust
pub fn generate_instantiate_msg(
    // ... snip ...
) -> Result<SubMsg, ContractError> {
    match self.get_code_id(storage, querier, &ado_type) {
        // ... snip ...
    }
}
```

It identifies what code ID to use for the component with `get_code_id()` which fetches the code ID for a given ADO type from the ADODB. The query for the code ID is handled by `query_code_id()` in the ADODB.

ref: https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/os/andromeda-adodb/src/contract.rs#L327-L330
```rust
fn query_code_id(deps: Deps, key: String) -> Result<u64, ContractError> {
    let code_id = read_code_id(deps.storage, &ADOVersion::from_string(key))?;
    Ok(code_id)
}
```

The key used for the query is the ADO type which can look like the following:
1. "ado_type"
2. "ado_type@0.1.0"
3. "ado_type@latest"

ref: https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/os/andromeda-adodb/src/state.rs#L46-L53
```rust
pub fn read_code_id(storage: &dyn Storage, ado_version: &ADOVersion) -> StdResult<u64> {
    if ado_version.get_version() == "latest" {
        let (_version, code_id) = read_latest_code_id(storage, ado_version.get_type())?;
        Ok(code_id)
    } else {
        CODE_ID.load(storage, ado_version.as_str())
    }
}
```

The code ID of any ADO version that exists in the ADODB can then be fetched.

## Impact
Users can create Apps with buggy older versions of ADOs. Note that the ADODB does not remove older published versions. It should not be possible to deploy Apps with older buggy components.

## Code Snippet
- https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/packages/std/src/ado_contract/instantiate.rs#L8-L36
- https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/os/andromeda-adodb/src/contract.rs#L327-L330
- https://github.com/sherlock-audit/2024-05-andromeda-ado/blob/main/andromeda-core/contracts/os/andromeda-adodb/src/state.rs#L46-L53

## Tool used
Manual Review

## Recommendation
Consider restricting the ADO type in `generate_instantiate_msg()` to only fetch the latest code_id of that ADO type. 