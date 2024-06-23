Great Leather Tarantula

medium

# is_permissioned() may underflow

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
