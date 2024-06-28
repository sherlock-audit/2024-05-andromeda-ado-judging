Great Leather Tarantula

Medium

# is_permissioned() It doesn't make sense to have permissions by default after Blacklisted expires.

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