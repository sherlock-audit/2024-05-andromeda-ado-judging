Great Leather Tarantula

high

# verify_origin() previous_sender may be forged

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