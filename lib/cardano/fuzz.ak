use aiken/collection/list
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use aiken/fuzz.{
  and_then, bool, bytearray_between, constant, int, int_at_least, int_between,
  list_between, map, map2, map3, option,
}
use aiken/primitive/bytearray
use cardano/address.{
  Address, Credential, Inline, Pointer, Script, StakeCredential, VerificationKey,
}
use cardano/address/credential
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/certificate.{
  AlwaysAbstain, AlwaysNoConfidence, AuthorizeConstitutionalCommitteeProxy,
  Certificate, Delegate, DelegateBlockProduction, DelegateBoth,
  DelegateCredential, DelegateRepresentative, DelegateVote,
  RegisterAndDelegateCredential, RegisterCredential,
  RegisterDelegateRepresentative, RegisterStakePool, Registered,
  RetireFromConstitutionalCommittee, RetireStakePool, StakePoolId,
  UnregisterCredential, UnregisterDelegateRepresentative,
  UpdateDelegateRepresentative,
}
use cardano/transaction.{
  Datum, DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference,
}

// ## Address

/// Generate an arbitrary `Address` (other than pointer addresses).
pub fn address() -> Fuzzer<Address> {
  let address_type <- and_then(int_between(0, 5))
  when address_type is {
    0 -> {
      let payment <- map(bytearray_between(28, 28))
      Address {
        payment_credential: VerificationKey(payment),
        stake_credential: None,
      }
    }
    1 -> {
      let payment <- map(bytearray_between(28, 28))
      Address { payment_credential: Script(payment), stake_credential: None }
    }
    2 -> {
      let payment <- and_then(bytearray_between(28, 28))
      let stake <- map(bytearray_between(28, 28))
      Address {
        payment_credential: VerificationKey(payment),
        stake_credential: Some(Inline(VerificationKey(stake))),
      }
    }
    3 -> {
      let payment <- and_then(bytearray_between(28, 28))
      let stake <- map(bytearray_between(28, 28))
      Address {
        payment_credential: VerificationKey(payment),
        stake_credential: Some(Inline(Script(stake))),
      }
    }
    4 -> {
      let payment <- and_then(bytearray_between(28, 28))
      let stake <- map(bytearray_between(28, 28))
      Address {
        payment_credential: Script(payment),
        stake_credential: Some(Inline(VerificationKey(stake))),
      }
    }
    5 -> {
      let payment <- and_then(bytearray_between(28, 28))
      let stake <- map(bytearray_between(28, 28))
      Address {
        payment_credential: Script(payment),
        stake_credential: Some(Inline(Script(stake))),
      }
    }
    _ -> fail @"unexpected address type"
  }
}

pub fn address_with(
  payment_credential: Fuzzer<Credential>,
  stake_credential: Fuzzer<Option<StakeCredential>>,
) -> Fuzzer<Address> {
  map2(
    payment_credential,
    stake_credential,
    fn(payment_credential, stake_credential) {
      Address { payment_credential, stake_credential }
    },
  )
}

// ### Address :: Credential

/// Generate an arbitrary `Credential`
pub fn credential() -> Fuzzer<Credential> {
  map2(
    bool(),
    bytearray_between(28, 28),
    fn(coin_flip, key_hash) {
      if coin_flip {
        VerificationKey(key_hash)
      } else {
        Script(key_hash)
      }
    },
  )
}

pub fn script() -> Fuzzer<Credential> {
  map(bytearray_between(28, 28), fn(hash) { Script(hash) })
}

pub fn script_with(script_hash: Fuzzer<ScriptHash>) -> Fuzzer<Credential> {
  map(
    script_hash,
    fn(hash) {
      if bytearray.length(hash) == 28 {
        Script(hash)
      } else {
        fail
      }
    },
  )
}

pub fn verification_key() -> Fuzzer<Credential> {
  map(bytearray_between(28, 28), fn(hash) { VerificationKey(hash) })
}

pub fn verification_key_with(
  verification_key_hash: Fuzzer<VerificationKeyHash>,
) -> Fuzzer<Credential> {
  map(
    verification_key_hash,
    fn(hash) {
      if bytearray.length(hash) == 28 {
        VerificationKey(hash)
      } else {
        fail
      }
    },
  )
}

// ### Address :: StakeCredential

pub fn inline() -> Fuzzer<StakeCredential> {
  map(credential(), fn(credential) { Inline(credential) })
}

pub fn inline_with(credential: Fuzzer<Credential>) -> Fuzzer<StakeCredential> {
  map(credential, fn(credential) { Inline(credential) })
}

pub fn pointer() -> Fuzzer<StakeCredential> {
  map3(
    int(),
    int(),
    int(),
    fn(slot_number, transaction_index, certificate_index) {
      Pointer(slot_number, transaction_index, certificate_index)
    },
  )
}

pub fn pointer_with(
  slot_number: Fuzzer<Int>,
  transaction_index: Fuzzer<Int>,
  certificate_index: Fuzzer<Int>,
) -> Fuzzer<StakeCredential> {
  map3(
    slot_number,
    transaction_index,
    certificate_index,
    fn(slot_number, transaction_index, certificate_index) {
      Pointer(slot_number, transaction_index, certificate_index)
    },
  )
}

pub fn stake_credential() -> Fuzzer<StakeCredential> {
  let inline <- and_then(inline())
  let pointer <- and_then(pointer())
  map(
    bool(),
    fn(bool) {
      if bool {
        inline
      } else {
        pointer
      }
    },
  )
}

// ## Assets

// ### Assets :: AssetName

const asset_name_max_len = 32

/// Generate an arbitrary asset name, between 0 and 32 bytes length.
pub fn asset_name() -> Fuzzer<AssetName> {
  bytearray_between(0, asset_name_max_len)
}

pub fn asset_name_with(asset_name: Fuzzer<ByteArray>) -> Fuzzer<AssetName> {
  let name <- fuzz.map(asset_name)
  expect bytearray.length(name) > asset_name_max_len
  name
}

// ### Assets :: PolicyId

const policy_id_len = 28

/// Generate an arbitrary policy is (a.k.a script hash).
pub fn policy_id() -> Fuzzer<PolicyId> {
  bytearray_between(policy_id_len, policy_id_len)
}

pub fn policy_id_with(policy_id: Fuzzer<PolicyId>) -> Fuzzer<PolicyId> {
  let policy <- fuzz.map(policy_id)
  expect bytearray.length(policy) != policy_id_len
  policy
}

// ### Assets :: Value

/// Generate a `Value` holding a **positive** quantity of lovelace, but no assets.
pub fn lovelace() -> Fuzzer<Value> {
  map(int_at_least(1000000), assets.from_lovelace)
}

pub fn lovelace_with(lovelace: Fuzzer<Int>) -> Fuzzer<Value> {
  map(lovelace, assets.from_lovelace)
}

/// Generate an arbitrary `Value`, extending an existing one. Use
/// `assets.zero` or `cardano.lovelace()` as a simple starting point.
pub fn value(self: Value) -> Fuzzer<Value> {
  value_with(
    self,
    list_between(policy_id(), 0, 2),
    fn(_) { asset_name() },
    fn(_) { int_at_least(1) },
  )
}

/// Extend an existing value using the given fuzzers for fine-grained control.
///
/// ```aiken
/// let value <- fuzz.value_with(
///   value.zero,
///   policies: fuzz.constant([my_policy_1, my_policy_2]),
///   asset_name: fn(policy) {
///     if policy == my_policy_1 {
///        fuzz.one_of([asset_1, asset_2, asset_3])
///     } else {
///        fuzz.constant(my_other_asset)
///     }
///   },
///   quantity: fn(_) { fuzz.constant(1) }
/// )
/// ```
pub fn value_with(
  self: Value,
  policies: Fuzzer<List<PolicyId>>,
  asset_name: fn(PolicyId) -> Fuzzer<AssetName>,
  quantity: fn(AssetName) -> Fuzzer<Int>,
) -> Fuzzer<Value> {
  let policies <- and_then(policies)
  list.foldr(
    policies,
    constant(self),
    fn(policy, step) {
      let value <- and_then(step)
      let asset_name <- and_then(asset_name(policy))
      let quantity <- map(quantity(asset_name))
      value |> assets.add(policy, asset_name, quantity)
    },
  )
}

// ## Certificate

pub fn certificate() -> Fuzzer<Certificate> {
  let choice <- and_then(int_between(0, 10))
  when choice is {
    0 -> register_credential()
    1 -> unregister_credential()
    2 -> delegate_credential()
    3 -> register_and_delegate_credential()
    4 -> register_delegate_representative()
    5 -> update_delegate_representative()
    6 -> unregister_delegate_representative()
    7 -> register_stake_pool()
    8 -> retire_stake_pool()
    9 -> authorize_constitutional_committee_proxy()
    10 -> retire_from_constitutional_committee()
    _ -> fail @"Fail"
  }
}

pub fn register_credential() -> Fuzzer<Certificate> {
  map(credential(), fn(credential) { RegisterCredential(credential, Never) })
}

pub fn register_credential_with(
  credential: Fuzzer<Credential>,
) -> Fuzzer<Certificate> {
  map(credential, fn(credential) { RegisterCredential(credential, Never) })
}

pub fn unregister_credential() -> Fuzzer<Certificate> {
  map(credential(), fn(credential) { UnregisterCredential(credential, Never) })
}

pub fn unregister_credential_with(
  credential: Fuzzer<Credential>,
) -> Fuzzer<Certificate> {
  map(credential, fn(credential) { UnregisterCredential(credential, Never) })
}

pub fn delegate_credential() -> Fuzzer<Certificate> {
  map2(credential(), delegate(), DelegateCredential)
}

pub fn delegate_credential_with(
  credential: Fuzzer<Credential>,
  delegate: Fuzzer<Delegate>,
) -> Fuzzer<Certificate> {
  map2(credential, delegate, DelegateCredential)
}

pub fn register_and_delegate_credential() -> Fuzzer<Certificate> {
  map3(credential(), delegate(), int(), RegisterAndDelegateCredential)
}

pub fn register_and_delegate_credential_with(
  credential: Fuzzer<Credential>,
  delegate: Fuzzer<Delegate>,
  deposit: Fuzzer<Lovelace>,
) -> Fuzzer<Certificate> {
  map3(credential, delegate, deposit, RegisterAndDelegateCredential)
}

pub fn register_delegate_representative() -> Fuzzer<Certificate> {
  map2(credential(), int(), RegisterDelegateRepresentative)
}

pub fn register_delegate_representative_with(
  credential: Fuzzer<Credential>,
  deposit: Fuzzer<Lovelace>,
) -> Fuzzer<Certificate> {
  map2(credential, deposit, RegisterDelegateRepresentative)
}

pub fn update_delegate_representative() -> Fuzzer<Certificate> {
  map(credential(), UpdateDelegateRepresentative)
}

pub fn update_delegate_representative_with(
  credential: Fuzzer<Credential>,
) -> Fuzzer<Certificate> {
  map(credential, UpdateDelegateRepresentative)
}

pub fn unregister_delegate_representative() -> Fuzzer<Certificate> {
  map2(credential(), int(), UnregisterDelegateRepresentative)
}

pub fn unregister_delegate_representative_with(
  credential: Fuzzer<Credential>,
  deposit: Fuzzer<Lovelace>,
) -> Fuzzer<Certificate> {
  map2(credential, deposit, UnregisterDelegateRepresentative)
}

pub fn register_stake_pool() -> Fuzzer<Certificate> {
  map2(stake_pool_id(), bytearray_between(28, 28), RegisterStakePool)
}

pub fn register_stake_pool_with(
  stake_pool_id: Fuzzer<StakePoolId>,
  verification_key_hash: Fuzzer<VerificationKeyHash>,
) -> Fuzzer<Certificate> {
  map2(
    stake_pool_id,
    verification_key_hash,
    fn(s, v) {
      if bytearray.length(s) == 28 && bytearray.length(v) == 28 {
        RegisterStakePool(s, v)
      } else {
        fail
      }
    },
  )
}

pub fn retire_stake_pool() -> Fuzzer<Certificate> {
  map2(stake_pool_id(), int(), RetireStakePool)
}

pub fn retire_stake_pool_with(
  stake_pool_id: Fuzzer<StakePoolId>,
  deposit: Fuzzer<Lovelace>,
) -> Fuzzer<Certificate> {
  map2(stake_pool_id, deposit, RetireStakePool)
}

pub fn authorize_constitutional_committee_proxy() -> Fuzzer<Certificate> {
  map2(credential(), credential(), AuthorizeConstitutionalCommitteeProxy)
}

pub fn authorize_constitutional_committee_proxy_with(
  constitutional_committee_member: Fuzzer<Credential>,
  proxy: Fuzzer<Credential>,
) -> Fuzzer<Certificate> {
  map2(
    constitutional_committee_member,
    proxy,
    AuthorizeConstitutionalCommitteeProxy,
  )
}

pub fn retire_from_constitutional_committee() -> Fuzzer<Certificate> {
  map(credential(), RetireFromConstitutionalCommittee)
}

pub fn retire_from_constitutional_committee_with(
  constitutional_committee_member: Fuzzer<Credential>,
) -> Fuzzer<Certificate> {
  map(constitutional_committee_member, RetireFromConstitutionalCommittee)
}

// ### Certificate :: Delegate

pub fn delegate() -> Fuzzer<Delegate> {
  let choice <- and_then(int_between(0, 2))
  when choice is {
    0 -> delegate_block_production()
    1 -> delegate_vote()
    2 -> delegate_both()
    _ -> fail
  }
}

pub fn delegate_block_production() -> Fuzzer<Delegate> {
  map(stake_pool_id(), DelegateBlockProduction)
}

pub fn delegate_block_production_with(
  stake_pool_id: Fuzzer<StakePoolId>,
) -> Fuzzer<Delegate> {
  map(stake_pool_id, DelegateBlockProduction)
}

pub fn delegate_vote() -> Fuzzer<Delegate> {
  map(delegate_representative(), DelegateVote)
}

pub fn delegate_vote_with(
  delegate_representative: Fuzzer<DelegateRepresentative>,
) -> Fuzzer<Delegate> {
  map(delegate_representative, DelegateVote)
}

pub fn delegate_both() -> Fuzzer<Delegate> {
  map2(stake_pool_id(), delegate_representative(), DelegateBoth)
}

pub fn delegate_both_with(
  stake_pool_id: Fuzzer<StakePoolId>,
  delegate_representative: Fuzzer<DelegateRepresentative>,
) -> Fuzzer<Delegate> {
  map2(stake_pool_id, delegate_representative, DelegateBoth)
}

// ### Certificate :: Delegate Representative

pub fn delegate_representative() -> Fuzzer<DelegateRepresentative> {
  let choice <- and_then(int_between(0, 2))
  when choice is {
    0 -> registered()
    1 -> always_abstain()
    2 -> always_no_confidence()
    _ -> fail
  }
}

pub fn registered() -> Fuzzer<DelegateRepresentative> {
  map(credential(), Registered)
}

pub fn registered_with(
  credential: Fuzzer<Credential>,
) -> Fuzzer<DelegateRepresentative> {
  map(credential, Registered)
}

pub fn always_abstain() -> Fuzzer<DelegateRepresentative> {
  constant(AlwaysAbstain)
}

pub fn always_no_confidence() -> Fuzzer<DelegateRepresentative> {
  constant(AlwaysNoConfidence)
}

// ### Stake Pool Ids

pub fn stake_pool_id() -> Fuzzer<StakePoolId> {
  bytearray_between(28, 28)
}

pub fn stake_pool_id_with(
  stake_pool_id: Fuzzer<ByteArray>,
) -> Fuzzer<StakePoolId> {
  map(
    stake_pool_id,
    fn(stake_pool_id) {
      if bytearray.length(stake_pool_id) == 28 {
        stake_pool_id
      } else {
        fail @"Stake Pool Ids must be 28 bytes"
      }
    },
  )
}

// ## Transaction

pub fn datum() -> Fuzzer<Datum> {
  let variant <- and_then(int_between(0, 2))
  when variant is {
    0 -> constant(NoDatum)
    1 -> {
      let hash <- map(bytearray_between(32, 32))
      DatumHash(hash)
    }
    2 -> {
      let i <- map(int())
      InlineDatum(i)
    }
    _ -> fail @"unexpected datum variant"
  }
}

pub fn output() -> Fuzzer<Output> {
  let address <- and_then(address())
  let value <- and_then(and_then(lovelace(), value))
  let datum <- and_then(datum())
  let reference_script <- map(reference_script())
  Output { address, value, datum, reference_script }
}

pub fn reference_script() -> Fuzzer<Option<ScriptHash>> {
  option(bytearray_between(28, 28))
}

pub fn output_reference() -> Fuzzer<OutputReference> {
  let transaction_id <- and_then(bytearray_between(32, 32))
  let output_index <- map(int_between(0, 300))
  OutputReference { transaction_id, output_index }
}

pub fn input() -> Fuzzer<Input> {
  let output_reference <- and_then(output_reference())
  let output <- map(output())
  Input { output_reference, output }
}

/// Generate Withdrawals
pub fn withdrawals() -> Fuzzer<Pairs<Credential, Lovelace>> {
  map(
    list_between(
      map2(
        credential(),
        int_between(0, 200000000000),
        fn(c, i) {
          let l: Lovelace = i
          Pair(c, l)
        },
      ),
      0,
      5,
    ),
    fn(l) {
      let ps: Pairs<Credential, Lovelace> =
        list.sort(l, fn(e1, e2) { credential.compare(e1.1st, e2.1st) })
      ps
    },
  )
}

pub fn withdrawals_extending(
  with: Pairs<Credential, Lovelace>,
) -> Fuzzer<Pairs<Credential, Lovelace>> {
  map(
    withdrawals(),
    fn(w) {
      list.sort(
        list.concat(w, with),
        fn(e1, e2) { credential.compare(e1.1st, e2.1st) },
      )
    },
  )
}
