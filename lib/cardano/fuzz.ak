use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz.{
  and_then, bool, bytearray_between, constant, int, int_at_least, int_between,
  list_between, map, map2, map3, option,
}
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
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

// ## Assets

/// Generate an arbitrary asset name, between 0 and 32 bytes length.
pub fn asset_name() -> Fuzzer<AssetName> {
  bytearray_between(0, 32)
}

/// Generate assets from a given policy, adding them to the provided value accumulator
pub fn assets(self: Value, policy_id: PolicyId) -> Fuzzer<Value> {
  let names <- and_then(list_between(asset_name(), 1, 3))
  list.foldr(
    names,
    constant(self),
    fn(asset_name, step) {
      let value <- and_then(step)
      let quantity <- map(int_at_least(1))
      value |> assets.add(policy_id, asset_name, quantity)
    },
  )
}

/// Generate a `Value` holding a **positive** quantity of lovelace, but no assets.
pub fn lovelace() -> Fuzzer<Value> {
  map(int_at_least(1000000), assets.from_lovelace)
}

/// Generate an arbitrary policy is (a.k.a script hash).
pub fn policy_id() -> Fuzzer<PolicyId> {
  bytearray_between(28, 28)
}

/// Generate an arbitrary `Value`, extending an existing one. Use
/// `assets.zero` or `cardano.lovelace()` as a simple starting point.
pub fn value(self: Value) -> Fuzzer<Value> {
  let policies <- and_then(list_between(policy_id(), 0, 2))
  list.foldr(
    policies,
    constant(self),
    fn(policy_id, step) {
      let value <- and_then(step)
      assets(value, policy_id)
    },
  )
}

/// Extend an existing value using the given fuzzers for fine-grained control.
///
/// ```ak
/// let value <- fuzz.value_with(
///   value.zero,
///   with_policies: fuzz.constant([my_policy_1, my_policy_2]),
///   with_asset_name: fn(policy) {
///     if policy == my_policy_1 {
///        fuzz.one_of([asset_1, asset_2, asset_3])
///     } else {
///        fuzz.constant(my_other_asset)
///     }
///   },
///   with_quantity: fn(_) { fuzz.constant(1) }
/// )
/// ```
pub fn value_with(
  self: Value,
  with_policies: Fuzzer<List<PolicyId>>,
  with_asset_name: fn(PolicyId) -> Fuzzer<AssetName>,
  with_quantity: fn(AssetName) -> Fuzzer<Int>,
) -> Fuzzer<Value> {
  let policies <- and_then(with_policies)
  list.foldr(
    policies,
    constant(self),
    fn(policy, step) {
      let value <- and_then(step)
      let asset_name <- and_then(with_asset_name(policy))
      let quantity <- map(with_quantity(asset_name))
      value |> assets.add(policy, asset_name, quantity)
    },
  )
}

// ## Certificates

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

pub fn delegate() -> Fuzzer<Delegate> {
  let choice <- and_then(int_between(0, 2))
  when choice is {
    0 -> map(stake_pool_id(), DelegateBlockProduction)
    1 -> map(delegate_representative(), DelegateVote)
    2 -> map2(stake_pool_id(), delegate_representative(), DelegateBoth)
    _ -> fail
  }
}

pub fn delegate_representative() -> Fuzzer<DelegateRepresentative> {
  let choice <- and_then(int_between(0, 2))
  when choice is {
    0 -> map(credential(), Registered)
    1 -> constant(AlwaysAbstain)
    2 -> constant(AlwaysNoConfidence)
    _ -> fail
  }
}

pub fn stake_pool_id() -> Fuzzer<StakePoolId> {
  bytearray_between(32, 32)
}

// ### Fine-grained

pub fn register_credential() -> Fuzzer<Certificate> {
  map(credential(), fn(credential) { RegisterCredential(credential, Never) })
}

pub fn unregister_credential() -> Fuzzer<Certificate> {
  map(credential(), fn(credential) { UnregisterCredential(credential, Never) })
}

pub fn delegate_credential() -> Fuzzer<Certificate> {
  map2(credential(), delegate(), DelegateCredential)
}

pub fn register_and_delegate_credential() -> Fuzzer<Certificate> {
  map3(credential(), delegate(), int(), RegisterAndDelegateCredential)
}

pub fn register_delegate_representative() -> Fuzzer<Certificate> {
  map2(credential(), int(), RegisterDelegateRepresentative)
}

pub fn update_delegate_representative() -> Fuzzer<Certificate> {
  map(credential(), UpdateDelegateRepresentative)
}

pub fn unregister_delegate_representative() -> Fuzzer<Certificate> {
  map2(credential(), int(), UnregisterDelegateRepresentative)
}

pub fn register_stake_pool() -> Fuzzer<Certificate> {
  map2(stake_pool_id(), bytearray_between(32, 32), RegisterStakePool)
}

pub fn retire_stake_pool() -> Fuzzer<Certificate> {
  map2(stake_pool_id(), int(), RetireStakePool)
}

pub fn authorize_constitutional_committee_proxy() -> Fuzzer<Certificate> {
  map2(credential(), credential(), AuthorizeConstitutionalCommitteeProxy)
}

pub fn retire_from_constitutional_committee() -> Fuzzer<Certificate> {
  map(credential(), RetireFromConstitutionalCommittee)
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
