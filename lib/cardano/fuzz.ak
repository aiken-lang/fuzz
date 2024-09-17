use aiken/collection/list
use aiken/fuzz.{bool, bytearray_between, int, map, map2, map3, such_that}
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets.{AssetName, PolicyId, Value}
// Lovelace
use cardano/transaction.{Datum, Input, NoDatum, Output, OutputReference}

/// Generate a random Credential
pub fn generate_random_credential() -> Fuzzer<Credential> {
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

/// Generate a random Address
pub fn generate_random_address() -> Fuzzer<Address> {
  let payment_credential = generate_random_credential()
  let staking_credential = generate_random_credential()
  map2(
    payment_credential,
    staking_credential,
    fn(p, s) { Address(p, Some(Inline(s))) },
  )
}

/// Generate a random PolicyId
pub fn generate_random_policy() -> Fuzzer<PolicyId> {
  fuzz.bytearray_between(28, 28)
}

/// Generate a random AssetName
pub fn generate_random_asset_name() -> Fuzzer<AssetName> {
  fuzz.bytearray_between(0, 28)
}

fn generate_random_pair(
  a_fuzz: Fuzzer<a>,
  b_fuzz: Fuzzer<b>,
) -> Fuzzer<Pair<a, b>> {
  map2(a_fuzz, b_fuzz, fn(a, b) { Pair(a, b) })
}

fn generate_random_tokens() -> Fuzzer<
  Pair<PolicyId, List<Pair<AssetName, Int>>>,
> {
  let policy = generate_random_policy()
  let f =
    fn(l: List<Pair<AssetName, Int>>) {
      let asset_names =
        list.foldr(
          l,
          [],
          fn(Pair(name, _amount), used_names) {
            if list.has(used_names, name) {
              fail
            } else {
              [name, ..used_names]
            }
          },
        )
      asset_names != []
    }
  let pairs =
    such_that(
      fuzz.list(generate_random_pair(generate_random_asset_name(), int())),
      f,
    )
  map2(policy, pairs, fn(p, ps) { Pair(p, ps) })
}

/// Generate a random Value
pub fn generate_random_value() -> Fuzzer<Value> {
  let f =
    fn(l: List<Pair<PolicyId, List<Pair<AssetName, Int>>>>) {
      let policies =
        list.foldr(
          l,
          [],
          fn(Pair(policy, _tokens), used_policies) {
            if list.has(used_policies, policy) {
              fail
            } else {
              [policy, ..used_policies]
            }
          },
        )
      policies != []
    }
  map(
    such_that(fuzz.list(generate_random_tokens()), f),
    fn(v: Pairs<PolicyId, Pairs<AssetName, Int>>) { assets.from_asset_list(v) },
  )
}

// TODO @riley
// pub fn generate_constrained_value(
// constraints: List<Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>>,
// ) -> Fuzzer<Value> {
// todo
// }

/// Generates a value with **only** the PolicyId and AssetNames included.
/// Amounts generated will be inclusive between bounds provided for a given asset.
/// Generate a random Input with no datum.
pub fn generate_random_input() -> Fuzzer<Input> {
  map2(
    generate_random_address(),
    generate_random_value(),
    fn(a, v) { Input(OutputReference("", 0), Output(a, v, NoDatum, None)) },
  )
}

/// Generate a random Input given a Fuzzer<Datum>
pub fn generate_random_input_with_datum(datum: Fuzzer<Datum>) -> Fuzzer<Input> {
  map3(
    generate_random_address(),
    generate_random_value(),
    datum,
    fn(a, v, d) { Input(OutputReference("", 0), Output(a, v, d, None)) },
  )
}

/// Generate a list of Inputs without Datums
pub fn generate_random_inputs(
  predicate: fn(List<Input>) -> Bool,
) -> Fuzzer<List<Input>> {
  such_that(fuzz.list(generate_random_input()), predicate)
}

/// Generate a list of Inputs given a Fuzzer<Datum>
pub fn generate_random_inputs_with_datum(
  datum: Fuzzer<Datum>,
  predicate: fn(List<Input>) -> Bool,
) -> Fuzzer<List<Input>> {
  such_that(fuzz.list(generate_random_input_with_datum(datum)), predicate)
}
/// Generates a list of outputs and a fee that ensures balance between input and output+fee.
// TODO @riley
// pub fn generate_balanced_outputs(
// inputs: List<Input>,
// ) -> Fuzzer<Pair<Lovelace, List<Output>>> {
// todo
// }
