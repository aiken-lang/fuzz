use aiken/collection/list
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use aiken/fuzz.{
  and_then, bytearray_between, constant, int, int_between, list_between, map,
  map2, option,
}
use cardano/address.{Credential}
use cardano/address/credential
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/certificate.{Certificate}
use cardano/gen_address.{any_address, any_credential}
use cardano/gen_assets.{any_constrained_value, any_value}
use cardano/transaction.{
  Datum, DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference,
  Transaction,
}

pub fn any_datum() -> Fuzzer<Datum> {
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

pub fn any_reference_script() -> Fuzzer<Option<ScriptHash>> {
  option(bytearray_between(28, 28))
}

pub fn any_output() -> Fuzzer<Output> {
  let address <- and_then(any_address())
  let value <- and_then(any_value())
  let datum <- and_then(any_datum())
  let reference_script <- map(any_reference_script())
  Output { address, value, datum, reference_script }
}

pub fn any_zero_output() -> Fuzzer<Output> {
  let address <- and_then(any_address())
  let datum <- and_then(any_datum())
  let reference_script <- map(any_reference_script())
  Output { address, value: assets.zero, datum, reference_script }
}

// The any_constrained_output function remains the same
pub fn any_constrained_output(
  constraints: List<Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>>,
  datum: Fuzzer<Datum>,
) -> Fuzzer<Output> {
  let address <- and_then(any_address())
  let value <- and_then(any_constrained_value(constraints))
  let datum <- and_then(datum)
  let reference_script <- map(any_reference_script())
  Output { address, value, datum, reference_script }
}

pub fn any_constrained_outputs(
  constraints: List<Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>>,
  datum: Fuzzer<Datum>,
  min_outs: Int,
  max_outs: Int,
) -> Fuzzer<List<Output>> {
  let non_normalized <-
    and_then(list_between(int_between(1, 100), min_outs, max_outs))
  let sum_nn = list.foldr(non_normalized, 0, fn(e, acc) { acc + e })
  let normalized = list.map(non_normalized, fn(e) { 100 * e / sum_nn })
  list.foldr(
    normalized,
    constant([]),
    fn(e, acc) {
      let sub_constraints =
        list.map(
          constraints,
          fn(constraint) {
            let Pair(policy_id, asset_constraints) = constraint
            let updated_asset_constraints =
              list.map(
                asset_constraints,
                fn(asset_constraint) {
                  let Pair(asset_name, Pair(min, max)) = asset_constraint
                  let sub_min = min * e / 100
                  let sub_max = max * e / 100
                  Pair(asset_name, Pair(sub_min, sub_max))
                },
              )
            Pair(policy_id, updated_asset_constraints)
          },
        )
      map2(
        any_constrained_output(sub_constraints, datum),
        acc,
        fn(no, a) { [no, ..a] },
      )
    },
  )
}

pub fn any_output_reference() -> Fuzzer<OutputReference> {
  let transaction_id <- and_then(bytearray_between(32, 32))
  let output_index <- map(int_between(0, 300))
  OutputReference { transaction_id, output_index }
}

pub fn any_input() -> Fuzzer<Input> {
  let output_reference <- and_then(any_output_reference())
  let output <- map(any_output())
  Input { output_reference, output }
}

pub fn any_constrained_input(
  constraints: List<Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>>,
  datum: Fuzzer<Datum>,
) -> Fuzzer<Input> {
  let output_reference <- and_then(any_output_reference())
  let output <- map(any_constrained_output(constraints, datum))
  Input { output_reference, output }
}

/// Generate Withdrawals
pub fn any_withdrawals() -> Fuzzer<Pairs<Credential, Lovelace>> {
  map(
    list_between(
      map2(
        any_credential(),
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

pub fn any_withdrawals_extending(
  with: Pairs<Credential, Lovelace>,
) -> Fuzzer<Pairs<Credential, Lovelace>> {
  map(
    any_withdrawals(),
    fn(w) {
      list.sort(
        list.concat(w, with),
        fn(e1, e2) { credential.compare(e1.1st, e2.1st) },
      )
    },
  )
}

// Transaction stuffz

pub fn add_fuzz_input(
  self: Transaction,
  input: Fuzzer<Input>,
) -> Fuzzer<Transaction> {
  map(
    input,
    fn(in) { Transaction { ..self, inputs: [in, ..self.reference_inputs] } },
  )
}

pub fn add_fuzz_inputs(
  self: Transaction,
  ins: Fuzzer<List<Input>>,
) -> Fuzzer<Transaction> {
  map(
    ins,
    fn(ins) { Transaction { ..self, inputs: list.concat(ins, self.inputs) } },
  )
}

pub fn add_fuzz_ref_input(
  self: Transaction,
  input: Fuzzer<Input>,
) -> Fuzzer<Transaction> {
  map(
    input,
    fn(in) {
      Transaction { ..self, reference_inputs: [in, ..self.reference_inputs] }
    },
  )
}

pub fn add_fuzz_ref_inputs(
  self: Transaction,
  inputs: Fuzzer<List<Input>>,
) -> Fuzzer<Transaction> {
  map(
    inputs,
    fn(ins) {
      Transaction {
        ..self,
        reference_inputs: list.concat(ins, self.reference_inputs),
      }
    },
  )
}

pub fn add_fuzz_output(
  self: Transaction,
  output: Fuzzer<Output>,
) -> Fuzzer<Transaction> {
  map(
    output,
    fn(out) { Transaction { ..self, outputs: [out, ..self.outputs] } },
  )
}

pub fn add_fuzz_outputs(
  self: Transaction,
  outs: Fuzzer<List<Output>>,
) -> Fuzzer<Transaction> {
  map(
    outs,
    fn(os) { Transaction { ..self, outputs: list.concat(os, self.outputs) } },
  )
}

pub fn add_fuzz_mint(
  self: Transaction,
  mint: Fuzzer<Value>,
) -> Fuzzer<Transaction> {
  map(mint, fn(m) { Transaction { ..self, mint: m } })
}

pub fn add_fuzz_cert(
  self: Transaction,
  cert: Fuzzer<Certificate>,
) -> Fuzzer<Transaction> {
  map(
    cert,
    fn(c) { Transaction { ..self, certificates: [c, ..self.certificates] } },
  )
}

pub fn add_fuzz_withdrawals(
  self: Transaction,
  withdraws: Fuzzer<Pairs<Credential, Lovelace>>,
) -> Fuzzer<Transaction> {
  map(
    withdraws,
    fn(w) {
      Transaction { ..self, withdrawals: list.concat(w, self.withdrawals) }
    },
  )
}

pub fn add_fuzz_signers(
  self: Transaction,
  signers: Fuzzer<List<VerificationKeyHash>>,
) -> Fuzzer<Transaction> {
  map(
    signers,
    fn(s) {
      Transaction {
        ..self,
        extra_signatories: list.concat(s, self.extra_signatories),
      }
    },
  )
}

pub fn balance_tx(self: Transaction) -> Transaction {
  // First reduce the inputs, withdrawals, and any deregistration amounts from certs.
  // Then reduce outputs and fee.
  // Create a single output or input that balances the self.
  todo
}
