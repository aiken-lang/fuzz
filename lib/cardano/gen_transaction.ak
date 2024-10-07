use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz.{
  and_then, bytearray_between, constant, int, int_between, list_between, map,
  map2, option,
}
use cardano/address.{Credential}
use cardano/address/credential
use cardano/assets.{AssetName, Lovelace, PolicyId}
use cardano/gen_address.{any_address, any_credential}
use cardano/gen_assets.{any_constrained_value, any_value}
use cardano/transaction.{
  Datum, DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference,
  Transaction,
}

// INPUTS
// OUTPUTS
// 

// pub type Transaction {
// inputs: List<Input>,
// reference_inputs: List<Input>,
// outputs: List<Output>,
// fee: Lovelace,
// mint: Value,
// certificates: List<Certificate>,
// /// > [!IMPORTANT]
// /// > Withdrawals are ordered by ascending [Credential](./credential.html#Credential). Yet, note that [`Script`](./credential.html#Credential) credentials are treated as **lower values** than [`VerificationKey`](./credential.html#Credential) credentials.
// withdrawals: Pairs<Credential, Lovelace>,
// validity_range: ValidityRange,
// extra_signatories: List<VerificationKeyHash>,
// /// > [!IMPORTANT]
// /// > Redeemers are ordered by ascending [ScriptPurpose](./transaction.html#ScriptPurpose).
// redeemers: Pairs<ScriptPurpose, Redeemer>,
// datums: Dict<DataHash, Data>,
// id: TransactionId,
// /// > [!IMPORTANT]
// /// > Votes are ordered by ascending [Voter](./governance.html#Voter) and [GovernanceActionId](./governance.html#GovernanceActionId).<br/>First constructor variants in a type are treated as lower indices; except for [Credential](./credential.html#Credential) where [`Script`](./credential.html#Credential) credentials are treated as **lower values** than [`VerificationKey`](./credential.html#Credential) credentials.
// votes: Pairs<Voter, Pairs<GovernanceActionId, Vote>>,
// proposal_procedures: List<ProposalProcedure>,
// current_treasury_amount: Option<Lovelace>,
// treasury_donation: Option<Lovelace>,
// }
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

pub fn add_fuzz_withdrawals(
  withdraws: Fuzzer<Pairs<Credential, Lovelace>>,
  tx: Transaction,
) -> Fuzzer<Transaction> {
  map(
    withdraws,
    fn(w) { Transaction { ..tx, withdrawals: list.concat(w, tx.withdrawals) } },
  )
}

pub fn add_fuzz_input(
  input: Fuzzer<Input>,
  tx: Transaction,
) -> Fuzzer<Transaction> {
  map(
    input,
    fn(in) { Transaction { ..tx, inputs: [in, ..tx.reference_inputs] } },
  )
}

pub fn add_fuzz_inputs(
  ins: Fuzzer<List<Input>>,
  tx: Transaction,
) -> Fuzzer<Transaction> {
  map(
    ins,
    fn(ins) { Transaction { ..tx, inputs: list.concat(ins, tx.inputs) } },
  )
}

pub fn add_fuzz_ref_input(
  input: Fuzzer<Input>,
  tx: Transaction,
) -> Fuzzer<Transaction> {
  map(
    input,
    fn(in) {
      Transaction { ..tx, reference_inputs: [in, ..tx.reference_inputs] }
    },
  )
}

pub fn add_fuzz_ref_inputs(
  inputs: Fuzzer<List<Input>>,
  tx: Transaction,
) -> Fuzzer<Transaction> {
  map(
    inputs,
    fn(ins) {
      Transaction {
        ..tx,
        reference_inputs: list.concat(ins, tx.reference_inputs),
      }
    },
  )
}

pub fn add_fuzz_output(
  output: Fuzzer<Output>,
  tx: Transaction,
) -> Fuzzer<Transaction> {
  map(output, fn(out) { Transaction { ..tx, outputs: [out, ..tx.outputs] } })
}

pub fn add_fuzz_outputs(
  outs: Fuzzer<List<Output>>,
  tx: Transaction,
) -> Fuzzer<Transaction> {
  map(
    outs,
    fn(os) { Transaction { ..tx, outputs: list.concat(os, tx.outputs) } },
  )
}

pub fn balance_tx(tx: Transaction) -> Transaction {
  todo
}
