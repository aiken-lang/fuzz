use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/fuzz.{map, map7}
use cardano/address.{Credential}
use cardano/assets.{Lovelace, Value, ada_asset_name, ada_policy_id}
use cardano/certificate.{Certificate}
use cardano/fuzz as cardano
use cardano/transaction.{Input, Output, Redeemer, ScriptPurpose, Transaction}

// > [!IMPORTANT]
// The following fields on the transaction are not handled within our library.
// datums: Dict<DataHash, Data>,
// id: TransactionId,
// votes: Pairs<Voter, Pairs<GovernanceActionId, Vote>>,
// proposal_procedures: List<ProposalProcedure>,
// current_treasury_amount: Option<Lovelace>,
// treasury_donation: Option<Lovelace>,

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

pub fn add_fuzz_redeemers(
  self: Transaction,
  redeemers: Fuzzer<Pairs<ScriptPurpose, Redeemer>>,
) -> Fuzzer<Transaction> {
  map(
    redeemers,
    fn(r) { Transaction { ..self, redeemers: list.concat(r, self.redeemers) } },
  )
}

pub fn generic_tx() -> Fuzzer<Transaction> {
  let tx <-
    fuzz.and_then(
      add_fuzz_inputs(transaction.placeholder, fuzz.list(cardano.input())),
    )
  add_fuzz_outputs(tx, fuzz.list(cardano.output()))
}

// TODO - Rewrite this handling separate parts of the tx separately.
// We also need to add test(s) for this.
/// > [!IMPORTANT]
/// This function does not consider certificates.
/// It only pays attention to withdrawals, inputs,
///  outputs, and the current fee.
pub fn balance_tx(self: Transaction) -> Fuzzer<Transaction> {
  let Transaction { inputs, withdrawals, outputs, fee, .. } = self
  let input_total =
    list.foldr(
      inputs,
      assets.zero,
      fn(in, v) { assets.merge(in.output.value, v) },
    )
  let withdrawals_total =
    list.foldr(
      withdrawals,
      0,
      fn(p, acc) {
        let Pair(_, i) = p
        acc + i
      },
    )
  let total_in =
    assets.add(
      input_total,
      ada_policy_id,
      ada_asset_name,
      fee + withdrawals_total,
    )
  let output_total =
    list.foldr(outputs, assets.zero, fn(out, v) { assets.merge(out.value, v) })
  let added_input_value =
    assets.reduce(
      output_total,
      assets.zero,
      fn(p, a, i, r) {
        let res = i - assets.quantity_of(total_in, p, a)
        if res > 0 {
          assets.add(r, p, a, res)
        } else {
          r
        }
      },
    )
      |> assets.add(ada_policy_id, ada_asset_name, 1)
  let added_output_value =
    assets.reduce(
      total_in,
      assets.zero,
      fn(p, a, i, r) {
        let res = i - assets.quantity_of(output_total, p, a)
        if res > 0 {
          assets.add(r, p, a, res)
        } else {
          r
        }
      },
    )
      |> assets.add(ada_policy_id, ada_asset_name, 1)
  map7(
    cardano.output_reference(),
    cardano.address(),
    cardano.address(),
    cardano.datum(),
    cardano.datum(),
    cardano.reference_script(),
    cardano.reference_script(),
    fn(o_ref, a1, a2, d1, d2, r1, r2) {
      let new_input = Input(o_ref, Output(a1, added_input_value, d1, r1))
      let new_output = Output(a2, added_output_value, d2, r2)
      Transaction {
        ..self,
        inputs: [new_input, ..self.inputs],
        outputs: [new_output, ..self.outputs],
      }
    },
  )
}
