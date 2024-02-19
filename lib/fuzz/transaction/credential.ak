use aiken/transaction/credential as t
use fuzz/bytearray as fba
use fuzz/fuzz.{map, map2, one_of}
use fuzz/int as fint
use fuzz/option as fopt
use fuzz/types.{Fuzz, Seed}

pub fn address() -> Fuzz<t.Address> {
  address_raw(payment_credential(), fopt.option(stake_credential()))
}

pub fn address_raw(
  fuzz_payment_credential: Fuzz<t.PaymentCredential>,
  fuzz_stake_credential: Fuzz<Option<t.StakeCredential>>,
) -> Fuzz<t.Address> {
  map2(
    fn(payment_credential, stake_credential) {
      t.Address { payment_credential, stake_credential }
    },
    fuzz_payment_credential,
    fuzz_stake_credential,
  )
}

pub fn credential() -> Fuzz<t.Credential> {
  one_of(verification_key_credential(), [script_credential()])
}

pub fn verification_key_credential() -> Fuzz<t.Credential> {
  map(fn(x) { t.VerificationKeyCredential(x) }, fba.bytearray28())
}

pub fn script_credential() -> Fuzz<t.Credential> {
  map(fn(x) { t.ScriptCredential(x) }, fba.bytearray28())
}

pub fn payment_credential() -> Fuzz<t.PaymentCredential> {
  credential()
}

pub fn pool_id() -> Fuzz<t.PoolId> {
  fba.bytearray28()
}

pub fn referenced(fuzz_a: Fuzz<a>) -> Fuzz<t.Referenced<a>> {
  one_of(inline(fuzz_a), [pointer()])
}

pub fn inline(fuzz_a: Fuzz<a>) -> Fuzz<t.Referenced<a>> {
  map(fn(x) { t.Inline(x) }, fuzz_a)
}

pub fn pointer() -> Fuzz<t.Referenced<a>> {
  fn(s: Seed) {
    let fz = fint.non_neg_int()
    let (slot_number, s1) = fz(s)
    let (transaction_index, s2) = fz(s1)
    let (certificate_index, s3) = fz(s2)
    (t.Pointer { slot_number, transaction_index, certificate_index }, s3)
  }
}

pub fn script() -> Fuzz<t.Script> {
  fba.bytearray_range(100, 10000)
}

pub fn signature() -> Fuzz<t.Signature> {
  fba.bytearray64()
}

pub fn stake_credential() -> Fuzz<t.StakeCredential> {
  referenced(credential())
}

pub fn verification_key() -> Fuzz<t.VerificationKey> {
  fba.bytearray32()
}
