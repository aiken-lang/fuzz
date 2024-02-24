use aiken/transaction/credential as t
use fuzz
use fuzz/hash

pub fn address(
  fuzz_payment_credential: fuzz.Fuzzer<t.PaymentCredential>,
  fuzz_stake_credential: fuzz.Fuzzer<Option<t.StakeCredential>>,
) -> fuzz.Fuzzer<t.Address> {
  fuzz.map2(
    fn(payment_credential, stake_credential) {
      t.Address { payment_credential, stake_credential }
    },
    fuzz_payment_credential,
    fuzz_stake_credential,
  )
}

pub fn credential() -> fuzz.Fuzzer<t.Credential> {
  fuzz.choose(verification_key_credential(), script_credential())
}

pub fn verification_key_credential() -> fuzz.Fuzzer<t.Credential> {
  fuzz.map(fn(x) { t.VerificationKeyCredential(x) }, hash.blake2b_224())
}

pub fn script_credential() -> fuzz.Fuzzer<t.Credential> {
  fuzz.map(fn(x) { t.ScriptCredential(x) }, hash.blake2b_224())
}

pub fn payment_credential() -> fuzz.Fuzzer<t.PaymentCredential> {
  credential()
}

pub fn pool_id() -> fuzz.Fuzzer<t.PoolId> {
  hash.blake2b_224()
}

pub fn default_referenced(fuzz_a: fuzz.Fuzzer<a>) -> fuzz.Fuzzer<t.Referenced<a>> {
  fuzz.choose(inline(fuzz_a), default_pointer())
}

pub fn referenced(pointer: fuzz.Fuzzer<t.Referenced<a>>, fuzz_a: fuzz.Fuzzer<a>) -> fuzz.Fuzzer<t.Referenced<a>> {
  fuzz.choose(inline(fuzz_a), pointer)
}

pub fn inline(fuzz_a: fuzz.Fuzzer<a>) -> fuzz.Fuzzer<t.Referenced<a>> {
  fuzz.map(fn(x) { t.Inline(x) }, fuzz_a)
}

pub fn default_pointer() -> fuzz.Fuzzer<t.Referenced<a>> {
  fuzz.map3(fn (slot_number, transaction_index, certificate_index) {
    t.Pointer { slot_number, transaction_index, certificate_index }
  }, 
    fuzz.int_range(0, 999_999_999_999), 
    fuzz.int_range(0, 1_000),
    fuzz.int_range(0, 1_000),
  )
}

/// FIXME : the ranges should be configurable?
pub fn pointer(
    fuzz_slot_number : fuzz.Fuzzer<Int>,
    fuzz_transaction_index : fuzz.Fuzzer<Int>,
    fuzz_certificate_index : fuzz.Fuzzer<Int>,
) -> fuzz.Fuzzer<t.Referenced<a>> {
  fuzz.map3(fn (slot_number, transaction_index, certificate_index) {
    t.Pointer { slot_number, transaction_index, certificate_index }
  }, 
    fuzz_slot_number,
    fuzz_transaction_index,
    fuzz_certificate_index,
  )
}

pub fn script() -> fuzz.Fuzzer<t.Script> {
  fuzz.bytearray()
}

pub fn signature() -> fuzz.Fuzzer<t.Signature> {
  fuzz.bytearray_fixed(64)
}

pub fn defaut_stake_credential() -> fuzz.Fuzzer<t.StakeCredential> {
  default_referenced(credential())
}

pub fn stake_credential(referenced : fn(fuzz.Fuzzer<t.Credential>) -> fuzz.Fuzzer<t.Referenced<t.Credential>>) -> fuzz.Fuzzer<t.StakeCredential> {
  referenced(credential())
}

pub fn verification_key() -> fuzz.Fuzzer<t.VerificationKey> {
  fuzz.bytearray_fixed(32)
}
