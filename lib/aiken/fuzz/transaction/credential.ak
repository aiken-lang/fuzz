use aiken/fuzz
use aiken/transaction/credential.{
  Address, Credential, Inline, PaymentCredential, Pointer, PoolId, Referenced,
  Script, Signature, StakeCredential, VerificationKey,
}

pub fn address(
  fuzz_payment_credential: Fuzzer<PaymentCredential>,
  fuzz_stake_credential: Fuzzer<Option<StakeCredential>>,
) -> Fuzzer<Address> {
  fuzz.map2(
    fuzz_payment_credential,
    fuzz_stake_credential,
    fn(payment_credential, stake_credential) {
      Address { payment_credential, stake_credential }
    },
  )
}

pub fn credential() -> Fuzzer<Credential> {
  fuzz.either(verification_key_credential(), script_credential())
}

pub fn verification_key_credential() -> Fuzzer<Credential> {
  fail
}

pub fn script_credential() -> Fuzzer<Credential> {
  fail
}

pub fn payment_credential() -> Fuzzer<PaymentCredential> {
  credential()
}

pub fn pool_id() -> Fuzzer<PoolId> {
  fuzz.bytearray_between(28, 28)
}

pub fn default_referenced(fuzz_a: Fuzzer<a>) -> Fuzzer<Referenced<a>> {
  fuzz.either(inline(fuzz_a), default_pointer())
}

pub fn referenced(
  pointer: Fuzzer<Referenced<a>>,
  fuzz_a: Fuzzer<a>,
) -> Fuzzer<Referenced<a>> {
  fuzz.either(inline(fuzz_a), pointer)
}

pub fn inline(fuzz_a: Fuzzer<a>) -> Fuzzer<Referenced<a>> {
  fuzz.map(fuzz_a, fn(x) { Inline(x) })
}

pub fn default_pointer() -> Fuzzer<Referenced<a>> {
  fuzz.map3(
    fuzz.int_between(0, 999_999_999_999),
    fuzz.int_between(0, 1_000),
    fuzz.int_between(0, 1_000),
    Pointer,
  )
}

pub fn script() -> Fuzzer<Script> {
  fuzz.bytearray()
}

pub fn signature() -> Fuzzer<Signature> {
  fuzz.bytearray_between(64, 64)
}

pub fn defaut_stake_credential() -> Fuzzer<StakeCredential> {
  default_referenced(credential())
}

pub fn stake_credential(
  referenced: fn(Fuzzer<Credential>) -> Fuzzer<Referenced<Credential>>,
) -> Fuzzer<StakeCredential> {
  referenced(credential())
}

pub fn verification_key() -> Fuzzer<VerificationKey> {
  fuzz.bytearray_between(32, 32)
}
