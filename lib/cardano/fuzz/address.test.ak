use aiken/fuzz.{label}
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/fuzz as cardano

test prop_credential(credential via cardano.credential()) {
  label(
    when credential is {
      Script(_) -> @"Script"
      VerificationKey(_) -> @"VerificationKey"
    },
  )
}

test prop_address(a via cardano.address()) {
  label(
    when a is {
      Address { payment_credential: VerificationKey(_), stake_credential: None } ->
        @"VerificationKey_NoStake"
      Address { payment_credential: Script(_), stake_credential: None } ->
        @"Script_NoStake"
      Address {
        payment_credential: VerificationKey(_),
        stake_credential: Some(Inline(VerificationKey(_))),
      } -> @"VerificationKey_InlineVerificationKey"
      Address {
        payment_credential: VerificationKey(_),
        stake_credential: Some(Inline(Script(_))),
      } -> @"VerificationKey_InlineScript"
      Address {
        payment_credential: Script(_),
        stake_credential: Some(Inline(VerificationKey(_))),
      } -> @"Script_InlineVerificationKey"
      Address {
        payment_credential: Script(_),
        stake_credential: Some(Inline(Script(_))),
      } -> @"Script_InlineScript"
      _ -> fail @"Unexpected Address from address"
    },
  )
}
