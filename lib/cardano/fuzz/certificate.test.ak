use aiken/fuzz.{label}
use cardano/certificate.{
  AlwaysAbstain, AlwaysNoConfidence, AuthorizeConstitutionalCommitteeProxy,
  DelegateBlockProduction, DelegateBoth, DelegateCredential, DelegateVote,
  RegisterAndDelegateCredential, RegisterCredential,
  RegisterDelegateRepresentative, RegisterStakePool, Registered,
  RetireFromConstitutionalCommittee, RetireStakePool, UnregisterCredential,
  UnregisterDelegateRepresentative, UpdateDelegateRepresentative,
}
use cardano/fuzz.{delegate, delegate_representative} as fuzz_cert

test prop_certificate(c via fuzz_cert.certificate()) {
  label(
    when c is {
      RegisterCredential(_, _) -> @"RegisterCredential"
      UnregisterCredential(_, _) -> @"UnregisterCredential"
      DelegateCredential(_, _) -> @"DelegateCredential"
      RegisterAndDelegateCredential(_, _, _) -> @"RegisterAndDelegateCredential"
      RegisterDelegateRepresentative(_, _) -> @"RegisterDelegateRepresentative"
      UpdateDelegateRepresentative(_) -> @"UpdateDelegateRepresentative"
      UnregisterDelegateRepresentative(_, _) ->
        @"UnregisterDelegateRepresentative"
      RegisterStakePool(_, _) -> @"RegisterStakePool"
      RetireStakePool(_, _) -> @"RetireStakePool"
      AuthorizeConstitutionalCommitteeProxy(_, _) ->
        @"AuthorizeConstitutionalCommitteeProxy"
      RetireFromConstitutionalCommittee(_) ->
        @"RetireFromConstitutionalCommittee"
    },
  )
}

/// Test for delegate generator
test prop_delegate(d via delegate()) {
  label(
    when d is {
      DelegateBlockProduction(_) -> @"DelegateBlockProduction"
      DelegateVote(_) -> @"DelegateVote"
      DelegateBoth(_, _) -> @"DelegateBoth"
    },
  )
}

/// Test for delegate_representative (DelegateRepresentative) generator
test prop_delegate_representative(d via delegate_representative()) {
  label(
    when d is {
      Registered(_) -> @"Registered"
      AlwaysAbstain -> @"AlwaysAbstain"
      AlwaysNoConfidence -> @"AlwaysNoConfidence"
    },
  )
}
