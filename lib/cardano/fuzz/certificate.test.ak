use aiken/fuzz.{label}
use cardano/certificate.{Certificate, Delegate, DelegateRepresentative}
use cardano/fuzz.{delegate, delegate_representative} as fuzz_cert

test prop_certificate(cert via fuzz_cert.certificate()) {
  label(
    when cert is {
      Certificate.RegisterCredential { .. } -> @"RegisterCredential"
      Certificate.UnregisterCredential { .. } -> @"UnregisterCredential"
      Certificate.DelegateCredential { .. } -> @"DelegateCredential"
      Certificate.RegisterAndDelegateCredential { .. } ->
        @"RegisterAndDelegateCredential"
      Certificate.RegisterDelegateRepresentative { .. } ->
        @"RegisterDelegateRepresentative"
      Certificate.UpdateDelegateRepresentative { .. } ->
        @"UpdateDelegateRepresentative"
      Certificate.UnregisterDelegateRepresentative { .. } ->
        @"UnregisterDelegateRepresentative"
      Certificate.RegisterStakePool { .. } -> @"RegisterStakePool"
      Certificate.RetireStakePool { .. } -> @"RetireStakePool"
      Certificate.AuthorizeConstitutionalCommitteeProxy { .. } ->
        @"AuthorizeConstitutionalCommitteeProxy"
      Certificate.RetireFromConstitutionalCommittee { .. } ->
        @"RetireFromConstitutionalCommittee"
    },
  )
}

/// Test for delegate generator
test prop_delegate(delegate via delegate()) {
  label(
    when delegate is {
      Delegate.DelegateBlockProduction { .. } -> @"DelegateBlockProduction"
      Delegate.DelegateVote { .. } -> @"DelegateVote"
      Delegate.DelegateBoth { .. } -> @"DelegateBoth"
    },
  )
}

/// Test for delegate_representative (DelegateRepresentative) generator
test prop_delegate_representative(drep via delegate_representative()) {
  label(
    when drep is {
      DelegateRepresentative.Registered(_) -> @"Registered"
      DelegateRepresentative.AlwaysAbstain -> @"AlwaysAbstain"
      DelegateRepresentative.AlwaysNoConfidence -> @"AlwaysNoConfidence"
    },
  )
}
