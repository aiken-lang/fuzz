
use aiken/transaction as t 
use aiken/transaction/certificate as cert
use aiken/transaction/credential as cred
use aiken/transaction/value as val

validator { fn datum( _ : t.Datum, _ctx : Data ) { True }}
validator { fn input( _ : t.Input, _ctx : Data ) { True }}
validator { fn output( _ : t.Output, _ctx : Data ) { True }}
validator { fn output_reference( _ : t.OutputReference, _ctx : Data ) { True }}
validator { fn redeemer( _ : t.Redeemer, _ctx : Data ) { True }}
validator { fn script_context( _ : t.ScriptContext, _ctx : Data ) { True }}
validator { fn script_purpose( _ : t.ScriptPurpose, _ctx : Data ) { True }}
validator { fn transaction( _ : t.Transaction, _ctx : Data ) { True }}
validator { fn transaction_id( _ : t.TransactionId, _ctx : Data ) { True }}
validator { fn validity_range( _ : t.ValidityRange, _ctx : Data ) { True }}
validator { fn certificate( _ : cert.Certificate, _ctx : Data ) { True }}
validator { fn address( _ : cred.Address, _ctx : Data ) { True }}
validator { fn credential( _ : cred.Credential, _ctx : Data ) { True }}
validator { fn payment_credential( _ : cred.PaymentCredential, _ctx : Data ) { True }}
validator { fn pool_id( _ : cred.PoolId, _ctx : Data ) { True }}
validator { fn referenced( _ : cred.Referenced<cred.Credential>, _ctx : Data ) { True }}
validator { fn script( _ : cred.Script, _ctx : Data ) { True }}
validator { fn signature( _ : cred.Signature, _ctx : Data ) { True }}
validator { fn stake_credential( _ : cred.StakeCredential, _ctx : Data ) { True }}
validator { fn verification_key( _ : cred.VerificationKey, _ctx : Data ) { True }}
validator { fn asset_name( _ : val.AssetName, _ctx : Data ) { True }}
validator { fn minted_value( _ : val.MintedValue, _ctx : Data ) { True }}
validator { fn policy_id( _ : val.PolicyId, _ctx : Data ) { True }}
validator { fn value( _ : val.Value, _ctx : Data ) { True }}

validator { fn integer(_: Int, _ctx: Data) { True } }
