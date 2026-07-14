using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The verification result for the <c>none</c> attestation statement format: no attestation
/// information was conveyed, so the attestation trust path is empty.
/// </summary>
/// <param name="Downgrade">
/// <see langword="null"/> for a genuine <c>none</c> attestation statement (the ordinary case, and
/// every existing call site's default). Non-null only when <see cref="Fido2RegistrationVerifier"/>
/// produced this result by downgrading a certified attestation whose trust path did not reach a
/// supplied anchor, per <see cref="Fido2AttestationDowngrade"/>'s own remarks — an audit marker, not
/// a genuine attestation-type classification.
/// </param>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">W3C Web Authentication Level 3, section 8.7: None Attestation Statement Format.</see>
/// That section's verification procedure returns implementation-specific values representing
/// attestation type None and an empty attestation trust path; this record is that outcome. The
/// closed <see cref="AttestationResult"/> sum stays at exactly four cases even with the downgrade
/// path added: this optional field extends <see cref="NoneAttestationResult"/> rather than
/// introducing a fifth sibling record, so every existing exhaustive switch over
/// <see cref="AttestationResult"/> (for example <see cref="Fido2RegistrationChecks.CheckRegistrationAttestationTrustworthy"/>)
/// needs no change.
/// </remarks>
[DebuggerDisplay("NoneAttestationResult({Downgrade,nq})")]
public sealed record NoneAttestationResult(Fido2AttestationDowngrade? Downgrade = null): AttestationResult;
