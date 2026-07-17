using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The verification result for self attestation: the authenticator signed the attestation
/// statement with the credential's own private key rather than a dedicated attestation key, so
/// the attestation trust path is empty.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2: Packed Attestation Statement Format.</see>
/// The verification procedure's <c>x5c</c>-absent branch: "If successful, return
/// implementation-specific values representing attestation type Self and an empty attestation
/// trust path."
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-types">Section 6.5.3: Attestation Types</see>
/// defines self attestation (also known as surrogate basic attestation) as the case where the
/// authenticator has no dedicated attestation key pair and instead uses the credential private
/// key to create the attestation signature.
/// </para>
/// </remarks>
[DebuggerDisplay("SelfAttestationResult")]
public sealed record SelfAttestationResult: AttestationResult;
