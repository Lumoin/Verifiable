using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// All inputs needed to validate one OID4VCI 1.0 <c>jwt</c> key proof (Appendix F.1 / F.4).
/// Threaded into <see cref="CredentialProofValidator.ValidateAsync"/> as a single record so
/// adding new check inputs does not re-shape the method signature.
/// </summary>
/// <remarks>
/// The <c>c_nonce</c> the proof must echo is passed IN as <see cref="ExpectedNonce"/> — the
/// Credential Issuer's <c>c_nonce</c> store and its single-use retirement remain the
/// application's responsibility (exactly as the §7 Nonce Endpoint leaves nonce minting to the
/// application). The validator only checks the proof's <c>nonce</c> claim against the supplied
/// value.
/// </remarks>
[DebuggerDisplay("CredentialProofValidationRequest aud={ExpectedAudience,nq} nonceRequired={NonceRequired}")]
public sealed record CredentialProofValidationRequest
{
    /// <summary>The compact-serialised <c>jwt</c> key proof from the §8.2 <c>proofs</c> array.</summary>
    public required string Proof { get; init; }

    /// <summary>
    /// The Credential Issuer Identifier the proof's <c>aud</c> claim MUST equal (§F.1: "The value
    /// of this claim MUST be the Credential Issuer Identifier").
    /// </summary>
    public required string ExpectedAudience { get; init; }

    /// <summary>
    /// The server-provided <c>c_nonce</c> the proof's <c>nonce</c> claim MUST echo, or
    /// <see langword="null"/> when the Issuer has no Nonce Endpoint and requires none. Validation
    /// behaviour depends on <see cref="NonceRequired"/>.
    /// </summary>
    public string? ExpectedNonce { get; init; }

    /// <summary>
    /// When <see langword="true"/>, validation fails if the proof has no <c>nonce</c> claim or the
    /// value does not equal <see cref="ExpectedNonce"/> (§F.4: "if the server has a Nonce Endpoint,
    /// the nonce in the key proof matches the server-provided c_nonce value"). When
    /// <see langword="false"/>, an absent <c>nonce</c> is accepted; a present but mismatched
    /// <c>nonce</c> still fails when an <see cref="ExpectedNonce"/> is supplied.
    /// </summary>
    public required bool NonceRequired { get; init; }
}
