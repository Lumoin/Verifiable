using System.Diagnostics;

namespace Verifiable.Core.Model.Did;

/// <summary>
/// A verification method reference that a Data Integrity proof carries under a <c>proofPurpose</c> naming none of the
/// verification relationships this library models, or under no <c>proofPurpose</c> at all, holding the proof's raw
/// purpose value so the proof keeps its <c>verificationMethod</c> whatever purpose it declares.
/// </summary>
/// <remarks>
/// <para>
/// The relationship types (<see cref="AuthenticationMethod"/>, <see cref="AssertionMethod"/>,
/// <see cref="KeyAgreementMethod"/>, <see cref="CapabilityInvocationMethod"/>, <see cref="CapabilityDelegationMethod"/>)
/// are a closed set keyed by purpose, while a proof may declare any purpose. Reading an unrecognized purpose into this
/// type instead of dropping the reference leaves the decision to the verification algorithm, which is where
/// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4 Verify Proof</see> places it:
/// "If expectedProofPurpose was given, and it does not match proof.proofPurpose, an error MUST be raised and SHOULD
/// convey an error type of PROOF_VERIFICATION_ERROR." A proof read this way also writes back with both its
/// <c>verificationMethod</c> and its <c>proofPurpose</c>.
/// </para>
/// <para>
/// This type never appears in a DID document's relationship arrays; a DID document's relationships are keyed by the
/// array they appear in, not by a purpose string.
/// </para>
/// </remarks>
[DebuggerDisplay("UnknownPurposeMethod(Id = {Id}, Purpose = {PurposeName}, IsEmbedded = {IsEmbeddedVerification})")]
public sealed class UnknownPurposeMethod: VerificationMethodReference
{
    /// <summary>
    /// The proof's own <c>proofPurpose</c> value exactly as it was read, or the empty string when the proof declared
    /// none.
    /// </summary>
    public override string PurposeName { get; }


    /// <summary>
    /// Initializes a reference, by URI, to the verification method a proof names under an unrecognized or absent purpose.
    /// </summary>
    /// <param name="purpose">The proof's raw <c>proofPurpose</c> value, or <see langword="null"/> when it declared none.</param>
    /// <param name="verificationReferenceId">The URI reference to the verification method.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="verificationReferenceId"/> is <see langword="null"/>.
    /// </exception>
    public UnknownPurposeMethod(string? purpose, string verificationReferenceId) : base(verificationReferenceId)
    {
        PurposeName = purpose ?? string.Empty;
    }


    /// <summary>
    /// Initializes a reference carrying the verification method a proof embeds under an unrecognized or absent purpose.
    /// </summary>
    /// <param name="purpose">The proof's raw <c>proofPurpose</c> value, or <see langword="null"/> when it declared none.</param>
    /// <param name="embeddedVerification">The embedded verification method.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="embeddedVerification"/> is <see langword="null"/>.
    /// </exception>
    public UnknownPurposeMethod(string? purpose, VerificationMethod embeddedVerification) : base(embeddedVerification)
    {
        PurposeName = purpose ?? string.Empty;
    }
}
