using System;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// The shared resolving identity-binding gate for the ecdsa-sd-2023 and bbs-2023 selective
/// disclosure Data Integrity proofs (<see cref="CredentialEcdsaSd2023Extensions"/>,
/// <see cref="CredentialBbs2023Extensions"/>): the SAME controller-resolution recipe the
/// embedded-proof credential path uses (<see cref="CredentialDataIntegrityExtensions"/>'s chain-link
/// verification), factored out once so both selective-disclosure cryptosuites fold into it rather
/// than each re-implementing the resolve-purpose-controller sequence ("the SAME gate the
/// embedded-proof credential path uses — folds in, not a special case").
/// </summary>
/// <remarks>
/// The two steps below are fail-closed short-circuits BEFORE any cryptographic check runs:
/// <list type="number">
/// <item><description>The proof's declared <c>proofPurpose</c> must be <c>assertionMethod</c> (Data Integrity 1.0 §4.2 — checked before resolving anything).</description></item>
/// <item><description>The proof's <c>verificationMethod</c> must resolve under the issuer document's <c>assertionMethod</c> relationship, not merely the flat verification-method array.</description></item>
/// </list>
/// Only after the caller has run the cryptographic check against the resolved method's own key
/// material does <see cref="TryBindIssuer"/> — the controller-RESOLUTION check (an issuer
/// alias whose resolved method declares a different controller is rejected) — reach
/// <see cref="BoundProvenance.TryBindByControllerArtifact"/>.
/// </remarks>
internal static class SelectiveDisclosureIdentityBinding
{
    /// <summary>
    /// Resolves <paramref name="proof"/>'s declared verification method under
    /// <paramref name="issuerDidDocument"/>'s <c>assertionMethod</c> relationship, after checking
    /// the declared proof purpose.
    /// </summary>
    /// <param name="proof">The base or derived proof carrying the claimed verification method and purpose.</param>
    /// <param name="issuerDidDocument">The issuer's DID document to resolve against.</param>
    /// <returns>
    /// The resolved method on success; otherwise a <see langword="null"/> method paired with the
    /// specific <see cref="VerificationFailureReason"/> the caller should report.
    /// </returns>
    /// <exception cref="ArgumentNullException">A required argument is <see langword="null"/>.</exception>
    internal static (VerificationMethod? Method, VerificationFailureReason FailureReason) TryResolveIssuerAssertionMethod(
        DataIntegrityProof proof,
        DidDocument issuerDidDocument)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(issuerDidDocument);

        if(!string.Equals(proof.ProofPurpose, AssertionMethod.Purpose, StringComparison.Ordinal))
        {
            return (null, VerificationFailureReason.ProofPurposeMismatch);
        }

        string? verificationMethodId = proof.VerificationMethod?.Id;
        if(string.IsNullOrEmpty(verificationMethodId))
        {
            return (null, VerificationFailureReason.MissingVerificationMethod);
        }

        VerificationMethod? method = issuerDidDocument.GetLocalAssertionMethodById(verificationMethodId);

        return method is null
            ? (null, VerificationFailureReason.VerificationMethodNotFound)
            : (method, VerificationFailureReason.None);
    }


    /// <summary>
    /// Binds <paramref name="verificationMethod"/> to <paramref name="credential"/>'s claimed issuer
    /// through <see cref="BoundProvenance.TryBindByControllerArtifact"/> — the SAME gate the
    /// embedded-proof credential path uses. Call only after the cryptographic check on
    /// <paramref name="verificationMethod"/>'s own key material has already succeeded (the
    /// gate is a witness over caller-supplied identity strings, not a recompute).
    /// </summary>
    /// <param name="credential">The credential whose <c>issuer</c> claim is the claimed controller.</param>
    /// <param name="verificationMethod">The method <see cref="TryResolveIssuerAssertionMethod"/> resolved.</param>
    /// <param name="declaredProofPurpose">The proof's own declared purpose (already checked equal to <c>assertionMethod</c> by <see cref="TryResolveIssuerAssertionMethod"/>).</param>
    /// <param name="subject">The exact value the resulting <see cref="Verified{T}"/> will be minted for.</param>
    /// <returns>The bound provenance, or <see langword="null"/> when the controller check refuses.</returns>
    /// <exception cref="ArgumentNullException">A required argument is <see langword="null"/>.</exception>
    internal static BoundProvenance? TryBindIssuer(
        VerifiableCredential credential,
        VerificationMethod verificationMethod,
        string declaredProofPurpose,
        object subject)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(verificationMethod);

        string? claimedController = credential.Issuer?.Id;
        if(string.IsNullOrEmpty(claimedController)
            || string.IsNullOrEmpty(verificationMethod.Controller)
            || string.IsNullOrEmpty(verificationMethod.Id))
        {
            return null;
        }

        return BoundProvenance.TryBindByControllerArtifact(
            claimedController,
            verificationMethod.Id,
            verificationMethod.Controller,
            declaredProofPurpose,
            VerificationRelationship.AssertionMethod,
            subject);
    }
}
