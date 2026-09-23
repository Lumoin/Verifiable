using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Vcalm;

/// <summary>
/// The VCALM 1.0 §3.5 presenting orchestration: it COMPOSES the library's tested selective-disclosure
/// derive surface (<see cref="CredentialEcdsaSd2023Extensions.DeriveProofAsync"/>, §3.5.1) and the
/// presentation Data Integrity sign surface
/// (<see cref="PresentationDataIntegrityExtensions.SignAsync"/>, §3.5.2). It does not re-roll
/// cryptography: the cryptosuite-specific seams flow in on <see cref="VcalmCredentialDerivation"/> and
/// <see cref="VcalmPresentationSigning"/>.
/// </summary>
public static class VcalmHolderService
{
    /// <summary>
    /// §3.5.1 derive: produces a selectively-disclosed ecdsa-sd-2023 credential from
    /// <paramref name="baseCredential"/>, disclosing the claims named by
    /// <paramref name="selectivePointers"/> (plus the issuer's mandatory pointers, always revealed).
    /// The §3.5.1 <c>options.selectivePointers</c> JSON pointers map to the derive surface's requested
    /// <see cref="CredentialPath"/> set.
    /// </summary>
    /// <remarks>
    /// The derived proof is built from the base proof's own members, so every base proof must carry the
    /// <c>type</c>, <c>verificationMethod</c> and <c>proofPurpose</c>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see> requires of every
    /// proof (<see cref="HasCompleteBaseProofs"/>). The §3.5.1 endpoint refuses an input that does not with a 400 through
    /// that same predicate before it calls this method; any other caller that passes one breaks this method's precondition
    /// and is refused before any derivation, so no derived credential ever carries a defective proof forward.
    /// </remarks>
    /// <param name="baseCredential">The base-proofed ecdsa-sd-2023 credential to derive from.</param>
    /// <param name="selectivePointers">The §3.5.1 JSON pointers naming the information to disclose.</param>
    /// <param name="derivation">The application-supplied selective-disclosure derive seams.</param>
    /// <param name="context">The per-request context threaded to the canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentException">A proof of <paramref name="baseCredential"/> lacks a Data Integrity §4.4 mandatory member.</exception>
    public static async ValueTask<DataIntegritySecuredCredential> DeriveAsync(
        DataIntegritySecuredCredential baseCredential,
        ImmutableArray<string> selectivePointers,
        VcalmCredentialDerivation derivation,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(baseCredential);
        ArgumentNullException.ThrowIfNull(derivation);
        ArgumentNullException.ThrowIfNull(context);

        if(!HasCompleteBaseProofs(baseCredential))
        {
            throw new ArgumentException(VcalmVerificationService.IncompleteInputProofDetail, nameof(baseCredential));
        }

        //§3.5.1: "selectivePointers [array] An array of JSON pointers specifying the selectively
        //disclosed information." Each pointer becomes a requested CredentialPath; the derive surface
        //unions them with the issuer's mandatory pointers (always disclosed) and trims the rest.
        HashSet<CredentialPath> requestedPaths = [];
        foreach(string pointer in selectivePointers)
        {
            if(CredentialPath.TryFromJsonPointer(pointer, out CredentialPath path))
            {
                _ = requestedPaths.Add(path);
            }
        }

        return await baseCredential.DeriveProofAsync(
            requestedPaths,
            userExclusions: null,
            derivation.PartitionStatements,
            derivation.SelectFragments,
            derivation.Canonicalize,
            derivation.ContextResolver,
            derivation.SerializeCredential,
            derivation.DeserializeCredential,
            derivation.ParseBaseProof,
            derivation.SerializeDerivedProof,
            derivation.Encoder,
            derivation.Decoder,
            derivation.MemoryPool,
            context,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// §3.5.2 create-presentation: secures <paramref name="presentation"/> with a Data Integrity
    /// proof binding the §3.5.2 <c>challenge</c> / <c>domain</c> / <c>verificationMethod</c> /
    /// <c>created</c> the request supplied, falling back to the instance defaults where the request
    /// omitted them. The proof purpose is <c>authentication</c> (VC-DM 2.0 §4.13).
    /// </summary>
    /// <param name="presentation">The unproofed presentation to secure.</param>
    /// <param name="challenge">The §3.5.2 anti-replay challenge the proof binds.</param>
    /// <param name="domain">The §3.5.2 domain the proof binds.</param>
    /// <param name="verificationMethodId">
    /// The §3.5.2 <c>verificationMethod</c> the proof carries (the request value, or the instance
    /// default when the request omitted it).
    /// </param>
    /// <param name="proofCreated">The proof's <c>created</c> timestamp (the request value, or the instance clock).</param>
    /// <param name="signing">The application-supplied presentation-signing seams.</param>
    /// <param name="context">The per-request context threaded to the canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <remarks>
    /// The presentation proof covers the presentation's existing proofs and every contained credential's proofs, so each
    /// must carry the <c>type</c>, <c>verificationMethod</c> and <c>proofPurpose</c>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see> requires of every
    /// proof (<see cref="HasCompleteInputProofs"/>). The §3.5.2 endpoint refuses an input that does not with a 400 through
    /// that same predicate before it calls this method; any other caller that passes one breaks this method's precondition
    /// and is refused before any signing, so no presentation proof ever signs over a defective input proof.
    /// </remarks>
    /// <exception cref="ArgumentException">An input proof of <paramref name="presentation"/> lacks a Data Integrity §4.4 mandatory member.</exception>
    public static async ValueTask<DataIntegritySecuredPresentation> CreatePresentationAsync(
        VerifiablePresentation presentation,
        string challenge,
        string domain,
        string verificationMethodId,
        DateTime proofCreated,
        VcalmPresentationSigning signing,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(signing);
        ArgumentNullException.ThrowIfNull(context);

        if(!HasCompleteInputProofs(presentation))
        {
            throw new ArgumentException(VcalmVerificationService.IncompleteInputProofDetail, nameof(presentation));
        }

        return await presentation.SignAsync(
            signing.PrivateKey,
            verificationMethodId,
            signing.Cryptosuite,
            proofCreated,
            challenge,
            domain,
            signing.Canonicalize,
            signing.ContextResolver,
            signing.EncodeProofValue,
            signing.SerializePresentation,
            signing.DeserializePresentation,
            signing.SerializeProofOptions,
            signing.Encoder,
            signing.ComputeDigest,
            signing.MemoryPool,
            context,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Whether every proof of a §3.5.1 base credential has the members
    /// <see cref="VcalmVerificationService.HasMandatoryProofOptions"/> checks, so a derivation never carries a defective
    /// base proof into the derived credential. The derive endpoint and <see cref="DeriveAsync"/> share this one check.
    /// </summary>
    /// <param name="baseCredential">The base credential the derivation starts from.</param>
    internal static bool HasCompleteBaseProofs(DataIntegritySecuredCredential baseCredential) =>
        baseCredential.Proof is not { } proofs || proofs.All(VcalmVerificationService.HasMandatoryProofOptions);


    /// <summary>
    /// Whether every proof the §3.5.2 input carries — the presentation's own existing proofs and each contained
    /// credential's proofs — has the members <see cref="VcalmVerificationService.HasMandatoryProofOptions"/> checks,
    /// so the presentation proof never signs over a defective input proof. The create-presentation endpoint and
    /// <see cref="CreatePresentationAsync"/> share this one check.
    /// </summary>
    /// <param name="presentation">The presentation the holder is asked to secure.</param>
    internal static bool HasCompleteInputProofs(VerifiablePresentation presentation) =>
        (presentation is not DataIntegritySecuredPresentation { Proof: { } presentationProofs }
            || presentationProofs.All(VcalmVerificationService.HasMandatoryProofOptions))
        && (presentation.VerifiableCredential is not { } credentials
            || credentials.All(credential => credential is not DataIntegritySecuredCredential { Proof: { } credentialProofs }
                || credentialProofs.All(VcalmVerificationService.HasMandatoryProofOptions)));
}
