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
/// <see cref="VcalmPresentationSigning"/>. It performs no
/// <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-response-format">VCALM 1.0
/// §3.4.3.2</see> channel-domain check itself; see the <see cref="CreatePresentationAsync"/> remarks.
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
    /// and is refused before any derivation, so no derived credential ever carries a defective proof forward. Every
    /// selective pointer must be a JSON pointer (<see cref="AreAllJsonPointers"/>): one that is not is refused the same
    /// way, before any derivation, never skipped, so a derivation never silently leaves out a claim it was asked to
    /// disclose.
    /// </remarks>
    /// <param name="baseCredential">The base-proofed ecdsa-sd-2023 credential to derive from.</param>
    /// <param name="selectivePointers">The §3.5.1 JSON pointers naming the information to disclose.</param>
    /// <param name="derivation">The application-supplied selective-disclosure derive seams.</param>
    /// <param name="context">The per-request context threaded to the canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentException">
    /// A proof of <paramref name="baseCredential"/> lacks a Data Integrity §4.4 mandatory member, or an item of
    /// <paramref name="selectivePointers"/> is not a JSON pointer.
    /// </exception>
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
        //disclosed information." An item that is not a JSON pointer is data this holder cannot process
        //(§2.4), refused before any derivation rather than skipped.
        if(!AreAllJsonPointers(selectivePointers))
        {
            throw new ArgumentException(UnparseablePointerDetail, nameof(selectivePointers));
        }

        //Each pointer becomes a requested CredentialPath; the derive surface unions them with the
        //issuer's mandatory pointers (always disclosed) and trims the rest.
        HashSet<CredentialPath> requestedPaths = [];
        foreach(string pointer in selectivePointers)
        {
            _ = requestedPaths.Add(CredentialPath.FromJsonPointer(pointer));
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
    /// <c>created</c> its caller passes. The proof purpose is <c>authentication</c> (VC-DM 2.0 §4.13).
    /// </summary>
    /// <param name="presentation">The unproofed presentation to secure.</param>
    /// <param name="challenge">The §3.5.2 anti-replay challenge the proof binds.</param>
    /// <param name="domain">The §3.5.2 domain the proof binds.</param>
    /// <param name="verificationMethodId">
    /// The §3.5.2 <c>verificationMethod</c> the proof carries. The proof is signed with
    /// <see cref="VcalmPresentationSigning.PrivateKey"/>, so this must name that key's method, as the §3.5.2
    /// endpoint's <see cref="VcalmPresentationSigning.DefaultVerificationMethodId"/> does.
    /// </param>
    /// <param name="proofCreated">The proof's <c>created</c> timestamp (the request value, or the instance clock).</param>
    /// <param name="signing">The application-supplied presentation-signing seams.</param>
    /// <param name="context">The per-request context threaded to the canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <remarks>
    /// <para>
    /// A presentation that carries its own proof is refused before any signing (<see cref="HasEmbeddedProof"/>): this
    /// holder processes no embedded presentation proof, since signing over one and then replacing it yields a proof that
    /// never verifies. The presentation proof covers each contained credential's proofs, so each must carry the
    /// <c>type</c>, <c>verificationMethod</c> and <c>proofPurpose</c>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see> requires of every
    /// proof (<see cref="HasCompleteInputProofs"/>). The §3.5.2 endpoint refuses an input that fails either check with a
    /// 400 through the same predicates before it calls this method; any other caller that passes one breaks this method's
    /// precondition and is refused before any signing, so no presentation proof ever signs over an embedded proof or a
    /// defective contained proof.
    /// </para>
    /// <para>
    /// This method performs NO <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-response-format">
    /// VCALM 1.0 §3.4.3.2</see> channel-domain check: "Holder implementations MUST ensure that the domain specified by
    /// the verifier matches the domain used for the current channel of communication." It signs
    /// <paramref name="domain"/> exactly as given. The §3.5.2 <c>POST /presentations</c> endpoint enforces that MUST
    /// before calling this method, through <see cref="VcalmIntegration.ResolveVcalmChannelDomainAsync"/>; any other
    /// caller MUST confirm that <paramref name="domain"/> equals its own current communication channel's domain
    /// before calling.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// <paramref name="presentation"/> carries its own proof, or a proof of a credential it contains lacks a Data
    /// Integrity §4.4 mandatory member.
    /// </exception>
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

        if(HasEmbeddedProof(presentation))
        {
            throw new ArgumentException(EmbeddedProofDetail, nameof(presentation));
        }

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
    /// Whether every §3.5.1 selective pointer is a JSON pointer <see cref="CredentialPath.TryFromJsonPointer"/> accepts.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#derive-credential">§3.5.1</see> names "selectivePointers [array]"
    /// as "An array of JSON pointers specifying the selectively disclosed information.", so an item that is not one is
    /// an option value the holder cannot process and is refused under the
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">§2.4</see> rule that an endpoint MUST throw an error on
    /// option values it does not know how to process. The derive endpoint and <see cref="DeriveAsync"/> share this one
    /// check, in the library, so a replaced parse seam cannot bypass it.
    /// </summary>
    /// <param name="selectivePointers">The requested selective pointers.</param>
    internal static bool AreAllJsonPointers(ImmutableArray<string> selectivePointers) =>
        selectivePointers.All(pointer => CredentialPath.TryFromJsonPointer(pointer, out _));


    /// <summary>
    /// The problem detail stated when a selective pointer is not a JSON pointer: <see cref="DeriveAsync"/> throws its
    /// <see cref="ArgumentException"/> with it.
    /// </summary>
    internal static string UnparseablePointerDetail { get; } =
        "A selectivePointers item is not a JSON pointer; this holder derives only from the JSON pointers it can resolve.";


    /// <summary>
    /// Whether the §3.5.2 input presentation carries its own <c>proof</c> member. The JSON leaf reads a non-null
    /// <c>proof</c> member of any kind (a proof object, a list, an empty list, a string or a number) as a
    /// <see cref="DataIntegritySecuredPresentation"/>, so the type answers for every such shape. This holder processes no
    /// embedded presentation proof: the §3.5.2 schema's "The document MAY include an embedded proof." leaves the handling
    /// to the instance, and signing over an embedded proof and then replacing it yields a proof that never verifies, so
    /// such an input is refused under the
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">§2.4</see> rule that an endpoint MUST throw an error on data
    /// it does not know how to process. The create-presentation endpoint and <see cref="CreatePresentationAsync"/> share
    /// this one check.
    /// </summary>
    /// <param name="presentation">The presentation the holder is asked to secure.</param>
    internal static bool HasEmbeddedProof(VerifiablePresentation presentation) =>
        presentation is DataIntegritySecuredPresentation;


    /// <summary>
    /// The problem detail stated when an input presentation carries its own proof: the create-presentation endpoint's
    /// 400 carries it, and <see cref="CreatePresentationAsync"/> throws its <see cref="ArgumentException"/> with it.
    /// </summary>
    internal static string EmbeddedProofDetail { get; } =
        "The presentation to secure already carries a proof; this holder secures only a presentation that carries none.";


    /// <summary>
    /// Whether every proof of each credential the §3.5.2 input presentation contains has the members
    /// <see cref="VcalmVerificationService.HasMandatoryProofOptions"/> checks, so the presentation proof never signs over
    /// a defective contained proof. A presentation carrying its own proof is refused before this check through
    /// <see cref="HasEmbeddedProof"/>. The create-presentation endpoint and <see cref="CreatePresentationAsync"/> share
    /// this one check.
    /// </summary>
    /// <param name="presentation">The presentation the holder is asked to secure.</param>
    internal static bool HasCompleteInputProofs(VerifiablePresentation presentation) =>
        presentation.VerifiableCredential is not { } credentials
        || credentials.All(credential => credential is not DataIntegritySecuredCredential { Proof: { } credentialProofs }
            || credentialProofs.All(VcalmVerificationService.HasMandatoryProofOptions));
}
