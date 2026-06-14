using System.Collections.Immutable;
using System.Diagnostics;
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
[DebuggerDisplay("VcalmHolderService")]
public static class VcalmHolderService
{
    /// <summary>
    /// §3.5.1 derive: produces a selectively-disclosed ecdsa-sd-2023 credential from
    /// <paramref name="baseCredential"/>, disclosing the claims named by
    /// <paramref name="selectivePointers"/> (plus the issuer's mandatory pointers, always revealed).
    /// The §3.5.1 <c>options.selectivePointers</c> JSON pointers map to the derive surface's requested
    /// <see cref="CredentialPath"/> set.
    /// </summary>
    /// <param name="baseCredential">The base-proofed ecdsa-sd-2023 credential to derive from.</param>
    /// <param name="selectivePointers">The §3.5.1 JSON pointers naming the information to disclose.</param>
    /// <param name="derivation">The application-supplied selective-disclosure derive seams.</param>
    /// <param name="context">The per-request context threaded to the canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
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

        //§3.5.1: "selectivePointers [array] An array of JSON pointers specifying the selectively
        //disclosed information." Each pointer becomes a requested CredentialPath; the derive surface
        //unions them with the issuer's mandatory pointers (always disclosed) and trims the rest.
        HashSet<CredentialPath> requestedPaths = [];
        foreach(string pointer in selectivePointers)
        {
            if(CredentialPath.TryFromJsonPointer(pointer, out CredentialPath path))
            {
                requestedPaths.Add(path);
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
}
