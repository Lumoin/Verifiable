using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// The shared resolving identity-binding gate for the Tier-C credential envelope surfaces
/// (<see cref="CredentialJwsExtensions"/>, <see cref="CredentialCoseExtensions"/>): the DIDComm
/// Tier-A recipe (<c>DidCommSignedExtensions.UnpackSignedAsync</c>) adapted to a credential's own
/// signed <c>issuer</c> claim rather than a DIDComm plaintext <c>from</c>.
/// </summary>
/// <remarks>
/// Every gate below is a fail-closed short-circuit BEFORE any cryptographic check runs, matching
/// DIDComm's own four-gate sequence:
/// <list type="number">
/// <item><description>The wire <c>kid</c> must parse as an absolute DID URL naming a base DID.</description></item>
/// <item><description>That base DID must equal the credential's signed <c>issuer</c> claim.</description></item>
/// <item><description>The DID is resolved INSIDE this method via the injected <see cref="DidResolver"/> — never a caller-handed document.</description></item>
/// <item><description>The method must be listed under the resolved document's <c>assertionMethod</c> relationship, not merely present in the flat verification-method array.</description></item>
/// </list>
/// Only a caller past all four gates receives a resolved <see cref="VerificationMethod"/>; extracting
/// key material and running the cryptographic check against it is the caller's next (and final) step.
/// </remarks>
internal static class CredentialEnvelopeIdentityBinding
{
    /// <summary>
    /// Runs the four resolving gates and returns the resolved verification method together with the
    /// document it resolved from, or <see langword="null"/> when any gate refuses.
    /// </summary>
    /// <param name="kid">The <c>kid</c> read from the envelope's protected header. Absent → refuse.</param>
    /// <param name="issuerId">The credential's signed <c>issuer</c> claim. Absent → refuse.</param>
    /// <param name="didResolver">The resolver this method calls to resolve the kid's base DID.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The resolved method and its document, or <see langword="null"/> on any gate refusal.</returns>
    internal static async ValueTask<(VerificationMethod Method, DidDocument Document)?> TryResolveAssertionMethodAsync(
        string? kid,
        string? issuerId,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);

        if(string.IsNullOrEmpty(kid) || string.IsNullOrEmpty(issuerId))
        {
            return null;
        }

        //Gate 1: the kid must name a base DID -- an unparseable kid cannot be bound to anything.
        if(!DidUrl.TryParse(kid, out DidUrl? kidUrl) || kidUrl.BaseDid is not string keyBaseDid)
        {
            return null;
        }

        //Gate 2: addressing-consistency -- the kid's base DID must equal the credential's own signed
        //issuer claim, the same-shape analogue of DIDComm's `from` == `kid` MUST.
        string issuerBaseDid = DidUrl.TryParse(issuerId, out DidUrl? issuerUrl) && issuerUrl.BaseDid is string parsedIssuerBaseDid
            ? parsedIssuerBaseDid
            : issuerId;

        if(!string.Equals(keyBaseDid, issuerBaseDid, StringComparison.Ordinal))
        {
            return null;
        }

        //Gate 3: resolve INSIDE this method via the injected resolver -- never a caller-handed document.
        DidResolutionResult resolution = await didResolver
            .ResolveAsync(keyBaseDid, exchangeContext, options: null, cancellationToken)
            .ConfigureAwait(false);

        if(!resolution.IsSuccessful || resolution.Document is null)
        {
            return null;
        }

        //Gate 4: relationship-scoped lookup -- the method must be listed under assertionMethod, not
        //merely present in the document's flat verificationMethod array (VC-JOSE-COSE's issuer proof
        //purpose is assertionMethod, mirroring the DataIntegrity credential path's own scoping).
        VerificationMethod? method = resolution.Document.GetLocalAssertionMethodById(kid);

        return method is null ? null : (method, resolution.Document);
    }


    /// <summary>
    /// Normalizes a possibly-relative verification method id to its absolute form against
    /// <paramref name="document"/>'s own DID, the same normalization
    /// <c>ResolveVerificationMethodReference</c> and <c>DidResolver.ExpandRelativeUrls</c> already
    /// apply — so a <c>BoundProvenance.TryBindByResolvedMethod</c> consistency check compares the
    /// claimed absolute <c>kid</c> against a like-for-like absolute method id, regardless of whether
    /// the resolved document itself defines the method with a relative (<c>"#key-1"</c>) or absolute id.
    /// </summary>
    /// <param name="method">The resolved verification method.</param>
    /// <param name="document">The document <paramref name="method"/> was resolved from.</param>
    /// <returns>The absolute method id, or <see langword="null"/> when the method carries no id.</returns>
    internal static string? ExpandMethodId(VerificationMethod method, DidDocument document)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(document);

        string? methodId = method.Id;
        if(methodId is null)
        {
            return null;
        }

        return methodId.StartsWith('#') && document.Id is not null
            ? $"{document.Id}{methodId}"
            : methodId;
    }
}
