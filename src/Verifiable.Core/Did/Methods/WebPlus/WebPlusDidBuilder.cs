using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;
using Verifiable.Foundation;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// The per-build state for constructing a <c>did:webplus</c> root DID document: the host, the verification /
/// update key, the timestamp, and the values derived once before the transformations run (the MBHash placeholder
/// occupying the self-hash slots, the placeholder-form DID, and the key's MBPubKey).
/// </summary>
/// <remarks>
/// This is the <c>TState</c> the <see cref="Builder{TResult,TState,TBuilder}"/> fold threads between the
/// <see cref="WebPlusDidBuilder"/> transformations. A record gives the value-equality the build-state contract
/// expects without the hand-written equality of the older struct build states.
/// </remarks>
/// <param name="UpdateKey">The Ed25519 (or other) key published as the verification method and named by the root <c>updateRules</c>.</param>
/// <param name="VerificationMethodType">The verification-method type used to represent <see cref="UpdateKey"/> (e.g. Multikey).</param>
/// <param name="MbPubKey">The MBPubKey of <see cref="UpdateKey"/> — the value the root <c>updateRules</c> <c>key</c> rule names.</param>
/// <param name="Placeholder">The MBHash placeholder occupying every self-hash slot before the document is self-hashed.</param>
/// <param name="PlaceholderDid">The DID with its trailing root-self-hash segment set to <see cref="Placeholder"/>.</param>
/// <param name="ValidFrom">The document's <c>validFrom</c> timestamp.</param>
public sealed record WebPlusDidBuildState(
    PublicKeyMemory UpdateKey,
    VerificationMethodTypeInfo VerificationMethodType,
    string MbPubKey,
    string Placeholder,
    string PlaceholderDid,
    string ValidFrom): IBuilderState;


/// <summary>
/// Builds and self-hashes a <c>did:webplus</c> <em>root</em> DID document (did:webplus Draft v0.4, DID Create;
/// WP-CTL-1, WP-SH-1). The standard W3C parts — the verification method and its relationships — are produced
/// through the SHARED DID construction (<see cref="DidBuilderExtensions.CreateVerificationMethod"/> +
/// <see cref="DidDocumentVerificationExtensions.WithStandardVerificationRelationships"/>), exactly as
/// <c>did:key</c>/<c>did:web</c> do; the did:webplus-specific control fields and the self-hash generation are
/// layered on top, so this method plugs into the builder abstraction uniformly.
/// </summary>
/// <remarks>
/// <para>
/// A root document is self-authorizing and carries no proofs (did:webplus Draft v0.4, root proofs MAY but are not
/// required), so the root builder needs no signing seam — only self-hash generation: the document is assembled
/// with the MBHash placeholder in every self-hash slot (the DID's trailing segment, the <c>selfHash</c> field,
/// and the verification method's <c>id</c>/<c>controller</c> DID suffix and <c>selfHash</c> query parameter), its
/// JCS form is hashed, and every placeholder occurrence is replaced by the resulting digest — length-preserving,
/// so the result stays JCS-canonical and the published document verifies against the same algorithm the resolver
/// runs. Producing an <em>update</em> document (WP-CTL-2), which carries proofs satisfying the predecessor's
/// <c>updateRules</c>, is a separate controller concern layered on a signing seam.
/// </para>
/// <para>
/// The JSON serialization (<see cref="WebPlusDidDocumentSerializer"/>), the hash function and the multibase
/// coders are supplied by the caller — <see cref="Verifiable.Core"/> pins none and takes no serializer
/// dependency — mirroring the seam style of <see cref="WebPlusDidResolver"/>.
/// </para>
/// </remarks>
public sealed class WebPlusDidBuilder: Builder<DidDocument, WebPlusDidBuildState, WebPlusDidBuilder>
{
    /// <summary>The serializer producing a document's JCS canonical bytes (the wire form a self-hash commits to).</summary>
    private readonly WebPlusDidDocumentSerializer serializer;

    /// <summary>The digest implementation matching <see cref="multihashCode"/>, used to compute the self-hash.</summary>
    private readonly ComputeDigestDelegate computeDigest;

    /// <summary>The digest tag naming the self-hash's algorithm for the seam, e.g. <see cref="CryptoTags.Blake3Digest"/>.</summary>
    private readonly Tag digestTag;

    /// <summary>The multihash code naming the self-hash's hash function, e.g. <see cref="MultihashHeaders.Blake3"/>.</summary>
    private readonly ReadOnlyMemory<byte> multihashCode;

    /// <summary>The digest length in bytes for the self-hash's hash function.</summary>
    private readonly int digestLength;

    /// <summary>The base64url (no padding) encoder the MBHash uses.</summary>
    private readonly EncodeDelegate base64UrlEncoder;

    /// <summary>The base58btc encoder producing the key's MBPubKey for the <c>updateRules</c> rule.</summary>
    private readonly EncodeDelegate base58Encoder;

    /// <summary>The pool the transient hash buffers are rented from.</summary>
    private readonly MemoryPool<byte> pool;


    /// <summary>
    /// Creates a did:webplus root builder bound to the JSON serializer, hash algorithm and multibase coders it
    /// mints with.
    /// </summary>
    /// <param name="serializer">Serializes a <see cref="WebPlusDidDocument"/> to its JCS bytes.</param>
    /// <param name="computeDigest">The digest implementation matching <paramref name="multihashCode"/>.</param>
    /// <param name="digestTag">The digest tag naming that algorithm for the seam, e.g. <see cref="CryptoTags.Blake3Digest"/>.</param>
    /// <param name="multihashCode">The multihash code naming the self-hash's hash function.</param>
    /// <param name="digestLength">The digest length in bytes for that hash function.</param>
    /// <param name="base64UrlEncoder">The base64url (no padding) encoder.</param>
    /// <param name="base58Encoder">The base58btc encoder producing the key's MBPubKey.</param>
    /// <param name="pool">The pool the transient hash buffers are rented from.</param>
    public WebPlusDidBuilder(
        WebPlusDidDocumentSerializer serializer,
        ComputeDigestDelegate computeDigest,
        Tag digestTag,
        ReadOnlyMemory<byte> multihashCode,
        int digestLength,
        EncodeDelegate base64UrlEncoder,
        EncodeDelegate base58Encoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(serializer);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(digestTag);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(base58Encoder);
        ArgumentNullException.ThrowIfNull(pool);

        this.serializer = serializer;
        this.computeDigest = computeDigest;
        this.digestTag = digestTag;
        this.multihashCode = multihashCode;
        this.digestLength = digestLength;
        this.base64UrlEncoder = base64UrlEncoder;
        this.base58Encoder = base58Encoder;
        this.pool = pool;

        //First transformation: the standard verification method and its relationships, via the SHARED
        //construction every method builder uses — only the did:webplus verification-method id format is specific.
        _ = With((document, builder, buildState, _) =>
        {
            string verificationMethodId = $"{buildState!.PlaceholderDid}?selfHash={buildState.Placeholder}&versionId=0#0";
            VerificationMethod verificationMethod = DidBuilderExtensions.CreateVerificationMethod(
                buildState.UpdateKey, buildState.VerificationMethodType, verificationMethodId, buildState.PlaceholderDid);
            document.VerificationMethod = [verificationMethod];
            document.WithStandardVerificationRelationships(buildState.UpdateKey, verificationMethodId);

            return ValueTask.FromResult(document);
        })
        //Second transformation: the did:webplus control fields. The root is governed by a key rule over the
        //update key's MBPubKey; selfHash holds the placeholder until the self-hash step.
        .With((document, builder, buildState, _) =>
        {
            var webPlus = (WebPlusDidDocument)document;
            webPlus.Id = new GenericDidMethod(buildState!.PlaceholderDid);
            webPlus.SelfHash = buildState.Placeholder;
            webPlus.UpdateRules = new Dictionary<string, object>(StringComparer.Ordinal) { [WellKnownWebPlusValues.UpdateRuleKey] = buildState.MbPubKey };
            webPlus.ValidFrom = buildState.ValidFrom;
            webPlus.VersionId = 0;

            return ValueTask.FromResult(document);
        })
        //Third transformation: self-hash generation. Serialize the placeholder form (the whole document,
        //relationships included), hash it, then write the digest into every self-hash slot. The slot value
        //appears in the DID suffix (the document id, each verification method's id/controller DID, and — via the
        //verification-method id — the verification-relationship references) and in the selfHash field and the
        //verification method's selfHash query parameter. Because the relationship references are immutable, they
        //are rebuilt against the final (digest) verification-method id; everything else is rewritten in place. The
        //substitution is length-preserving, so the result stays JCS-canonical and verifies against the same
        //algorithm the resolver runs.
        .With(async (document, builder, buildState, cancellationToken) =>
        {
            var webPlus = (WebPlusDidDocument)document;

            TaggedMemory<byte> placeholderJcs = builder.serializer(webPlus);
            string selfHash = await WebPlusMbHash.ComputeAsync(
                placeholderJcs.Memory, builder.multihashCode, builder.digestLength, builder.computeDigest, builder.digestTag, builder.base64UrlEncoder, builder.pool, cancellationToken).ConfigureAwait(false);

            string placeholder = buildState!.Placeholder;
            webPlus.SelfHash = selfHash;
            webPlus.Id = new GenericDidMethod(buildState.PlaceholderDid.Replace(placeholder, selfHash, StringComparison.Ordinal));

            //Clear the placeholder-form relationships (their references are immutable) so they can be re-added
            //against the final verification-method id once the verification methods carry the digest.
            webPlus.Authentication = null;
            webPlus.AssertionMethod = null;
            webPlus.KeyAgreement = null;
            webPlus.CapabilityInvocation = null;
            webPlus.CapabilityDelegation = null;

            foreach(VerificationMethod verificationMethod in webPlus.VerificationMethod!)
            {
                verificationMethod.Id = verificationMethod.Id?.Replace(placeholder, selfHash, StringComparison.Ordinal);
                verificationMethod.Controller = verificationMethod.Controller?.Replace(placeholder, selfHash, StringComparison.Ordinal);
                webPlus.WithStandardVerificationRelationships(buildState.UpdateKey, verificationMethod.Id!);
            }

            return document;
        });
    }


    /// <summary>
    /// Builds and self-hashes a did:webplus root DID document for <paramref name="host"/>, publishing
    /// <paramref name="updateKey"/> as the verification method and as the <c>updateRules</c> key rule. The
    /// resolved DID is the returned document's <see cref="WebPlusDidDocument.Id"/>; its
    /// <see cref="WebPlusDidDocument.SelfHash"/> is the root self-hash committed to by the DID's trailing segment.
    /// </summary>
    /// <param name="updateKey">The key published as the verification method and named by the root <c>updateRules</c>.</param>
    /// <param name="host">The DID host (and optional <c>%3A</c>-encoded port / path) the DID is published under.</param>
    /// <param name="validFrom">The document's <c>validFrom</c> RFC 3339 timestamp.</param>
    /// <param name="verificationMethodType">The verification-method type representing <paramref name="updateKey"/>; defaults to Multikey.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The self-hashed root <see cref="WebPlusDidDocument"/>.</returns>
    public async ValueTask<WebPlusDidDocument> BuildRootAsync(
        PublicKeyMemory updateKey,
        string host,
        string validFrom,
        VerificationMethodTypeInfo? verificationMethodType = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(updateKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(validFrom);

        string placeholder = WebPlusMbHash.Placeholder(multihashCode.Span, digestLength, base64UrlEncoder, pool);
        WebPlusDidBuildState buildState = new(
            updateKey,
            verificationMethodType ?? MultikeyVerificationMethodTypeInfo.Instance,
            MbPubKey: MultibaseSerializer.EncodeKey(updateKey, base58Encoder),
            placeholder,
            PlaceholderDid: $"{WellKnownDidMethodPrefixes.WebPlusDidMethodPrefix}:{host}:{placeholder}",
            validFrom);

        DidDocument document = await BuildAsync(
            seedGeneratorAsync: _ => ValueTask.FromResult<DidDocument>(new WebPlusDidDocument()),
            seedGeneratorParameter: buildState,
            preBuildActionAsync: (state, _) => ValueTask.FromResult(state),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return (WebPlusDidDocument)document;
    }
}
