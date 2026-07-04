using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Core.Model.Did;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// Resolves <c>did:webplus</c> identifiers per the
/// <see href="https://ledgerdomain.github.io/did-webplus-spec/">did:webplus method specification (LedgerDomain Draft v0.4)</see>.
/// </summary>
/// <remarks>
/// <para>
/// <c>did:webplus</c> is a JCS web microledger DID: a Verifiable Data Registry (VDR) serves a DID's history as a
/// <c>did-documents.jsonl</c> file (a newline-delimited concatenation of the ordered, JCS-serialized DID
/// documents) at the same kind of web location <c>did:web</c> uses. The identifier is
/// <c>did:webplus:&lt;host&gt;[%3A&lt;port&gt;][:&lt;path&gt;...]:&lt;root-self-hash&gt;</c>; the trailing
/// <c>root-self-hash</c> is the <c>selfHash</c> of the root DID document, cryptographically committing the DID
/// to the content of its root document.
/// </para>
/// <list type="bullet">
///   <item><description><c>did:webplus:example.com:uHiB…NEA</c> → <c>https://example.com/uHiB…NEA/did-documents.jsonl</c></description></item>
///   <item><description><c>did:webplus:example.com:p1:uHiB…NEA</c> → <c>https://example.com/p1/uHiB…NEA/did-documents.jsonl</c></description></item>
///   <item><description><c>did:webplus:example.com%3A3000:p1:uHiB…NEA</c> → <c>https://example.com:3000/p1/uHiB…NEA/did-documents.jsonl</c></description></item>
///   <item><description><c>did:webplus:localhost:uHiB…NEA</c> → <c>http://localhost/uHiB…NEA/did-documents.jsonl</c></description></item>
/// </list>
/// <para>
/// <see cref="Resolve"/> computes the microledger URL only (the DID-to-URL transform). Full resolution — fetching
/// the <c>did-documents.jsonl</c>, replaying and verifying every entry through the
/// <see cref="Verifiable.Cryptography.EventLogs.LogReplayer{TState,TOperation,TProof,TContext}"/>, and returning the resolved DID document
/// — is layered on top in later steps.
/// </para>
/// </remarks>
public static class WebPlusDidResolver
{
    /// <summary>
    /// An upper bound on the fetched <c>did-documents.jsonl</c> size, so a malicious or misconfigured VDR cannot
    /// exhaust resolver memory/CPU by serving an unbounded microledger (verifying every document is
    /// JCS-canonicalize + hash + per-proof signature). The bound is generous relative to a real microledger (each
    /// document is one JSON line) yet rejects an obviously hostile payload. Enforced before the body is parsed.
    /// </summary>
    private const int MaxMicroledgerBytes = 8 * 1024 * 1024;

    /// <summary>
    /// The canonical media type of a resolved did:webplus DID document. did:webplus has a single canonical form
    /// (the JCS-serialized DID document), so the resolver always returns that representation regardless of the
    /// resolution <c>accept</c> option (WP-RO-1).
    /// </summary>
    private const string DidDocumentMediaType = "application/did+json";

    /// <summary>
    /// Computes the microledger (<c>did-documents.jsonl</c>) URL for a <c>did:webplus</c> identifier by applying
    /// the did:webplus DID-to-URL transform: drop the <c>did:webplus:</c> prefix, map the colon-delimited
    /// segments to path segments, percent-decode (which restores a <c>%3A</c>-encoded port colon), append the
    /// microledger file name, and prepend <c>http</c> for <c>localhost</c> or <c>https</c> otherwise.
    /// </summary>
    /// <param name="didWebPlusIdentifier">A valid <c>did:webplus</c> identifier string.</param>
    /// <returns>The URL where the DID's microledger (<c>did-documents.jsonl</c>) is published.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="didWebPlusIdentifier"/> is <see langword="null"/>, empty, whitespace, does not
    /// start with the <c>did:webplus:</c> prefix, or has no root-self-hash segment after the host.
    /// </exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "DID identifiers contain method-specific syntax that System.Uri does not handle correctly.")]
    public static string Resolve(string didWebPlusIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didWebPlusIdentifier);

        string prefixWithColon = $"{WellKnownDidMethodPrefixes.WebPlusDidMethodPrefix}:";
        if(!didWebPlusIdentifier.StartsWith(prefixWithColon, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The given DID identifier '{didWebPlusIdentifier}' is not a valid did:webplus identifier.",
                nameof(didWebPlusIdentifier));
        }

        return WebHttpsTransform.MapToUrl(didWebPlusIdentifier[prefixWithColon.Length..], didWebPlusIdentifier, TransformPolicy);
    }


    /// <summary>
    /// The did:webplus DID-to-URL policy: no leading segment precedes the host, the host is not IDNA-encoded, a
    /// <c>localhost</c> host selects <c>http</c> (local development) while every other host uses <c>https</c>, no
    /// <c>/.well-known</c> segment is inserted, the identifier MUST carry a trailing root-self-hash path segment,
    /// each path segment is percent-decoded (did:webplus DID-to-URL Mapping), and the document file is the
    /// microledger file.
    /// </summary>
    private static WebHttpsTransformPolicy TransformPolicy { get; } = new()
    {
        LeadingSegmentsToDrop = 0,
        IdnaEncodeHost = false,
        LocalhostUsesHttp = true,
        WellKnownWhenNoPath = false,
        MinimumPathSegments = 1,
        SegmentMapping = WebHttpsSegmentMapping.Decode,
        DocumentFileName = WellKnownWebPlusValues.DidDocumentsFile
    };


    /// <summary>
    /// Resolves the registered <see cref="ComputeDigestDelegate"/> for the BLAKE3-default <see cref="Build"/> overload.
    /// </summary>
    /// <returns>The registered digest delegate.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no <see cref="ComputeDigestDelegate"/> is registered.</exception>
    private static ComputeDigestDelegate ResolveRegisteredDigest()
        => CryptographicKeyFactory.GetFunction<ComputeDigestDelegate>(typeof(ComputeDigestDelegate))
            ?? throw new InvalidOperationException(
                $"No {nameof(ComputeDigestDelegate)} has been registered. Supply one to the explicit {nameof(Build)} overload "
                + "or register one via CryptographicKeyFactory.RegisterFunction during application startup.");


    /// <summary>
    /// Builds a <c>did:webplus</c> resolver with the method's default self-hash algorithm (BLAKE3-256) and the
    /// registered <see cref="ComputeDigestDelegate"/>. Use the explicit overload to control the digest implementation
    /// or to verify a microledger self-hashed under a different MUST-support algorithm.
    /// </summary>
    /// <param name="transport">The application-supplied single-hop transport the guarded fetch drives.</param>
    /// <param name="documentParser">The strict verifier parser producing a <see cref="WebPlusDidDocument"/> from a microledger line.</param>
    /// <param name="updateRulesParser">Parses a document's <c>updateRules</c> into a <see cref="WebPlusUpdateRule"/> tree.</param>
    /// <param name="proofExtractor">Extracts a document's proofs and the JCS of the document with <c>proofs</c> removed.</param>
    /// <param name="canonicalizer">The JCS canonicalizer the byte-equality validation step compares against.</param>
    /// <param name="documentDeserializer">Deserializes the resolved line into the full <see cref="DidDocument"/> returned to the caller.</param>
    /// <param name="base64UrlEncoder">The base64url (no padding) encoder.</param>
    /// <param name="base64UrlDecoder">The base64url (no padding) decoder.</param>
    /// <param name="base58Decoder">The base58btc decoder, used when an MBPubKey is in its base58btc (<c>z</c>) form.</param>
    /// <param name="pool">The pool the transient hash, key and signature buffers are rented from.</param>
    /// <param name="timeProvider">The clock the verification consults for any time-bounded check.</param>
    /// <returns>A <see cref="DidMethodResolverDelegate"/> for registration with the resolver composition.</returns>
    public static DidMethodResolverDelegate Build(
        OutboundTransportDelegate transport,
        WebPlusDidDocumentParser documentParser,
        WebPlusUpdateRuleParser updateRulesParser,
        WebPlusProofExtractor proofExtractor,
        WebPlusJcsCanonicalizer canonicalizer,
        WebPlusDocumentDeserializer documentDeserializer,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        DecodeDelegate base58Decoder,
        MemoryPool<byte> pool,
        TimeProvider timeProvider)
        => Build(transport, documentParser, updateRulesParser, proofExtractor, canonicalizer, documentDeserializer,
            ResolveRegisteredDigest(), CryptoTags.Blake3Digest, MultihashHeaders.Blake3.ToArray(), Blake3DigestLength,
            base64UrlEncoder, base64UrlDecoder, base58Decoder, pool, timeProvider);


    /// <summary>The BLAKE3-256 digest length in bytes, the did:webplus default self-hash output size.</summary>
    private const int Blake3DigestLength = 32;


    /// <summary>
    /// Builds a <see cref="DidMethodResolverDelegate"/> that fully resolves a <c>did:webplus</c>: it computes the
    /// microledger URL, fetches the <c>did-documents.jsonl</c> through the guarded
    /// <see cref="OutboundFetch"/> chokepoint, replays and verifies every document through the
    /// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> (self-hash, the
    /// <c>prevDIDDocumentSelfHash</c> chain, every proof, and the cross-document obligations), selects the
    /// requested version, and returns the resolved <see cref="DidDocument"/> with its metadata.
    /// </summary>
    /// <param name="transport">The application-supplied single-hop transport the guarded fetch drives.</param>
    /// <param name="documentParser">The strict verifier parser producing a <see cref="WebPlusDidDocument"/> from a microledger line.</param>
    /// <param name="updateRulesParser">Parses a document's <c>updateRules</c> into a <see cref="WebPlusUpdateRule"/> tree.</param>
    /// <param name="proofExtractor">Extracts a document's proofs and the JCS of the document with <c>proofs</c> removed.</param>
    /// <param name="canonicalizer">The JCS canonicalizer the byte-equality validation step compares against.</param>
    /// <param name="documentDeserializer">Deserializes the resolved line into the full <see cref="DidDocument"/> returned to the caller.</param>
    /// <param name="computeDigest">The digest implementation matching <paramref name="multihashCode"/>, used to verify each self-hash.</param>
    /// <param name="digestTag">The digest tag naming that algorithm for the seam, e.g. <see cref="CryptoTags.Blake3Digest"/>.</param>
    /// <param name="multihashCode">The multihash code naming the self-hash's hash function, e.g. <see cref="MultihashHeaders.Blake3"/>.</param>
    /// <param name="digestLength">The digest length in bytes for the self-hash's hash function.</param>
    /// <param name="base64UrlEncoder">The base64url (no padding) encoder.</param>
    /// <param name="base64UrlDecoder">The base64url (no padding) decoder.</param>
    /// <param name="base58Decoder">The base58btc decoder, used when an MBPubKey is in its base58btc (<c>z</c>) form.</param>
    /// <param name="pool">The pool the transient hash, key and signature buffers are rented from.</param>
    /// <param name="timeProvider">The clock the verification consults for any time-bounded check.</param>
    /// <returns>A <see cref="DidMethodResolverDelegate"/> for registration with the resolver composition.</returns>
    public static DidMethodResolverDelegate Build(
        OutboundTransportDelegate transport,
        WebPlusDidDocumentParser documentParser,
        WebPlusUpdateRuleParser updateRulesParser,
        WebPlusProofExtractor proofExtractor,
        WebPlusJcsCanonicalizer canonicalizer,
        WebPlusDocumentDeserializer documentDeserializer,
        ComputeDigestDelegate computeDigest,
        Tag digestTag,
        ReadOnlyMemory<byte> multihashCode,
        int digestLength,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        DecodeDelegate base58Decoder,
        MemoryPool<byte> pool,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(documentParser);
        ArgumentNullException.ThrowIfNull(updateRulesParser);
        ArgumentNullException.ThrowIfNull(proofExtractor);
        ArgumentNullException.ThrowIfNull(canonicalizer);
        ArgumentNullException.ThrowIfNull(documentDeserializer);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(digestTag);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base58Decoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        WebPlusValidationContext validationContext = new()
        {
            Parser = documentParser,
            Canonicalizer = canonicalizer,
            ProofExtractor = proofExtractor,
            ComputeDigest = computeDigest,
            DigestTag = digestTag,
            MultihashCode = multihashCode,
            DigestLength = digestLength,
            Base64UrlEncoder = base64UrlEncoder,
            Base64UrlDecoder = base64UrlDecoder,
            Base58Decoder = base58Decoder,
            HashedKeyMatcher = WebPlusHashedKey.CreateMatcher(multihashCode, digestLength, computeDigest, digestTag, base64UrlEncoder, pool),
            MemoryPool = pool,
            TimeProvider = timeProvider
        };

        LogReplayContext<WebPlusState, WebPlusRawEntry, string, WebPlusValidationContext> replayContext = new()
        {
            Classify = WebPlusMicroledger.ClassifyEntry,
            VerifyChainIntegrity = WebPlusMicroledger.CreateChainVerification(validationContext),
            ValidateProof = WebPlusMicroledger.ValidateProofAsync,
            ValidationContext = validationContext,
            Apply = WebPlusMicroledger.ApplyEntry,
            TimeProvider = timeProvider
        };

        return async (did, options, context, cancellationToken) =>
        {
            string logUrl;
            try
            {
                logUrl = Resolve(did);
            }
            catch(ArgumentException)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            //WP-ID-1: the DID's trailing <root-self-hash> segment commits the DID to its root document. It MUST
            //equal the root document's selfHash; otherwise the DID does not name this microledger.
            if(!TryGetRootSelfHash(did, out string? rootSelfHash))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            if(!Uri.TryCreate(logUrl, UriKind.Absolute, out Uri? target))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            OutboundResponse? microledgerResponse = await TryFetchMicroledgerAsync(target, transport, context, cancellationToken).ConfigureAwait(false);
            if(microledgerResponse is null)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            //Bound the fetched microledger so an oversized payload is rejected before it is parsed, rather than
            //driving unbounded allocation through the entry parser.
            if(microledgerResponse.Body.Memory.Length > MaxMicroledgerBytes)
            {
                return DidResolutionResult.Failure(InvalidDid("The did:webplus microledger exceeds the maximum permitted size."));
            }

            List<LogEntry<WebPlusRawEntry, string>> entries;
            try
            {
                entries = ParseEntries(microledgerResponse.Body.Memory, documentParser, updateRulesParser, proofExtractor);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            if(entries.Count == 0)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            //WP-ID-1: bind the DID to its root (genesis) document — the first line's selfHash MUST equal the DID's
            //<root-self-hash>, and its id MUST be the DID being resolved. The chain's id-equality (WP-VAL-7a) then
            //carries that binding to every later document.
            WebPlusDidDocument rootDocument = entries[0].Operation!.Document;
            if(!string.Equals(rootDocument.SelfHash, rootSelfHash, StringComparison.Ordinal)
                || !string.Equals(rootDocument.Id?.Id, did, StringComparison.Ordinal))
            {
                return DidResolutionResult.Failure(InvalidDid("The did:webplus root document does not match the DID's root-self-hash."));
            }

            //Select the requested version (selfHash/versionId query parameters), or the latest document. Only the
            //entries up to and including the target are replayed and verified, so a version query targeting a
            //valid earlier version resolves even if later entries are invalid (WP-RES-1/2).
            (int targetIndex, DidProblemDetails? selectionError) = SelectTargetEntry(entries, options);
            if(selectionError is not null)
            {
                return DidResolutionResult.Failure(selectionError);
            }

            LogReplayer<WebPlusState, WebPlusRawEntry, string, WebPlusValidationContext> replayer = new();
            List<WebPlusState> states = new(targetIndex + 1);
            WebPlusState? finalState = null;
            LogEntry<WebPlusRawEntry, string>? finalEntry = null;
            bool isDeactivated = false;
            bool isDeactivatedByLaterEntry = false;
            string? replayError = null;
            int replayIndex = -1;

            await foreach(LogReplayResult<WebPlusState, WebPlusRawEntry, string> result in
                replayer.ReplayAsync(ToAsync(entries, cancellationToken), replayContext, cancellationToken).ConfigureAwait(false))
            {
                if(result.Error is not null)
                {
                    //An error at or before the target invalidates the resolved version; an error after the target
                    //ends the verified chain but does not fail a valid prior-version query.
                    if(replayIndex + 1 <= targetIndex)
                    {
                        replayError = result.Error;
                    }

                    break;
                }

                replayIndex++;

                if(replayIndex <= targetIndex)
                {
                    finalEntry = result.Entry;
                    switch(result.State)
                    {
                        case ActiveLogState<WebPlusState> active:
                            finalState = active.Value;
                            states.Add(active.Value);
                            isDeactivated = false;
                            break;
                        case DeactivatedLogState<WebPlusState> deactivated:
                            finalState = deactivated.Value;
                            states.Add(deactivated.Value);
                            isDeactivated = true;
                            break;
                    }
                }
                else if(result.State is DeactivatedLogState<WebPlusState>)
                {
                    //A VERIFIED later document deactivates the DID; deactivation is terminal, so stop the scan. A
                    //prior version still resolves but carries deactivated:true (WP-MD-7).
                    isDeactivatedByLaterEntry = true;

                    break;
                }
            }

            if(replayError is not null)
            {
                //A verification failure renders the did:webplus DID invalid; the precise replay message becomes
                //the problemDetails.Detail (WP-VAL-0).
                return DidResolutionResult.Failure(InvalidDid(replayError));
            }

            if(finalEntry is null || finalState is null)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            bool isResolvedVersionDeactivated = isDeactivated || isDeactivatedByLaterEntry;

            DidDocumentMetadata metadata = new()
            {
                VersionId = finalState.VersionId.ToString(CultureInfo.InvariantCulture),
                Deactivated = isResolvedVersionDeactivated,
                Created = ParseTimestamp(states[0].ValidFrom),
                Updated = ParseTimestamp(finalState.ValidFrom)
            };

            //When the resolved version is itself the deactivation, the resolver MUST NOT return the DIDDoc: a
            //result with a null document and deactivated:true metadata (WP-CTL-3 tombstone). A prior version
            //queried on a deactivated DID still returns its DIDDoc with deactivated:true (handled above).
            if(isDeactivated)
            {
                return DidResolutionResult.SuccessDeactivated(metadata, contentType: DidDocumentMediaType);
            }

            DidDocument? document;
            try
            {
                document = documentDeserializer(finalEntry.CanonicalBytes.Span);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            if(document is null)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            return DidResolutionResult.Success(document, metadata, contentType: DidDocumentMediaType);
        };
    }


    /// <summary>
    /// Extracts the DID's trailing <c>&lt;root-self-hash&gt;</c> segment: the last <c>':'</c>-delimited segment
    /// after the <c>did:webplus:</c> prefix (the host's <c>%3A</c>-encoded port is not a real colon, so it stays
    /// within the host segment). A DID with no segment after the host has no root-self-hash and is malformed.
    /// </summary>
    /// <param name="did">The DID being resolved.</param>
    /// <param name="rootSelfHash">When this returns <see langword="true"/>, the DID's root-self-hash segment.</param>
    /// <returns><see langword="true"/> when a root-self-hash segment is present; otherwise <see langword="false"/>.</returns>
    private static bool TryGetRootSelfHash(string did, [NotNullWhen(true)] out string? rootSelfHash)
    {
        rootSelfHash = null;

        string prefixWithColon = $"{WellKnownDidMethodPrefixes.WebPlusDidMethodPrefix}:";
        if(!did.StartsWith(prefixWithColon, StringComparison.Ordinal))
        {
            return false;
        }

        string[] segments = did[prefixWithColon.Length..].Split(':');
        if(segments.Length < 2 || segments[0].Length == 0 || segments[^1].Length == 0)
        {
            return false;
        }

        rootSelfHash = segments[^1];

        return true;
    }


    /// <summary>
    /// Drives one guarded fetch for the microledger, returning the response only on a successful 200, or
    /// <see langword="null"/> on a transport failure or any non-200 status. Cancellation is always propagated.
    /// </summary>
    /// <param name="target">The microledger URL to fetch.</param>
    /// <param name="transport">The single-hop transport the guarded fetch drives.</param>
    /// <param name="context">The per-operation context carrying the SSRF outbound-fetch policy.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The successful response, or <see langword="null"/> when the fetch did not yield a 200.</returns>
    private static async ValueTask<OutboundResponse?> TryFetchMicroledgerAsync(
        Uri target,
        OutboundTransportDelegate transport,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        OutboundRequest request = new() { Target = target, Method = "GET", MaxResponseBytes = MaxMicroledgerBytes };

        OutboundFetchResult fetch;
        try
        {
            fetch = await Verifiable.Core.OutboundFetch.OutboundFetch.FetchAsync(request, context, transport, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }

        return fetch is { IsFetched: true, Response: { StatusCode: 200 } response } ? response : null;
    }


    /// <summary>
    /// Selects the microledger entry index the resolution targets per the version-query parameters: a numeric
    /// versionId (the did:webplus <c>versionId</c> is an unsigned integer), a <c>selfHash</c> MBHash, the document
    /// active at a requested <c>versionTime</c> (the latest whose <c>validFrom</c> is at or before it), or — with
    /// no version query — the latest document. A requested version that is absent is a NotFound (WP-RES-1/2).
    /// </summary>
    /// <param name="entries">The parsed microledger entries.</param>
    /// <param name="options">The resolution options carrying any version query.</param>
    /// <returns>The target entry index and a <see langword="null"/> error, or <c>-1</c> and a NotFound problem.</returns>
    private static (int Index, DidProblemDetails? Error) SelectTargetEntry(
        List<LogEntry<WebPlusRawEntry, string>> entries,
        DidResolutionOptions options)
    {
        if(options.VersionNumber is int number)
        {
            return number >= 0 ? SelectByVersionId(entries, (ulong)number) : (-1, DidResolutionErrors.NotFound);
        }

        if(options.VersionId is { Length: > 0 } versionId)
        {
            //A numeric query selects by the unsigned-integer versionId; any other value is a selfHash MBHash
            //selector (the did:webplus selfHash/versionId query parameters; WP-RES-2).
            return ulong.TryParse(versionId, NumberStyles.None, CultureInfo.InvariantCulture, out ulong parsed)
                ? SelectByVersionId(entries, parsed)
                : SelectBySelfHash(entries, versionId);
        }

        if(options.VersionTime is DateTimeOffset versionTime)
        {
            int active = -1;
            for(int i = 0; i < entries.Count; i++)
            {
                if(ParseTimestamp(entries[i].Operation?.Document.ValidFrom) is DateTimeOffset entryTime && entryTime <= versionTime)
                {
                    active = i;
                }
            }

            return active >= 0 ? (active, null) : (-1, DidResolutionErrors.NotFound);
        }

        return (entries.Count - 1, null);
    }


    /// <summary>
    /// Selects the entry whose document <c>versionId</c> equals the requested value, or NotFound when no such
    /// document exists in the microledger.
    /// </summary>
    /// <param name="entries">The parsed microledger entries.</param>
    /// <param name="versionId">The requested <c>versionId</c>.</param>
    /// <returns>The matching entry index and a <see langword="null"/> error, or <c>-1</c> and a NotFound problem.</returns>
    private static (int Index, DidProblemDetails? Error) SelectByVersionId(List<LogEntry<WebPlusRawEntry, string>> entries, ulong versionId)
    {
        for(int i = 0; i < entries.Count; i++)
        {
            if(entries[i].Operation?.Document.VersionId == versionId)
            {
                return (i, null);
            }
        }

        return (-1, DidResolutionErrors.NotFound);
    }


    /// <summary>
    /// Selects the entry whose document <c>selfHash</c> equals the requested MBHash, or NotFound when no such
    /// document exists in the microledger.
    /// </summary>
    /// <param name="entries">The parsed microledger entries.</param>
    /// <param name="selfHash">The requested <c>selfHash</c> MBHash.</param>
    /// <returns>The matching entry index and a <see langword="null"/> error, or <c>-1</c> and a NotFound problem.</returns>
    private static (int Index, DidProblemDetails? Error) SelectBySelfHash(List<LogEntry<WebPlusRawEntry, string>> entries, string selfHash)
    {
        for(int i = 0; i < entries.Count; i++)
        {
            if(string.Equals(entries[i].Operation?.Document.SelfHash, selfHash, StringComparison.Ordinal))
            {
                return (i, null);
            }
        }

        return (-1, DidResolutionErrors.NotFound);
    }


    /// <summary>
    /// Parses a did:webplus <c>validFrom</c> / metadata RFC 3339 timestamp into a <see cref="DateTimeOffset"/>, or
    /// <see langword="null"/> when it is absent or unparseable. The replay already validated the resolved chain's
    /// <c>validFrom</c> fields, so the metadata timestamps are well-formed; an unparseable value simply yields a
    /// <see langword="null"/> metadata timestamp.
    /// </summary>
    /// <param name="timestamp">The RFC 3339 timestamp string, or <see langword="null"/>.</param>
    /// <returns>The parsed timestamp, or <see langword="null"/> when absent or unparseable.</returns>
    private static DateTimeOffset? ParseTimestamp(string? timestamp)
    {
        return timestamp is { Length: > 0 } value
            && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset parsed)
            ? parsed
            : null;
    }


    /// <summary>
    /// did:webplus resolution maps every invalidating condition to the invalidDid error; a precise message is
    /// carried as the occurrence-specific <c>problemDetails.Detail</c>. The detail-free form equals the shared
    /// <see cref="DidResolutionErrors.InvalidDid"/> by problem-type, so callers can still compare by type.
    /// </summary>
    /// <param name="detail">The occurrence-specific detail, or <see langword="null"/> for the shared instance.</param>
    /// <returns>The invalid-DID problem details.</returns>
    private static DidProblemDetails InvalidDid(string? detail)
    {
        return detail is null
            ? DidResolutionErrors.InvalidDid
            : new DidProblemDetails(DidErrorTypes.InvalidDid, Title: "Invalid DID", Detail: detail);
    }


    /// <summary>
    /// Splits the fetched <c>did-documents.jsonl</c> into entries, slicing each JCS document line out of the
    /// fetched buffer (no re-encode): the line slice backs the entry's <c>CanonicalBytes</c> that the verification
    /// re-parses, so the byte-equality validation step (WP-VAL-1) decides whether the served line was already JCS.
    /// </summary>
    /// <param name="body">The fetched microledger body.</param>
    /// <param name="documentParser">The strict verifier parser for a microledger line.</param>
    /// <param name="updateRulesParser">The parser producing a line's <see cref="WebPlusUpdateRule"/> tree.</param>
    /// <param name="proofExtractor">The extractor producing a line's proofs and signing-input base.</param>
    /// <returns>The parsed log entries, one per non-empty line.</returns>
    private static List<LogEntry<WebPlusRawEntry, string>> ParseEntries(
        ReadOnlyMemory<byte> body,
        WebPlusDidDocumentParser documentParser,
        WebPlusUpdateRuleParser updateRulesParser,
        WebPlusProofExtractor proofExtractor)
    {
        var entries = new List<LogEntry<WebPlusRawEntry, string>>();
        ReadOnlySpan<byte> span = body.Span;
        ulong index = 0;
        int start = 0;

        for(int i = 0; i <= span.Length; i++)
        {
            if(i < span.Length && span[i] != (byte)'\n')
            {
                continue;
            }

            ReadOnlyMemory<byte> line = TrimAsciiWhitespace(body[start..i]);
            start = i + 1;
            if(line.IsEmpty)
            {
                continue;
            }

            WebPlusDidDocument document = documentParser(line.Span);
            WebPlusUpdateRule updateRules = updateRulesParser(line.Span);
            WebPlusProofExtraction extraction = proofExtractor(line);

            ReadOnlyMemory<byte>? previousDigest = document.PrevDidDocumentSelfHash is { Length: > 0 } previous
                ? Encoding.UTF8.GetBytes(previous)
                : null;

            entries.Add(new LogEntry<WebPlusRawEntry, string>
            {
                Index = index,
                PreviousDigest = previousDigest,
                Digest = Encoding.UTF8.GetBytes(document.SelfHash ?? string.Empty),
                CanonicalBytes = line,
                Operation = new WebPlusRawEntry(document, updateRules),
                Proofs = extraction.Proofs
            });

            index++;
        }

        return entries;
    }


    /// <summary>
    /// Trims leading and trailing ASCII whitespace from a microledger line slice, so a line padded with spaces or
    /// carriage returns is parsed by its content rather than rejected for the surrounding whitespace.
    /// </summary>
    /// <param name="value">The line slice to trim.</param>
    /// <returns>The slice with leading and trailing ASCII whitespace removed.</returns>
    private static ReadOnlyMemory<byte> TrimAsciiWhitespace(ReadOnlyMemory<byte> value)
    {
        ReadOnlySpan<byte> span = value.Span;
        int begin = 0;
        int end = span.Length;

        while(begin < end && IsAsciiWhitespace(span[begin]))
        {
            begin++;
        }

        while(end > begin && IsAsciiWhitespace(span[end - 1]))
        {
            end--;
        }

        return value[begin..end];
    }


    /// <summary>Whether the byte is an ASCII space, tab, carriage return or line feed.</summary>
    /// <param name="value">The byte to test.</param>
    /// <returns><see langword="true"/> when the byte is ASCII whitespace.</returns>
    private static bool IsAsciiWhitespace(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';


    /// <summary>
    /// Adapts the parsed entries to the <see cref="IAsyncEnumerable{T}"/> the
    /// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> consumes, observing cancellation per entry.
    /// </summary>
    /// <param name="entries">The parsed microledger entries.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The entries as an async stream.</returns>
    private static async IAsyncEnumerable<LogEntry<WebPlusRawEntry, string>> ToAsync(
        List<LogEntry<WebPlusRawEntry, string>> entries,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach(LogEntry<WebPlusRawEntry, string> entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;

            await Task.CompletedTask.ConfigureAwait(false);
        }
    }
}
