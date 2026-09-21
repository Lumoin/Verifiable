using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Outbound;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Transport;
using Verifiable.Cryptography;
using Verifiable.Cryptography.EventLogs;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// Resolves <c>did:webvh</c> identifiers per the
/// <see href="https://identity.foundation/didwebvh/v1.0/">did:webvh v1.0 method specification</see>.
/// </summary>
/// <remarks>
/// <para>
/// <c>did:webvh</c> extends <c>did:web</c> with a verifiable history: the DID Log is a JSON Lines file
/// (<c>did.jsonl</c>) served at the same web location <c>did:web</c> would use for <c>did.json</c>. The
/// identifier is <c>did:webvh:&lt;scid&gt;:&lt;domain&gt;[:&lt;path&gt;...]</c>; the location transform drops the
/// self-certifying identifier (SCID) segment, then applies the <c>did:web</c> domain/path rules with
/// <c>did.jsonl</c> as the file.
/// </para>
/// <list type="bullet">
///   <item><description><c>did:webvh:{SCID}:example.com</c> → <c>https://example.com/.well-known/did.jsonl</c></description></item>
///   <item><description><c>did:webvh:{SCID}:example.com:dids:issuer</c> → <c>https://example.com/dids/issuer/did.jsonl</c></description></item>
///   <item><description><c>did:webvh:{SCID}:example.com%3A3000:dids:issuer</c> → <c>https://example.com:3000/dids/issuer/did.jsonl</c></description></item>
/// </list>
/// <para>
/// <see cref="Resolve"/> computes the DID Log URL only. <see cref="Build(OutboundTransportDelegate, WebVhLineParser, WebVhWitnessFileParser, WebVhDocumentIdentityReader, WebVhStateDeserializer, WebVhCanonicalizer, EncodeDelegate, DecodeDelegate, BaseMemoryPool, TimeProvider)"/> performs full resolution: it
/// fetches the <c>did.jsonl</c> through the guarded outbound-fetch chokepoint, replays and verifies every
/// entry through the <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>, and returns the resolved
/// <see cref="DidDocument"/>.
/// </para>
/// </remarks>
public static class WebVhDidResolver
{
    /// <summary>
    /// An upper bound on the fetched <c>did.jsonl</c> size, so a malicious or misconfigured host cannot exhaust
    /// resolver memory by serving an unbounded DID Log (did:webvh v1.0: resolvers SHOULD guard against
    /// resource-exhaustion during retrieval). The bound is generous relative to a real DID Log (each entry is a
    /// single JSON line) yet rejects an obviously hostile payload.
    /// </summary>
    private const int MaxDidLogBytes = 8 * 1024 * 1024;

    /// <summary>
    /// An upper bound on the fetched <c>did-witness.json</c> size, mirroring <see cref="MaxDidLogBytes"/> so a
    /// malicious or MITM'd witness host cannot exhaust resolver memory/CPU by serving an unbounded witness file
    /// (verifying every entry × proof is JCS-canonicalize + 2×SHA-256 + Ed25519). The size cap bounds the proof
    /// count too, since each proof costs bytes. Enforced before the body is copied into a pooled buffer.
    /// </summary>
    private const int MaxWitnessFileBytes = 8 * 1024 * 1024;

    /// <summary>
    /// Computes the HTTPS <c>did.jsonl</c> DID Log location for a <c>did:webvh</c> identifier.
    /// </summary>
    /// <param name="didWebVhIdentifier">A valid <c>did:webvh</c> identifier string.</param>
    /// <returns>The HTTPS URL where the DID Log (<c>did.jsonl</c>) is published.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="didWebVhIdentifier"/> is <see langword="null"/>, empty, whitespace, does
    /// not start with the <c>did:webvh:</c> prefix, or has no domain after the SCID segment.
    /// </exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "DID identifiers contain method-specific syntax that System.Uri does not handle correctly.")]
    public static string Resolve(string didWebVhIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didWebVhIdentifier);

        string prefixWithColon = $"{WellKnownDidMethodPrefixes.WebVhDidMethodPrefix}:";
        if(!didWebVhIdentifier.StartsWith(prefixWithColon, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The given DID identifier '{didWebVhIdentifier}' is not a valid did:webvh identifier.",
                nameof(didWebVhIdentifier));
        }

        return WebHttpsTransform.MapToUrl(didWebVhIdentifier[prefixWithColon.Length..], didWebVhIdentifier, TransformPolicy);
    }


    /// <summary>
    /// The did:webvh DID-to-HTTPS policy: the SCID (the first method-specific segment) precedes the host, the host
    /// is IDNA/Punycode-encoded, a <c>/.well-known</c> segment is inserted when the identifier declares no path,
    /// each path segment is percent-decoded then re-encoded to a canonical RFC3986 percent-encoding (did:webvh
    /// v1.0, The DID to HTTPS Transformation), and the document file is the DID Log file.
    /// </summary>
    private static WebHttpsTransformPolicy TransformPolicy { get; } = new()
    {
        LeadingSegmentsToDrop = 1,
        IdnaEncodeHost = true,
        LocalhostUsesHttp = false,
        WellKnownWhenNoPath = true,
        MinimumPathSegments = 0,
        SegmentMapping = WebHttpsSegmentMapping.DecodeThenReencode,
        DocumentFileName = WellKnownWebVhValues.DidLogFile
    };


    /// <summary>
    /// The did:webvh SCID length: exactly 46 characters drawn from the base58btc alphabet (did:webvh v1.0:
    /// <c>scid = 46(base58-alphabet)</c>).
    /// </summary>
    private const int ScidLength = 46;

    /// <summary>The base58btc alphabet, which excludes 0, O, I and l to avoid visually ambiguous characters.</summary>
    private const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /// <summary>Whether the SCID segment of a did:webvh identifier (the first segment after <c>did:webvh:</c>) is well-formed.</summary>
    /// <param name="did">The did:webvh identifier.</param>
    /// <returns><see langword="true"/> when the SCID is exactly 46 base58btc-alphabet characters.</returns>
    private static bool HasWellFormedScid(string did)
    {
        string prefixWithColon = $"{WellKnownDidMethodPrefixes.WebVhDidMethodPrefix}:";
        if(!did.StartsWith(prefixWithColon, StringComparison.Ordinal))
        {
            return false;
        }

        string remainder = did[prefixWithColon.Length..];
        int separatorIndex = remainder.IndexOf(':', StringComparison.Ordinal);
        ReadOnlySpan<char> scid = separatorIndex >= 0 ? remainder.AsSpan(0, separatorIndex) : remainder.AsSpan();

        if(scid.Length != ScidLength)
        {
            return false;
        }

        foreach(char character in scid)
        {
            if(!Base58Alphabet.Contains(character, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Resolves the registered <see cref="ComputeDigestDelegate"/> for the no-digest <see cref="Build(OutboundTransportDelegate, WebVhLineParser, WebVhWitnessFileParser, WebVhDocumentIdentityReader, WebVhStateDeserializer, WebVhCanonicalizer, EncodeDelegate, DecodeDelegate, BaseMemoryPool, TimeProvider)"/> overload.
    /// </summary>
    /// <returns>The registered digest delegate.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no <see cref="ComputeDigestDelegate"/> is registered.</exception>
    private static ComputeDigestDelegate ResolveRegisteredDigest()
        => CryptographicKeyFactory.GetFunction<ComputeDigestDelegate>(typeof(ComputeDigestDelegate))
            ?? throw new InvalidOperationException(
                $"No {nameof(ComputeDigestDelegate)} has been registered. Supply one to the explicit {nameof(Build)} overload "
                + "or register one via CryptographicKeyFactory.RegisterFunction during application startup.");


    /// <summary>
    /// Builds a <see cref="DidMethodResolverDelegate"/> that fully resolves a <c>did:webvh</c>: it computes
    /// the DID Log URL, fetches the <c>did.jsonl</c> through the guarded
    /// <see cref="Outbound"/> chokepoint, replays and verifies every entry (entryHash chain, SCID,
    /// controller proofs, pre-rotation, versionTime), and returns the resolved <see cref="DidDocument"/>
    /// from the last entry's <c>state</c>.
    /// </summary>
    /// <param name="transport">The application-supplied single-hop transport the guarded fetch drives.</param>
    /// <param name="lineParser">Parses one <c>did.jsonl</c> line into a <see cref="WebVhRawEntry"/>.</param>
    /// <param name="witnessFileParser">Parses the <c>did-witness.json</c> file into its witness proof records.</param>
    /// <param name="documentIdentityReader">Reads each entry's DIDDoc <c>id</c> and <c>alsoKnownAs</c> for the portability check.</param>
    /// <param name="stateDeserializer">Deserializes the resolved entry's <c>state</c> into a <see cref="DidDocument"/>.</param>
    /// <param name="canonicalizer">The JCS canonicalizers the verification steps hash and sign over.</param>
    /// <param name="base58Encoder">The raw base58btc encoder (no multibase prefix).</param>
    /// <param name="base58Decoder">The base58btc decoder for update keys and proof values.</param>
    /// <param name="pool">The pool the key, signature, hash and witness-file buffers are rented from.</param>
    /// <param name="timeProvider">The clock used for the <c>versionTime</c> checks.</param>
    /// <returns>A <see cref="DidMethodResolverDelegate"/> for registration with the resolver composition.</returns>
    /// <remarks>
    /// This overload takes the registered <see cref="ComputeDigestDelegate"/> from <see cref="CryptographicKeyFactory"/>
    /// and forwards to the explicit-delegate overload; supply a digest there to control the implementation per resolver.
    /// </remarks>
    public static DidMethodResolverDelegate Build(
        OutboundTransportDelegate transport,
        WebVhLineParser lineParser,
        WebVhWitnessFileParser witnessFileParser,
        WebVhDocumentIdentityReader documentIdentityReader,
        WebVhStateDeserializer stateDeserializer,
        WebVhCanonicalizer canonicalizer,
        EncodeDelegate base58Encoder,
        DecodeDelegate base58Decoder,
        BaseMemoryPool pool,
        TimeProvider timeProvider)
        => Build(transport, lineParser, witnessFileParser, documentIdentityReader, stateDeserializer, canonicalizer,
            ResolveRegisteredDigest(), base58Encoder, base58Decoder, pool, timeProvider);


    /// <summary>
    /// Builds a <c>did:webvh</c> resolver using an explicitly supplied <see cref="ComputeDigestDelegate"/> for the
    /// SHA-256 SCID, entryHash and pre-rotation hashes — the caller controls the digest implementation.
    /// </summary>
    /// <param name="transport">The application-supplied single-hop transport the guarded fetch drives.</param>
    /// <param name="lineParser">Parses one <c>did.jsonl</c> line into a <see cref="WebVhRawEntry"/>.</param>
    /// <param name="witnessFileParser">Parses the <c>did-witness.json</c> file into its witness proof records.</param>
    /// <param name="documentIdentityReader">Reads each entry's DIDDoc <c>id</c> and <c>alsoKnownAs</c> for the portability check.</param>
    /// <param name="stateDeserializer">Deserializes the resolved entry's <c>state</c> into a <see cref="DidDocument"/>.</param>
    /// <param name="canonicalizer">The JCS canonicalizers the verification steps hash and sign over.</param>
    /// <param name="computeDigest">The SHA-256 digest implementation (telemetry/CBOM-bearing) the verification steps use.</param>
    /// <param name="base58Encoder">The raw base58btc encoder (no multibase prefix).</param>
    /// <param name="base58Decoder">The base58btc decoder for update keys and proof values.</param>
    /// <param name="pool">The pool the key, signature, hash and witness-file buffers are rented from.</param>
    /// <param name="timeProvider">The clock used for the <c>versionTime</c> checks.</param>
    /// <returns>A <see cref="DidMethodResolverDelegate"/> for registration with the resolver composition.</returns>
    /// <remarks>
    /// <para>
    /// did:webvh's Read algorithm matches the requested DID against the top-level <c>id</c> of ANY verified
    /// version, not only the resolved one: "If the DID being resolved matches exactly the value of
    /// <c>state.id</c> in the current DIDDoc entry, increment <c>didIdMatchCount</c> by 1", and at the end
    /// "the value of <c>didIdMatchCount</c> MUST be greater than 0" (
    /// <see href="https://identity.foundation/didwebvh/v1.0/#read-resolve">did:webvh v1.0, Read</see>). So the
    /// old name of a moved DID resolves, and what it resolves to is the current document, whose <c>id</c> is
    /// the new name. DID Resolution says of the returned document: "The value of <c>id</c> in the resolved DID
    /// document MUST be string equal to the DID that was resolved" (
    /// <see href="https://www.w3.org/TR/did-resolution/#dfn-diddocument">DID Resolution, the <c>didDocument</c>
    /// output value</see>). For a moved DID resolved by its old name the two rules cannot both be met to the
    /// letter: the returned <c>id</c> is NOT string equal to the requested DID. This resolver returns the
    /// current document and states, in the document metadata, the equivalence it has verified; the paragraphs
    /// below say why that is the sound reading and what bounds it.
    /// </para>
    /// <para>
    /// The current document is returned rather than the last pre-move version because a caller resolves a DID
    /// to learn its CURRENT keys and services; a pre-move version is a superseded state, and handing it out
    /// would hand out superseded keys. did:webvh's own portability rule agrees: the DID "can be renamed by
    /// changing the <c>id</c> DID string in the DIDDoc", so an old name is a past label for the SAME, evolving
    /// subject, not a frozen alias to its old document.
    /// </para>
    /// <para>
    /// This equivalence is expressed through <see cref="DidDocumentMetadata.CanonicalId"/> and
    /// <see cref="DidDocumentMetadata.EquivalentId"/>, inside DID Resolution rather than as a special case around
    /// it, because <c>equivalentId</c> exists precisely for this: "A DID method can define different forms of a
    /// DID that are logically equivalent... A conforming DID method specification MUST guarantee that each
    /// <c>equivalentId</c> value is logically equivalent to the <c>id</c> property value", and the specification
    /// ranks it above the DID Core <c>alsoKnownAs</c> property: "<c>equivalentId</c> is a much stronger form of
    /// equivalence than <c>alsoKnownAs</c> because the equivalence MUST be guaranteed by the governing DID
    /// method" (<see href="https://www.w3.org/TR/did-resolution/#did-document-metadata">DID Resolution,
    /// <c>equivalentId</c></see>). A method that sets <c>EquivalentId</c> is making exactly that guarantee, so
    /// <see cref="DidResolver.ResolveAsync"/> accepts a differing document <c>id</c> only on this method's own
    /// verified statement.
    /// </para>
    /// <para>
    /// <c>alsoKnownAs</c> is never read for this equivalence, even though did:webvh REQUIRES it on the moved
    /// document ("The DIDDoc MUST contain the prior DID string as an <c>alsoKnownAs</c> entry") and this
    /// resolver's portability check enforces that requirement: <c>alsoKnownAs</c> is the controller's own
    /// unverified assertion about itself, while what makes a prior name equivalent here is that it WAS a
    /// replay-verified <c>state.id</c> of this same SCID's chain — a fact this resolver checked, not a claim the
    /// document makes about itself.
    /// </para>
    /// <para>
    /// The did:webvh Security Note on prior domains applies unchanged: "Resolvers and clients of resolvers MUST
    /// ignore any prior domain components when evaluating the history or trustworthiness of a did:webvh DID;
    /// only the current hosting location and its associated verifiable history are relevant" (
    /// <see href="https://identity.foundation/didwebvh/v1.0/#did-portability">did:webvh v1.0, DID
    /// Portability</see>). Naming a prior identifier as equivalent says nothing about trusting the domain it once
    /// named; the verified history served from the location being resolved is what the trust decision rests on.
    /// </para>
    /// <para>
    /// A caller is expected to use <see cref="DidDocumentMetadata.CanonicalId"/>, not any prior name, as its
    /// primary identifier: "A requesting party is expected to use the <c>canonicalId</c> value as its primary ID
    /// value for the DID subject and treat all other equivalent values as secondary aliases" (
    /// <see href="https://www.w3.org/TR/did-resolution/#did-document-metadata">DID Resolution,
    /// <c>canonicalId</c></see>).
    /// </para>
    /// </remarks>
    public static DidMethodResolverDelegate Build(
        OutboundTransportDelegate transport,
        WebVhLineParser lineParser,
        WebVhWitnessFileParser witnessFileParser,
        WebVhDocumentIdentityReader documentIdentityReader,
        WebVhStateDeserializer stateDeserializer,
        WebVhCanonicalizer canonicalizer,
        ComputeDigestDelegate computeDigest,
        EncodeDelegate base58Encoder,
        DecodeDelegate base58Decoder,
        BaseMemoryPool pool,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(lineParser);
        ArgumentNullException.ThrowIfNull(witnessFileParser);
        ArgumentNullException.ThrowIfNull(documentIdentityReader);
        ArgumentNullException.ThrowIfNull(stateDeserializer);
        ArgumentNullException.ThrowIfNull(canonicalizer);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(base58Encoder);
        ArgumentNullException.ThrowIfNull(base58Decoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        VerifyChainIntegrityDelegate<WebVhRawEntry, WebVhProof> verifyChainIntegrity =
            WebVhChainVerification.Create(canonicalizer.EntryHashInput, computeDigest, base58Encoder, base58Decoder, pool);

        return async (did, options, context, cancellationToken) =>
        {
            //One committed resolution timestamp is read once and used for every not-in-the-future versionTime
            //check (and proof-expiry check) across this resolve, so entries are judged against a single instant
            //rather than a clock that advances mid-replay (did:webvh v1.0, Read: a stable resolution clock).
            TimeProvider resolutionClock = new FrozenTimeProvider(timeProvider.GetUtcNow());

            LogReplayContext<WebVhState, WebVhRawEntry, WebVhProof, WebVhValidationContext> replayContext = new()
            {
                Classify = ClassifyEntry,
                VerifyChainIntegrity = verifyChainIntegrity,
                ValidateProof = WebVhProofVerification.ValidateProofAsync,
                ValidationContext = new WebVhValidationContext
                {
                    Canonicalizer = canonicalizer,
                    ComputeDigest = computeDigest,
                    Base58Encoder = base58Encoder,
                    Base58Decoder = base58Decoder,
                    MemoryPool = pool,
                    TimeProvider = resolutionClock
                },
                Apply = ApplyEntry,
                TimeProvider = resolutionClock
            };

            string logUrl;
            try
            {
                logUrl = Resolve(did);
            }
            catch(ArgumentException)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            //Fail fast at the identifier boundary on a malformed SCID: the ABNF fixes the SCID to exactly 46
            //base58btc-alphabet characters (did:webvh v1.0: "scid = 46(base58-alphabet)"). A malformed SCID is
            //invalidDid before the log is fetched, rather than only when self-certification fails to reproduce it.
            if(!HasWellFormedScid(did))
            {
                return DidResolutionResult.Failure(InvalidDid("The did:webvh identifier has a malformed SCID; it must be 46 base58btc characters."));
            }

            if(!Uri.TryCreate(logUrl, UriKind.Absolute, out Uri? target))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            //Fetch the DID Log from the DID's designated HTTPS location; on a not-found condition the resolver
            //MAY fall back to the supplied alternative sources (Watcher URLs), retrieving and verifying the log
            //from them exactly as it would the primary (did:webvh v1.0, Read: L886). A successful fetch from
            //any source is used; if none succeed, the DID is notFound, with a Detail naming which of the three
            //retrieval causes the primary hit.
            (OutboundResponse? logResponse, string? logFetchDetail) =
                await FetchDidLogAsync(target, options, transport, context, cancellationToken).ConfigureAwait(false);
            if(logResponse is null)
            {
                return DidResolutionResult.Failure(NotFound(logFetchDetail));
            }

            //Bound the fetched DID Log so an oversized payload is rejected before it is parsed, rather than
            //driving unbounded allocation through the entry parser (did:webvh v1.0: guard retrieval against
            //resource exhaustion).
            if(logResponse.Body.Memory.Length > MaxDidLogBytes)
            {
                return DidResolutionResult.Failure(InvalidDid("The did:webvh DID Log exceeds the maximum permitted size."));
            }

            List<LogEntry<WebVhRawEntry, WebVhProof>> entries;
            try
            {
                entries = ParseEntries(logResponse.Body.Memory, lineParser);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //ParseEntries walks untrusted fetched bytes through the caller-supplied line parser; any
                //failure to parse them is an invalid DID from the resolver's perspective, cancellation
                //excepted above.
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            if(entries.Count == 0)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            //The genesis entry's versionId MUST be of the shape "1-<entryHash>" (version number 1; did:webvh
            //v1.0, Creating the DID). A genesis versionId not of that shape is rejected fail-fast as invalidDid
            //at the identifier boundary rather than only when the entryHash chain fails to verify.
            if(!WebVhVersionId.TryParse(entries[0].Operation?.VersionId, out int genesisVersionNumber, out _) || genesisVersionNumber != 1)
            {
                return DidResolutionResult.Failure(InvalidDid("The did:webvh genesis entry versionId MUST be of the form '1-<entryHash>'."));
            }

            //Select the requested version (versionId/versionNumber/versionTime), or the latest entry. Only the
            //entries up to and including the target are replayed and verified, so a version query targeting a
            //valid earlier version resolves even if later entries are invalid (did:webvh v1.0, Read).
            (int targetIndex, DidProblemDetails? selectionError) = SelectTargetEntry(entries, options);
            if(selectionError is not null)
            {
                return DidResolutionResult.Failure(selectionError);
            }

            //Resolving a prior version of a deactivated DID still reports the DID as deactivated (did:webvh
            //v1.0, Deactivate: L1023). To honor that SECURELY the full log is replayed: a later deactivation
            //counts only when that entry itself passes cryptographic replay. A forged/unsigned appended
            //deactivation line never marks the DID deactivated — it fails replay, and an error AFTER the target
            //ends the verified chain (entries from the first invalid one to the end are not honored) without
            //failing the prior-version resolution (did:webvh v1.0, Read).
            LogReplayer<WebVhState, WebVhRawEntry, WebVhProof, WebVhValidationContext> replayer = new();
            List<WebVhState> states = new(targetIndex + 1);
            List<ReadOnlyMemory<byte>> entryLines = new(targetIndex + 1);
            WebVhState? finalState = null;
            LogEntry<WebVhRawEntry, WebVhProof>? finalEntry = null;
            bool isDeactivated = false;
            bool isDeactivatedByLaterEntry = false;
            string? replayError = null;
            int replayIndex = -1;

            await foreach(LogReplayResult<WebVhState, WebVhRawEntry, WebVhProof> result in
                replayer.ReplayAsync(ToAsync(entries, cancellationToken), replayContext, cancellationToken).ConfigureAwait(false))
            {
                if(result.Error is not null)
                {
                    //An error at or before the target invalidates the resolved version; an error after the
                    //target ends the verified chain but does not fail a valid prior-version query.
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
                        case EmptyLogState<WebVhState>:
                            //The replayer has not yet applied an entry into this state; finalState and
                            //isDeactivated keep whatever the prior iteration left them at.
                            break;
                        case ActiveLogState<WebVhState> active:
                            finalState = active.Value;
                            states.Add(active.Value);
                            entryLines.Add(result.Entry.CanonicalBytes);
                            isDeactivated = false;
                            break;
                        case DeactivatedLogState<WebVhState> deactivated:
                            finalState = deactivated.Value;
                            states.Add(deactivated.Value);
                            entryLines.Add(result.Entry.CanonicalBytes);
                            isDeactivated = true;
                            break;
                        default:
                            //No known log-state subtype matched; finalState and isDeactivated keep whatever the
                            //prior iteration left them at.
                            break;
                    }
                }
                else if(result.State is DeactivatedLogState<WebVhState>)
                {
                    //A VERIFIED later entry deactivates the DID; deactivation is terminal, so stop the scan.
                    isDeactivatedByLaterEntry = true;

                    break;
                }
            }

            if(replayError is not null)
            {
                //A verification failure renders the did:webvh DID invalid; the precise replay message becomes
                //the problemDetails.Detail (did:webvh v1.0, Read: error field is invalidDid; READ-31/34).
                return DidResolutionResult.Failure(InvalidDid(replayError));
            }

            if(finalEntry is null || finalState is null)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            //A change to the DIDDoc id across entries is a DID move: it is permitted only when portability was
            //active and the new entry back-references the prior DID in alsoKnownAs, and every id retains the
            //SCID (did:webvh v1.0, DID Portability). Verified locally before the witness fetch. A malformed
            //state (for example a non-string alsoKnownAs member) fails closed like any other malformed entry.
            List<WebVhDocumentIdentity> identities = new(states.Count);
            try
            {
                for(int i = 0; i < states.Count; i++)
                {
                    identities.Add(documentIdentityReader(entryLines[i].Span));
                }
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //documentIdentityReader is a caller-supplied delegate over untrusted entry bytes; any failure
                //to read an identity from them is an invalid DID from the resolver's perspective, cancellation
                //excepted above.
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            if(WebVhPortabilityVerification.Verify(states, identities) is { } portabilityError)
            {
                return DidResolutionResult.Failure(InvalidDid(portabilityError));
            }

            //If any verified entry has an active witness rule, a threshold of the then-active witnesses MUST
            //approve it: fetch and verify did-witness.json before resolving (did:webvh v1.0, Verifying Witness
            //Proofs During Resolution). The file is fetched only when witnesses are active.
            if(WebVhWitnessVerification.RequiresWitnessing(states))
            {
                DidProblemDetails? witnessError = await VerifyWitnessesAsync(
                    logUrl, states, witnessFileParser, replayContext.ValidationContext, transport, context, cancellationToken).ConfigureAwait(false);
                if(witnessError is not null)
                {
                    return DidResolutionResult.Failure(witnessError);
                }
            }

            DidDocument? document;
            try
            {
                document = stateDeserializer(finalEntry.CanonicalBytes.Span);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //stateDeserializer is a caller-supplied delegate over untrusted canonical bytes; any failure
                //to parse them is an invalid DID from the resolver's perspective, cancellation excepted above.
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            if(document is null)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            //The requested DID MUST match the top-level id in at least one verified version, not necessarily the
            //resolved one — a portable DID's resolved version may carry a different id (did:webvh v1.0, Read:
            //"matches the top-level id in at least one version of the DIDDoc").
            if(!MatchesAnyVersionId(identities, did))
            {
                return DidResolutionResult.Failure(InvalidDid($"The DID '{did}' does not match the top-level id of any verified version."));
            }

            //did:webvh implicitly defines a #files (relativeRef) and #whois (LinkedVerifiablePresentation)
            //service so a client can dereference <did>/path and <did>/whois itself even when the resolver does
            //not. An explicit service of the same id already in the DIDDoc takes precedence (did:webvh v1.0,
            //DID URL Resolution).
            AddImplicitServices(document, did, logUrl);

            bool isResolvedVersionDeactivated = isDeactivated || isDeactivatedByLaterEntry;

            //The portability equivalence this resolver has itself replay-verified (identities[*].Id only, never
            //alsoKnownAs); this single construction site is reached by the latest, deactivated and
            //version-specific (versionId/versionTime) paths alike, since identities holds exactly the verified
            //prefix up to targetIndex for all three (see the Build(...) remarks for the full reasoning).
            (string? canonicalId, IReadOnlyList<string>? equivalentId) = BuildPortabilityEquivalence(identities);

            DidDocumentMetadata metadata = new()
            {
                VersionId = finalState.VersionId,
                Deactivated = isResolvedVersionDeactivated,
                Created = WebVhResolutionMetadata.ParseTimestamp(states[0].VersionTime),
                Updated = WebVhResolutionMetadata.ParseTimestamp(finalState.VersionTime),
                CanonicalId = canonicalId,
                EquivalentId = equivalentId,
                AdditionalData = WebVhResolutionMetadata.Build(finalState, isResolvedVersionDeactivated)
            };

            //When the resolved (latest) version is itself the deactivation, the resolver MUST NOT return the
            //DIDDoc: a result with a null document and deactivated:true metadata so DidResolver Step 5b surfaces
            //it as a deactivated resolution (did:webvh v1.0, Deactivate: L1019). A prior version queried on a
            //deactivated DID still returns its DIDDoc with deactivated:true metadata (L1023), so the
            //null-document rule applies only when the target entry is the deactivation itself.
            HttpCacheFreshness freshness = HttpCacheFreshness.Compute(logResponse);

            if(isDeactivated)
            {
                return DidResolutionResult.SuccessDeactivated(metadata, contentType: "application/did+json", freshness: freshness);
            }

            return DidResolutionResult.Success(document, metadata, contentType: "application/did+json", freshness: freshness);
        };
    }


    /// <summary>
    /// The three ways a guarded fetch can fail to yield a usable response, told apart so a resolution result's
    /// <c>Detail</c> can say which one it was without ever publishing the application transport's own exception
    /// message or the outbound-fetch policy's diagnostic <see cref="OutboundFetchResult.DenyReason"/>.
    /// </summary>
    private enum WebVhFetchFailureCause
    {
        /// <summary>The application transport threw (cancellation excepted).</summary>
        TransportFailed,

        /// <summary>The outbound-fetch policy refused the target, or a redirect hop, before any terminal response.</summary>
        PolicyRefused,

        /// <summary>A terminal response was obtained but its status was not 200.</summary>
        UnsuccessfulStatus
    }


    /// <summary>
    /// The outcome of one guarded fetch driven through <see cref="TryFetchAsync(Uri, long, OutboundTransportDelegate, ExchangeContext, CancellationToken)"/>.
    /// </summary>
    /// <param name="Response">The successful response, or <see langword="null"/> on failure.</param>
    /// <param name="Cause">The failure cause, or <see langword="null"/> on success.</param>
    /// <param name="StatusCode">
    /// The status the server answered with, when <paramref name="Cause"/> is
    /// <see cref="WebVhFetchFailureCause.UnsuccessfulStatus"/>; otherwise <c>0</c>.
    /// </param>
    private sealed record WebVhFetchOutcome(OutboundResponse? Response, WebVhFetchFailureCause? Cause, int StatusCode);


    /// <summary>
    /// Fetches the DID Log from the primary location, then — only when the primary fails — from each supplied
    /// alternative source (Watcher URL) in turn. Returns the first successful 200 response, or, when no source
    /// yields one, a <c>Detail</c> naming the PRIMARY's own retrieval cause — the transport failed, the outbound
    /// policy refused the fetch, or the server answered with a non-200 status — and, when at least one
    /// alternative source was tried, that none of them yielded the log either (did:webvh v1.0, Read: L886, the
    /// alternative-source fallback). The retrieved log is verified by the caller exactly as the primary would
    /// be, so a tampered alternative source still fails verification.
    /// </summary>
    /// <param name="primaryTarget">The DID's designated DID Log location.</param>
    /// <param name="options">The resolution options carrying any watcher URLs.</param>
    /// <param name="transport">The single-hop transport the guarded fetch drives.</param>
    /// <param name="context">The per-operation context carrying the SSRF outbound-fetch policy.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The first successful response, or <see langword="null"/> with the not-found <c>Detail</c>.</returns>
    private static async ValueTask<(OutboundResponse? Response, string? Detail)> FetchDidLogAsync(
        Uri primaryTarget,
        DidResolutionOptions options,
        OutboundTransportDelegate transport,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        WebVhFetchOutcome primary = await TryFetchLogAsync(primaryTarget, transport, context, cancellationToken).ConfigureAwait(false);
        if(primary.Response is not null)
        {
            return (primary.Response, null);
        }

        string primaryDetail = DescribeFetchFailure(primary.Cause!.Value, primary.StatusCode);

        if(options.WatcherUrls is not { Count: > 0 } watcherUrls)
        {
            return (null, primaryDetail);
        }

        foreach(string watcherUrl in watcherUrls)
        {
            if(!Uri.TryCreate(watcherUrl, UriKind.Absolute, out Uri? watcherTarget))
            {
                continue;
            }

            WebVhFetchOutcome watcherOutcome = await TryFetchLogAsync(watcherTarget, transport, context, cancellationToken).ConfigureAwait(false);
            if(watcherOutcome.Response is not null)
            {
                return (watcherOutcome.Response, null);
            }
        }

        return (null, $"{primaryDetail} No alternative source yielded the log.");
    }


    /// <summary>
    /// Drives one guarded fetch for the DID Log, bounded by <see cref="MaxDidLogBytes"/>.
    /// </summary>
    /// <param name="target">The DID Log URL to fetch.</param>
    /// <param name="transport">The single-hop transport the guarded fetch drives.</param>
    /// <param name="context">The per-operation context carrying the SSRF outbound-fetch policy.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The fetch outcome: the successful response, or the cause of the failure.</returns>
    private static ValueTask<WebVhFetchOutcome> TryFetchLogAsync(
        Uri target,
        OutboundTransportDelegate transport,
        ExchangeContext context,
        CancellationToken cancellationToken)
        => TryFetchAsync(target, MaxDidLogBytes, transport, context, cancellationToken);


    /// <summary>
    /// Drives one guarded fetch, telling apart the three ways it can fail to yield a usable response: the
    /// application transport threw (an application transport that enforces <paramref name="maxResponseBytes"/>
    /// while streaming reports it this way), the outbound-fetch policy refused the target (or a redirect hop)
    /// before any terminal response, or a terminal response was obtained whose status was not 200. Cancellation
    /// is always propagated, never turned into a failure cause.
    /// </summary>
    /// <param name="target">The URL to fetch.</param>
    /// <param name="maxResponseBytes">The response size this fetch is bounded to.</param>
    /// <param name="transport">The single-hop transport the guarded fetch drives.</param>
    /// <param name="context">The per-operation context carrying the SSRF outbound-fetch policy.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The fetch outcome: the successful response, or the cause of the failure.</returns>
    private static async ValueTask<WebVhFetchOutcome> TryFetchAsync(
        Uri target,
        long maxResponseBytes,
        OutboundTransportDelegate transport,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        OutboundRequest request = new() { Target = target, Method = "GET", MaxResponseBytes = maxResponseBytes };

        OutboundFetchResult fetch;
        try
        {
            fetch = await Verifiable.Core.Outbound.OutboundFetch.FetchAsync(request, context, transport, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            //An application transport that enforces maxResponseBytes while streaming reports an oversized or
            //otherwise failed fetch by throwing; the exception's own message and type are the application
            //transport's, not the library's to publish, so only the cause is recorded here, cancellation
            //excepted above.
            return new WebVhFetchOutcome(Response: null, Cause: WebVhFetchFailureCause.TransportFailed, StatusCode: 0);
        }

        if(!fetch.IsFetched)
        {
            //The outbound-fetch policy refused the target (or a redirect hop) before any terminal response was
            //obtained; OutboundFetchResult.DenyReason is diagnostic only and is not the library's to publish.
            return new WebVhFetchOutcome(Response: null, Cause: WebVhFetchFailureCause.PolicyRefused, StatusCode: 0);
        }

        if(fetch.Response is not { StatusCode: 200 } response)
        {
            return new WebVhFetchOutcome(Response: null, Cause: WebVhFetchFailureCause.UnsuccessfulStatus, StatusCode: fetch.Response?.StatusCode ?? 0);
        }

        return new WebVhFetchOutcome(Response: response, Cause: null, StatusCode: 200);
    }


    /// <summary>
    /// The one-sentence, application-agnostic description of a guarded-fetch failure cause for the DID Log
    /// fetch — naming neither the application transport's own exception text nor the outbound-fetch policy's
    /// diagnostic reason, only which of the three causes it was (did:webvh v1.0, Read: the <c>notFound</c>
    /// error condition; L848-849).
    /// </summary>
    /// <param name="cause">The failure cause.</param>
    /// <param name="statusCode">The status the server answered with, when <paramref name="cause"/> is <see cref="WebVhFetchFailureCause.UnsuccessfulStatus"/>.</param>
    /// <returns>The one-sentence detail.</returns>
    private static string DescribeFetchFailure(WebVhFetchFailureCause cause, int statusCode) => cause switch
    {
        WebVhFetchFailureCause.TransportFailed => "The transport failed to retrieve the DID Log.",
        WebVhFetchFailureCause.PolicyRefused => "The outbound policy refused the fetch of the DID Log.",
        WebVhFetchFailureCause.UnsuccessfulStatus => $"The server answered with status {statusCode}.",
        _ => "The DID Log could not be retrieved.",
    };


    /// <summary>
    /// The one-sentence description of a guarded-fetch failure cause for the <c>did-witness.json</c> fetch, in
    /// the same three-cause shape as <see cref="DescribeFetchFailure(WebVhFetchFailureCause, int)"/> (did:webvh
    /// v1.0, DID Witnesses: resolvers MUST retrieve and verify the witness file when witnesses are active).
    /// </summary>
    /// <param name="cause">The failure cause.</param>
    /// <param name="statusCode">The status the server answered with, when <paramref name="cause"/> is <see cref="WebVhFetchFailureCause.UnsuccessfulStatus"/>.</param>
    /// <returns>The one-sentence detail.</returns>
    private static string DescribeWitnessFetchFailure(WebVhFetchFailureCause cause, int statusCode) => cause switch
    {
        WebVhFetchFailureCause.TransportFailed => "Witnesses are active but the transport failed to retrieve the did-witness.json file.",
        WebVhFetchFailureCause.PolicyRefused => "Witnesses are active but the outbound policy refused the fetch of the did-witness.json file.",
        WebVhFetchFailureCause.UnsuccessfulStatus => $"Witnesses are active but the server answered with status {statusCode} for the did-witness.json file.",
        _ => "Witnesses are active but the did-witness.json file could not be retrieved.",
    };


    /// <summary>
    /// Fetches and verifies <c>did-witness.json</c> when the replayed log has active witnesses. Returns a problem
    /// detail to fail resolution closed (the file is absent/unreachable while witnesses are active, or a threshold
    /// is unmet), or <see langword="null"/> when every entry requiring witnessing is approved.
    /// </summary>
    /// <param name="logUrl">The DID Log URL, whose final path element is replaced to locate the witness file.</param>
    /// <param name="states">The verified entry states, carrying the witness rules and versionIds.</param>
    /// <param name="witnessFileParser">Parses the <c>did-witness.json</c> body into its witness proof records.</param>
    /// <param name="validationContext">The verification seams the witness-proof check runs over.</param>
    /// <param name="transport">The single-hop transport the guarded fetch drives.</param>
    /// <param name="context">The per-operation context carrying the SSRF outbound-fetch policy.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A problem detail to fail resolution closed, or <see langword="null"/> when witnessing is satisfied.</returns>
    private static async ValueTask<DidProblemDetails?> VerifyWitnessesAsync(
        string logUrl,
        IReadOnlyList<WebVhState> states,
        WebVhWitnessFileParser witnessFileParser,
        WebVhValidationContext validationContext,
        OutboundTransportDelegate transport,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(!Uri.TryCreate(ResolveWitnessUrl(logUrl), UriKind.Absolute, out Uri? witnessTarget))
        {
            return DidResolutionErrors.InvalidDid;
        }

        //Witnesses are active, so an absent or unsuccessful did-witness.json fails resolution closed: the
        //entries requiring witnessing cannot be confirmed without it. The three ways the fetch can fail are
        //told apart in the Detail exactly as the primary DID Log fetch tells them apart.
        WebVhFetchOutcome witnessFetch = await TryFetchAsync(witnessTarget, MaxWitnessFileBytes, transport, context, cancellationToken).ConfigureAwait(false);
        if(witnessFetch.Response is not { } fetchedWitnessResponse)
        {
            return InvalidDid(DescribeWitnessFetchFailure(witnessFetch.Cause!.Value, witnessFetch.StatusCode));
        }

        //The did-witness.json media type SHOULD be application/json (did:webvh v1.0, The Witness Proofs File).
        //A response that declares a different content type is treated as a retrieval failure: the file the
        //witness rule depends on was not served in its defined form, so witnessing cannot be confirmed. An
        //absent Content-Type is tolerated (the SHOULD does not require the header to be present).
        if(!IsAcceptableJsonContentType(fetchedWitnessResponse))
        {
            return InvalidDid("The did:webvh did-witness.json was served with a non-JSON Content-Type.");
        }

        ReadOnlyMemory<byte> body = fetchedWitnessResponse.Body.Memory;
        int length = body.Length;

        //Bound the witness file like the DID Log (MaxWitnessFileBytes) before any allocation or verification,
        //so an oversized did-witness.json is rejected rather than driving unbounded memory/CPU.
        if(length > MaxWitnessFileBytes)
        {
            return InvalidDid("The did:webvh did-witness.json exceeds the maximum permitted size.");
        }

        //The fetched body is a GC-managed transport buffer; copy it into a pooled, owned buffer so the witness
        //JSON is tracked and reclaimed like the other did:webvh working buffers. Ownership transfers to the
        //WebVhWitnessFile, which the finally block disposes once verification has read the bytes.
        IMemoryOwner<byte>? owner = validationContext.MemoryPool.Rent(length);
        WebVhWitnessFile? witnessFile = null;
        try
        {
            body.Span.CopyTo(owner.Memory.Span);
            ImmutableArray<WebVhWitnessProofEntry> witnessEntries = witnessFileParser(owner.Memory.Span[..length]);
            witnessFile = new WebVhWitnessFile(witnessEntries, owner, length);
            owner = null;

            string? error = await WebVhWitnessVerification.VerifyAsync(states, witnessFile, validationContext, cancellationToken).ConfigureAwait(false);

            return error is null ? null : InvalidDid(error);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            //A failure verifying the witness file fails resolution closed, cancellation excepted above.
            return DidResolutionErrors.InvalidDid;
        }
        finally
        {
            witnessFile?.Dispose();
            owner?.Dispose();
        }
    }


    /// <summary>
    /// Whether a <c>did-witness.json</c> response carries an acceptable <c>Content-Type</c>: <c>application/json</c>
    /// (the SHOULD media type), or no <c>Content-Type</c> header at all (the SHOULD does not require the header to
    /// be present). Any media-type parameters (for example <c>; charset=utf-8</c>) are ignored, comparing only the
    /// media type. A response declaring a different media type is rejected so the witness file is consumed only in
    /// its defined form.
    /// </summary>
    /// <param name="response">The witness-file response to inspect.</param>
    /// <returns><see langword="true"/> when the Content-Type is acceptable or absent.</returns>
    private static bool IsAcceptableJsonContentType(OutboundResponse response)
    {
        if(!response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType) || contentType is not { Length: > 0 })
        {
            return true;
        }

        int parameterIndex = contentType.IndexOf(';', StringComparison.Ordinal);
        ReadOnlySpan<char> mediaType = (parameterIndex >= 0 ? contentType.AsSpan(0, parameterIndex) : contentType.AsSpan()).Trim();

        return mediaType.Equals(WellKnownWebVhValues.WitnessFileMediaType, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// The witness proofs file shares the DID's web location with only the final path element changed
    /// (<c>did.jsonl</c> → <c>did-witness.json</c>) (did:webvh v1.0, The Witness Proofs File). The log URL is
    /// produced by <see cref="Resolve"/>, which always ends in the DID Log file name.
    /// </summary>
    /// <param name="logUrl">The DID Log URL.</param>
    /// <returns>The witness-file URL.</returns>
    private static string ResolveWitnessUrl(string logUrl)
    {
        return logUrl.EndsWith(WellKnownWebVhValues.DidLogFile, StringComparison.Ordinal)
            ? string.Concat(logUrl.AsSpan(0, logUrl.Length - WellKnownWebVhValues.DidLogFile.Length), WellKnownWebVhValues.DidWitnessFile)
            : logUrl;
    }


    /// <summary>
    /// did:webvh resolution maps every invalidating condition to the invalidDid error (did:webvh v1.0, Read:
    /// "invalidDid — Any error that renders the did:webvh DID invalid during resolution"); a precise message is
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
    /// did:webvh resolution maps a DID Log that could not be retrieved to the
    /// <see href="https://identity.foundation/didwebvh/v1.0/#read-resolve">notFound error</see> (did:webvh
    /// v1.0, Read: "notFound — The DID Log or the resource referenced by a DID URL was not found"); a precise
    /// message naming which of the three retrieval causes it was (the transport failed; the outbound policy
    /// refused the fetch; the server answered with a non-200 status) is carried as the occurrence-specific
    /// <c>problemDetails.Detail</c>. The detail-free form equals the shared <see cref="DidResolutionErrors.NotFound"/>
    /// by problem-type, so callers can still compare by type.
    /// </summary>
    /// <param name="detail">The occurrence-specific detail, or <see langword="null"/> for the shared instance.</param>
    /// <returns>The not-found problem details.</returns>
    private static DidProblemDetails NotFound(string? detail)
    {
        return detail is null
            ? DidResolutionErrors.NotFound
            : new DidProblemDetails(DidErrorTypes.NotFound, Title: "Not found", Detail: detail);
    }


    /// <summary>
    /// Whether the requested DID matches the top-level <c>id</c> of any verified version — a portable DID's
    /// resolved version may carry a different <c>id</c> than an earlier one (did:webvh v1.0, Read).
    /// </summary>
    /// <param name="identities">The per-version document identities.</param>
    /// <param name="did">The requested DID.</param>
    /// <returns><see langword="true"/> when some verified version's id equals the requested DID.</returns>
    private static bool MatchesAnyVersionId(List<WebVhDocumentIdentity> identities, string did)
    {
        foreach(WebVhDocumentIdentity identity in identities)
        {
            if(string.Equals(identity.Id, did, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Computes the did:webvh portability equivalence this resolver has itself replay-verified: the resolved
    /// version's own top-level <c>id</c> becomes <see cref="DidDocumentMetadata.CanonicalId"/>, and every OTHER
    /// distinct top-level <c>id</c> the verified chain carried becomes
    /// <see cref="DidDocumentMetadata.EquivalentId"/>, in log order. A chain whose entries all share the same
    /// <c>id</c> never moved, so neither value is set — a document is not an equivalent of itself.
    /// </summary>
    /// <param name="identities">
    /// The per-version document identities collected from every replay-verified entry up to and including the
    /// resolved one; <c>alsoKnownAs</c> is deliberately not read here (the controller's own unverified
    /// assertion), only <see cref="WebVhDocumentIdentity.Id"/>, the value this resolver has itself verified.
    /// </param>
    /// <returns>The resolved version's canonical id and its other verified equivalents, or both <see langword="null"/> when the chain never moved.</returns>
    private static (string? CanonicalId, IReadOnlyList<string>? EquivalentId) BuildPortabilityEquivalence(
        List<WebVhDocumentIdentity> identities)
    {
        string? resolvedId = identities.Count > 0 ? identities[^1].Id : null;

        //Every OTHER distinct verified id, in the order it first appeared in the log — never the resolved id
        //itself, and never a value read from alsoKnownAs.
        List<string> equivalentId = new(identities.Count);
        foreach(WebVhDocumentIdentity identity in identities)
        {
            if(identity.Id is { } id
                && !string.Equals(id, resolvedId, StringComparison.Ordinal)
                && !equivalentId.Contains(id, StringComparer.Ordinal))
            {
                equivalentId.Add(id);
            }
        }

        return equivalentId.Count == 0 ? (null, null) : (resolvedId, equivalentId);
    }


    /// <summary>
    /// Adds the did:webvh implicit <c>#files</c> (relativeRef) and <c>#whois</c> (LinkedVerifiablePresentation)
    /// services to the resolved DIDDoc unless an explicit service of the same id is already present — an explicit
    /// service overrides the implicit one (did:webvh v1.0, DID URL Resolution). The <c>serviceEndpoint</c> base is
    /// the DID Log location with the <c>did.jsonl</c> file and any <c>.well-known/</c> segment removed.
    /// </summary>
    /// <param name="document">The resolved DID document to augment.</param>
    /// <param name="did">The resolved DID, used to form the service ids.</param>
    /// <param name="logUrl">The DID Log URL the service-endpoint base is derived from.</param>
    private static void AddImplicitServices(DidDocument document, string did, string logUrl)
    {
        string baseUrl = ServiceBaseUrl(logUrl);

        if(!HasServiceWithFragment(document, WellKnownWebVhValues.FilesServiceFragment))
        {
            _ = document.WithService(new Service
            {
                Id = DidUrl.Parse($"{did}{WellKnownWebVhValues.FilesServiceFragment}"),
                Type = WellKnownServiceTypes.RelativeRef,
                ServiceEndpoint = baseUrl
            });
        }

        if(!HasServiceWithFragment(document, WellKnownWebVhValues.WhoisServiceFragment))
        {
            //The LinkedVerifiablePresentation service carries the linked-vp @context that binds its type
            //semantics (did:webvh v1.0, whois LinkedVP Service); the #files relativeRef service does not.
            _ = document.WithService(new Service
            {
                Id = DidUrl.Parse($"{did}{WellKnownWebVhValues.WhoisServiceFragment}"),
                Type = WellKnownServiceTypes.LinkedVerifiablePresentation,
                ServiceEndpoint = baseUrl + WellKnownWebVhValues.WhoisFile,
                AdditionalData = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["@context"] = WellKnownServiceTypes.LinkedVerifiablePresentationContext
                }
            });
        }
    }


    /// <summary>
    /// The implicit-service endpoint base: the DID Log URL with the <c>did.jsonl</c> file name and any trailing
    /// <c>.well-known/</c> segment removed.
    /// </summary>
    /// <param name="logUrl">The DID Log URL.</param>
    /// <returns>The service-endpoint base URL.</returns>
    private static string ServiceBaseUrl(string logUrl)
    {
        string baseUrl = logUrl.EndsWith(WellKnownWebVhValues.DidLogFile, StringComparison.Ordinal)
            ? logUrl[..^WellKnownWebVhValues.DidLogFile.Length]
            : logUrl;

        string wellKnownPath = $"{WellKnownWebVhValues.WellKnownSegment}/";

        return baseUrl.EndsWith(wellKnownPath, StringComparison.Ordinal)
            ? baseUrl[..^wellKnownPath.Length]
            : baseUrl;
    }


    /// <summary>
    /// Whether the DIDDoc already defines a service whose id carries the given fragment (an absolute
    /// <c>&lt;did&gt;#files</c> or a relative <c>#files</c>), in which case the explicit service overrides the
    /// implicit one.
    /// </summary>
    /// <param name="document">The DID document to inspect.</param>
    /// <param name="fragment">The service-id fragment to look for.</param>
    /// <returns><see langword="true"/> when a service with that fragment is already present.</returns>
    private static bool HasServiceWithFragment(DidDocument document, string fragment)
    {
        if(document.Service is not { } services)
        {
            return false;
        }

        foreach(Service service in services)
        {
            if(service.Id?.ToString().EndsWith(fragment, StringComparison.Ordinal) == true)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Selects the log entry index the resolution targets per the version-query parameters: an exact
    /// <c>versionId</c>, an exact <c>versionNumber</c>, the entry active at <c>versionTime</c> (the latest entry
    /// whose <c>versionTime</c> is at or before the requested time), or — with no version query — the latest
    /// entry. A requested version that is absent or not active at the requested time is a NotFound (did:webvh
    /// v1.0, Reading did:webvh DID URLs).
    /// </summary>
    /// <param name="entries">The parsed DID Log entries.</param>
    /// <param name="options">The resolution options carrying any version query.</param>
    /// <returns>The target entry index and a <see langword="null"/> error, or <c>-1</c> and a NotFound problem.</returns>
    private static (int Index, DidProblemDetails? Error) SelectTargetEntry(
        List<LogEntry<WebVhRawEntry, WebVhProof>> entries,
        DidResolutionOptions options)
    {
        if(options.VersionId is { Length: > 0 } versionId)
        {
            for(int i = 0; i < entries.Count; i++)
            {
                if(string.Equals(entries[i].Operation?.VersionId, versionId, StringComparison.Ordinal))
                {
                    if(options.VersionNumber is int requestedNumber
                        && (!WebVhVersionId.TryParse(versionId, out int versionNumber, out _) || versionNumber != requestedNumber))
                    {
                        return (-1, DidResolutionErrors.NotFound);
                    }

                    return ValidateTimeConstraint(entries, i, options);
                }
            }

            return (-1, DidResolutionErrors.NotFound);
        }

        if(options.VersionNumber is int number)
        {
            for(int i = 0; i < entries.Count; i++)
            {
                if(WebVhVersionId.TryParse(entries[i].Operation?.VersionId, out int parsed, out _) && parsed == number)
                {
                    return ValidateTimeConstraint(entries, i, options);
                }
            }

            return (-1, DidResolutionErrors.NotFound);
        }

        if(options.VersionTime is DateTimeOffset versionTime)
        {
            int active = -1;
            for(int i = 0; i < entries.Count; i++)
            {
                if(TryGetEntryTime(entries[i], out DateTimeOffset entryTime) && entryTime <= versionTime)
                {
                    active = i;
                }
            }

            return active >= 0 ? (active, null) : (-1, DidResolutionErrors.NotFound);
        }

        return (entries.Count - 1, null);
    }


    /// <summary>
    /// A version selected by <c>versionId</c>/<c>versionNumber</c> is only valid at a requested <c>versionTime</c>
    /// if its own <c>versionTime</c> is at or before that time.
    /// </summary>
    /// <param name="entries">The parsed DID Log entries.</param>
    /// <param name="index">The index selected by versionId/versionNumber.</param>
    /// <param name="options">The resolution options carrying any versionTime constraint.</param>
    /// <returns>The validated index, or <c>-1</c> and a NotFound problem when the time constraint is violated.</returns>
    private static (int Index, DidProblemDetails? Error) ValidateTimeConstraint(
        List<LogEntry<WebVhRawEntry, WebVhProof>> entries,
        int index,
        DidResolutionOptions options)
    {
        if(options.VersionTime is DateTimeOffset versionTime
            && TryGetEntryTime(entries[index], out DateTimeOffset entryTime)
            && entryTime > versionTime)
        {
            return (-1, DidResolutionErrors.NotFound);
        }

        return (index, null);
    }


    /// <summary>
    /// Reads an entry's <c>versionTime</c> using the same strict UTC-'Z' grammar as the verifier, so a
    /// <c>versionTime</c> query selects the entry a conformant resolver would.
    /// </summary>
    /// <param name="entry">The DID Log entry.</param>
    /// <param name="value">When this returns <see langword="true"/>, the entry's parsed <c>versionTime</c>.</param>
    /// <returns><see langword="true"/> when the entry carries a parseable <c>versionTime</c>.</returns>
    private static bool TryGetEntryTime(LogEntry<WebVhRawEntry, WebVhProof> entry, out DateTimeOffset value)
    {
        value = default;

        //Version SELECTION uses the same strict UTC-'Z' grammar as the verifier (WebVhProofVerification), so a
        //versionTime query selects the entry a conformant resolver would, not a different one a lenient parse
        //might admit (did:webvh v1.0, The DID Log File: versionTime is a UTC ISO8601 with an explicit 'Z').
        return entry.Operation?.VersionTime is { Length: > 0 } versionTime
            && WebVhProofVerification.TryParseVersionTime(versionTime, out value);
    }


    /// <summary>The first entry is the genesis; an entry declaring <c>deactivated:true</c> is terminal; all others update.</summary>
    /// <param name="entry">The entry to classify.</param>
    /// <returns>The entry's classification.</returns>
    private static LogEntryClassification ClassifyEntry(LogEntry<WebVhRawEntry, WebVhProof> entry)
    {
        if(entry.Index == 0)
        {
            return LogEntryClassification.Genesis;
        }

        if(entry.Operation?.DeclaredParameters.Deactivated == true)
        {
            return LogEntryClassification.Deactivate;
        }

        return LogEntryClassification.Update;
    }


    /// <summary>
    /// Folds the declared parameters onto the accumulated state and advances to the active (or, for a deactivation
    /// entry, terminal) state. The fold re-succeeds here because proof validation already ran it.
    /// </summary>
    /// <param name="classification">The entry's classification.</param>
    /// <param name="currentState">The current log state before this entry is applied.</param>
    /// <param name="entry">The entry to apply.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The new log state and <see langword="null"/> on success, or the unchanged state and an error.</returns>
    private static ValueTask<(LogState<WebVhState> State, string? Error)> ApplyEntry(
        LogEntryClassification classification,
        LogState<WebVhState> currentState,
        LogEntry<WebVhRawEntry, WebVhProof> entry,
        CancellationToken cancellationToken)
    {
        if(entry.Operation is not WebVhRawEntry rawEntry)
        {
            //The (string?) cast is load-bearing: ValueTask.FromResult<TResult> infers TResult from
            //the argument alone, so a bare string literal would infer a non-nullable tuple element
            //and fail to convert to the declared ValueTask<(LogState<WebVhState>, string?)> return type.
            return ValueTask.FromResult((currentState, (string?)"The did:webvh log entry carries no parsed content."));
        }

        WebVhParameters? parameters;
        string? error;
        if(classification == LogEntryClassification.Genesis)
        {
            (parameters, error) = WebVhParameters.FoldGenesis(rawEntry.DeclaredParameters);
        }
        else if(currentState is ActiveLogState<WebVhState> active)
        {
            (parameters, error) = WebVhParameters.Fold(active.Value.Parameters, rawEntry.DeclaredParameters);
        }
        else
        {
            return ValueTask.FromResult((currentState, (string?)$"The did:webvh entry at index {entry.Index} cannot be applied to state '{currentState.GetType().Name}'."));
        }

        if(error is not null)
        {
            return ValueTask.FromResult((currentState, (string?)error));
        }

        WebVhState state = new(parameters!, rawEntry.VersionId, rawEntry.VersionTime);
        LogState<WebVhState> nextState = classification == LogEntryClassification.Deactivate
            ? new DeactivatedLogState<WebVhState>(state)
            : new ActiveLogState<WebVhState>(state);

        return ValueTask.FromResult((nextState, (string?)null));
    }


    /// <summary>
    /// Splits the fetched <c>did.jsonl</c> into entries, slicing each line out of the fetched buffer (no
    /// re-encode); the line slice backs the entry's <c>CanonicalBytes</c> that the canonicalizers re-parse.
    /// </summary>
    /// <param name="body">The fetched DID Log body.</param>
    /// <param name="lineParser">Parses one <c>did.jsonl</c> line into a <see cref="WebVhRawEntry"/>.</param>
    /// <returns>The parsed log entries, one per non-empty line.</returns>
    private static List<LogEntry<WebVhRawEntry, WebVhProof>> ParseEntries(ReadOnlyMemory<byte> body, WebVhLineParser lineParser)
    {
        var entries = new List<LogEntry<WebVhRawEntry, WebVhProof>>();
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

            WebVhRawEntry parsed = lineParser(line);
            entries.Add(new LogEntry<WebVhRawEntry, WebVhProof>
            {
                Index = index,
                PreviousDigest = null,
                Digest = Encoding.UTF8.GetBytes(parsed.VersionId),
                CanonicalBytes = line,
                Operation = parsed,
                Proofs = parsed.Proofs
            });

            index++;
        }

        return entries;
    }


    /// <summary>Trims leading and trailing ASCII whitespace from a DID Log line slice.</summary>
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
    /// <param name="entries">The parsed DID Log entries.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The entries as an async stream.</returns>
    private static async IAsyncEnumerable<LogEntry<WebVhRawEntry, WebVhProof>> ToAsync(
        List<LogEntry<WebVhRawEntry, WebVhProof>> entries,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach(LogEntry<WebVhRawEntry, WebVhProof> entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;

            await Task.CompletedTask.ConfigureAwait(false);
        }
    }


    /// <summary>
    /// A <see cref="TimeProvider"/> frozen at a single instant, so every <c>versionTime</c> and proof-expiry
    /// comparison in one resolution is judged against the same committed resolution clock rather than a clock that
    /// advances mid-replay. The underlying provider's UTC instant is captured once at the start of each resolve.
    /// </summary>
    private sealed class FrozenTimeProvider: TimeProvider
    {
        /// <summary>The committed resolution instant returned for every <see cref="GetUtcNow"/> call.</summary>
        private DateTimeOffset Instant { get; }

        /// <summary>Creates a provider frozen at the given instant.</summary>
        /// <param name="instant">The instant to freeze at.</param>
        public FrozenTimeProvider(DateTimeOffset instant)
        {
            this.Instant = instant;
        }

        /// <inheritdoc />
        public override DateTimeOffset GetUtcNow()
        {
            return Instant;
        }
    }
}
