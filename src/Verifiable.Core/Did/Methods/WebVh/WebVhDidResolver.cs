using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.EventLogs;
using Verifiable.Core.Model.Did;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;

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
/// <see cref="Resolve"/> computes the DID Log URL only. <see cref="Build"/> performs full resolution: it
/// fetches the <c>did.jsonl</c> through the guarded outbound-fetch chokepoint, replays and verifies every
/// entry through the <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>, and returns the resolved
/// <see cref="DidDocument"/>.
/// </para>
/// </remarks>
public static class WebVhDidResolver
{
    private static readonly char[] PathSeparator = [':'];

    //An upper bound on the fetched did.jsonl size, so a malicious or misconfigured host cannot exhaust resolver
    //memory by serving an unbounded DID Log (did:webvh v1.0: resolvers SHOULD guard against resource-exhaustion
    //during retrieval). The bound is generous relative to a real DID Log (each entry is a single JSON line) yet
    //rejects an obviously hostile payload.
    private const int MaxDidLogBytes = 8 * 1024 * 1024;

    //An upper bound on the fetched did-witness.json size, mirroring MaxDidLogBytes so a malicious or MITM'd
    //witness host cannot exhaust resolver memory/CPU by serving an unbounded witness file (verifying every
    //entry × proof is JCS-canonicalize + 2×SHA-256 + Ed25519). The size cap bounds the proof count too, since
    //each proof costs bytes. Enforced before the body is copied into a pooled buffer.
    private const int MaxWitnessFileBytes = 8 * 1024 * 1024;

    //IDNA2008 mapping for the DID-to-HTTPS domain transform. IdnMapping.GetAscii applies RFC3491 Unicode
    //normalization and Punycode-encodes each international label, leaving ASCII domains unchanged.
    private static readonly IdnMapping DomainIdnMapping = new();

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

        //The method-specific id is "<scid>:<domain>[:<path>...]". Split on colons — a colon separates DID
        //segments while %3A is a literal colon for a port — then drop the SCID (the first segment), leaving the
        //domain segment and any path segments to map exactly as did:web does.
        string[] parts = didWebVhIdentifier[prefixWithColon.Length..].Split(PathSeparator);
        if(parts.Length < 2 || parts[0].Length == 0)
        {
            throw new ArgumentException(
                $"The did:webvh identifier '{didWebVhIdentifier}' must contain an SCID segment followed by a domain.",
                nameof(didWebVhIdentifier));
        }

        //The domain is the first segment after the SCID. RFC3491 Unicode normalization and IDNA2008 Punycode
        //encoding apply to the host (jp納豆.例.jp -> xn--jp-cd2fp15c.xn--fsq.jp), while a percent-encoded port
        //(%3A) is decoded to a literal colon and the port number kept as-is (did:webvh v1.0, DID-to-HTTPS
        //Transformation).
        string domain = EncodeDomainSegment(parts[1]);

        //Each remaining path segment is percent-encoded per RFC3986 (用户 -> %E7%94%A8%E6%88%B7) so an
        //internationalized path maps to a valid HTTP URL; the ':' separators become '/'.
        var location = new StringBuilder(domain);
        for(int i = 2; i < parts.Length; i++)
        {
            location.Append('/');
            location.Append(Uri.EscapeDataString(parts[i]));
        }

        bool hasPath = parts.Length > 2;
        string logUrl = $"https://{location}";

        if(!hasPath)
        {
            logUrl += $"/{WellKnownWebVhValues.WellKnownSegment}";
        }

        logUrl += $"/{WellKnownWebVhValues.DidLogFile}";

        return logUrl;
    }


    //The did:webvh SCID ABNF: exactly 46 characters drawn from the base58btc alphabet (did:webvh v1.0: "scid =
    //46(base58-alphabet)"). The base58btc alphabet excludes 0, O, I and l to avoid visually ambiguous characters.
    private const int ScidLength = 46;
    private const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    //Whether the SCID segment of a did:webvh identifier (the first segment after "did:webvh:") is well-formed.
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


    //Maps a did:webvh domain segment to its HTTPS host[:port] form: IDNA/Punycode-encode the host per IDNA2008
    //(RFC3491 Unicode normalization is applied by IdnMapping.GetAscii), and preserve a %3A-encoded port by
    //decoding only that colon — the host stays IDNA-encoded (did:webvh v1.0, DID-to-HTTPS Transformation).
    private static string EncodeDomainSegment(string domainSegment)
    {
        //%3A (or %3a) is the literal colon separating host and port. Splitting on it isolates the host so the
        //port number is preserved verbatim while only the host is IDNA-encoded.
        int portIndex = domainSegment.IndexOf("%3A", StringComparison.OrdinalIgnoreCase);
        string host = portIndex >= 0 ? domainSegment[..portIndex] : domainSegment;
        string? port = portIndex >= 0 ? domainSegment[(portIndex + 3)..] : null;

        string asciiHost = DomainIdnMapping.GetAscii(host);

        return port is null ? asciiHost : $"{asciiHost}:{port}";
    }


    /// <summary>
    /// Builds a <see cref="DidMethodResolverDelegate"/> that fully resolves a <c>did:webvh</c>: it computes
    /// the DID Log URL, fetches the <c>did.jsonl</c> through the guarded
    /// <see cref="OutboundFetch"/> chokepoint, replays and verifies every entry (entryHash chain, SCID,
    /// controller proofs, pre-rotation, versionTime), and returns the resolved <see cref="DidDocument"/>
    /// from the last entry's <c>state</c>.
    /// </summary>
    /// <param name="transport">The application-supplied single-hop transport the guarded fetch drives.</param>
    /// <param name="lineParser">Parses one <c>did.jsonl</c> line into a <see cref="WebVhRawEntry"/>.</param>
    /// <param name="witnessFileParser">Parses the <c>did-witness.json</c> file into its witness proof records.</param>
    /// <param name="documentIdentityReader">Reads each entry's DIDDoc <c>id</c> and <c>alsoKnownAs</c> for the portability check.</param>
    /// <param name="stateDeserializer">Deserializes the resolved entry's <c>state</c> into a <see cref="DidDocument"/>.</param>
    /// <param name="canonicalizer">The JCS canonicalizers the verification steps hash and sign over.</param>
    /// <param name="hashFunction">The SHA-256 hash function fixed by did:webvh v1.0.</param>
    /// <param name="base58Encoder">The raw base58btc encoder (no multibase prefix).</param>
    /// <param name="base58Decoder">The base58btc decoder for update keys and proof values.</param>
    /// <param name="pool">The pool the key, signature, hash and witness-file buffers are rented from.</param>
    /// <param name="timeProvider">The clock used for the <c>versionTime</c> checks.</param>
    /// <returns>A <see cref="DidMethodResolverDelegate"/> for registration with the resolver composition.</returns>
    public static DidMethodResolverDelegate Build(
        OutboundTransportDelegate transport,
        WebVhLineParser lineParser,
        WebVhWitnessFileParser witnessFileParser,
        WebVhDocumentIdentityReader documentIdentityReader,
        WebVhStateDeserializer stateDeserializer,
        WebVhCanonicalizer canonicalizer,
        HashFunctionDelegate hashFunction,
        EncodeDelegate base58Encoder,
        DecodeDelegate base58Decoder,
        MemoryPool<byte> pool,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(lineParser);
        ArgumentNullException.ThrowIfNull(witnessFileParser);
        ArgumentNullException.ThrowIfNull(documentIdentityReader);
        ArgumentNullException.ThrowIfNull(stateDeserializer);
        ArgumentNullException.ThrowIfNull(canonicalizer);
        ArgumentNullException.ThrowIfNull(hashFunction);
        ArgumentNullException.ThrowIfNull(base58Encoder);
        ArgumentNullException.ThrowIfNull(base58Decoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        VerifyChainIntegrityDelegate<WebVhRawEntry, WebVhProof> verifyChainIntegrity =
            WebVhChainVerification.Create(canonicalizer.EntryHashInput, hashFunction, base58Encoder, base58Decoder, pool);

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
                    HashFunction = hashFunction,
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
            //any source is used; if none succeed, the DID is notFound.
            OutboundResponse? logResponse = await FetchDidLogAsync(target, options, transport, context, cancellationToken).ConfigureAwait(false);
            if(logResponse is null)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
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

            DidDocumentMetadata metadata = new()
            {
                VersionId = finalState.VersionId,
                Deactivated = isResolvedVersionDeactivated,
                Created = WebVhResolutionMetadata.ParseTimestamp(states[0].VersionTime),
                Updated = WebVhResolutionMetadata.ParseTimestamp(finalState.VersionTime),
                AdditionalData = WebVhResolutionMetadata.Build(finalState, isResolvedVersionDeactivated)
            };

            //When the resolved (latest) version is itself the deactivation, the resolver MUST NOT return the
            //DIDDoc: a result with a null document and deactivated:true metadata so DidResolver Step 5b surfaces
            //it as a deactivated resolution (did:webvh v1.0, Deactivate: L1019). A prior version queried on a
            //deactivated DID still returns its DIDDoc with deactivated:true metadata (L1023), so the
            //null-document rule applies only when the target entry is the deactivation itself.
            if(isDeactivated)
            {
                return DidResolutionResult.SuccessDeactivated(metadata, contentType: "application/did+json");
            }

            return DidResolutionResult.Success(document, metadata, contentType: "application/did+json");
        };
    }


    //Fetches the DID Log from the primary location, then — only on a not-found condition — from each supplied
    //alternative source (Watcher URL) in turn. Returns the first successful 200 response body, or null when no
    //source yields one. A transport failure or a non-200 status is treated as not-found for fallback purposes;
    //the retrieved log is verified by the caller exactly as the primary would be, so a tampered alternative
    //source still fails verification (did:webvh v1.0, Read: L886).
    private static async ValueTask<OutboundResponse?> FetchDidLogAsync(
        Uri primaryTarget,
        DidResolutionOptions options,
        OutboundTransportDelegate transport,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        OutboundResponse? primary = await TryFetchLogAsync(primaryTarget, transport, context, cancellationToken).ConfigureAwait(false);
        if(primary is not null)
        {
            return primary;
        }

        if(options.WatcherUrls is not { Count: > 0 } watcherUrls)
        {
            return null;
        }

        foreach(string watcherUrl in watcherUrls)
        {
            if(!Uri.TryCreate(watcherUrl, UriKind.Absolute, out Uri? watcherTarget))
            {
                continue;
            }

            OutboundResponse? watcherResponse = await TryFetchLogAsync(watcherTarget, transport, context, cancellationToken).ConfigureAwait(false);
            if(watcherResponse is not null)
            {
                return watcherResponse;
            }
        }

        return null;
    }


    //Drives one guarded fetch for the DID Log, returning the response only on a successful 200, or null on a
    //transport failure or any non-200 status. Cancellation is always propagated.
    private static async ValueTask<OutboundResponse?> TryFetchLogAsync(
        Uri target,
        OutboundTransportDelegate transport,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        OutboundRequest request = new() { Target = target, Method = "GET", MaxResponseBytes = MaxDidLogBytes };

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


    //Fetches and verifies did-witness.json when the replayed log has active witnesses. Returns a problem
    //detail to fail resolution closed (the file is absent/unreachable while witnesses are active, or a
    //threshold is unmet), or null when every entry requiring witnessing is approved.
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

        OutboundRequest request = new() { Target = witnessTarget, Method = "GET", MaxResponseBytes = MaxWitnessFileBytes };

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
            return DidResolutionErrors.InvalidDid;
        }

        //Witnesses are active, so an absent or unsuccessful did-witness.json fails resolution closed: the
        //entries requiring witnessing cannot be confirmed without it.
        if(!fetch.IsFetched || fetch.Response is null || fetch.Response.StatusCode != 200)
        {
            return InvalidDid("Witnesses are active but the did-witness.json file could not be retrieved.");
        }

        //The did-witness.json media type SHOULD be application/json (did:webvh v1.0, The Witness Proofs File).
        //A response that declares a different content type is treated as a retrieval failure: the file the
        //witness rule depends on was not served in its defined form, so witnessing cannot be confirmed. An
        //absent Content-Type is tolerated (the SHOULD does not require the header to be present).
        if(!IsAcceptableJsonContentType(fetch.Response))
        {
            return InvalidDid("The did:webvh did-witness.json was served with a non-JSON Content-Type.");
        }

        ReadOnlyMemory<byte> body = fetch.Response.Body.Memory;
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
            return DidResolutionErrors.InvalidDid;
        }
        finally
        {
            witnessFile?.Dispose();
            owner?.Dispose();
        }
    }


    //Whether a did-witness.json response carries an acceptable Content-Type: application/json (the SHOULD media
    //type), or no Content-Type header at all (the SHOULD does not require the header to be present). Any media
    //type parameters (for example "; charset=utf-8") are ignored, comparing only the media type. A response
    //declaring a different media type is rejected so the witness file is consumed only in its defined form.
    private static bool IsAcceptableJsonContentType(OutboundResponse response)
    {
        if(!response.TryGetHeader("Content-Type", out string? contentType) || contentType is not { Length: > 0 })
        {
            return true;
        }

        int parameterIndex = contentType.IndexOf(';', StringComparison.Ordinal);
        ReadOnlySpan<char> mediaType = (parameterIndex >= 0 ? contentType.AsSpan(0, parameterIndex) : contentType.AsSpan()).Trim();

        return mediaType.Equals(WellKnownWebVhValues.WitnessFileMediaType, StringComparison.OrdinalIgnoreCase);
    }


    //The witness proofs file shares the DID's web location with only the final path element changed
    //(did.jsonl -> did-witness.json) (did:webvh v1.0, The Witness Proofs File). The log URL is produced by
    //Resolve, which always ends in the DID Log file name.
    private static string ResolveWitnessUrl(string logUrl)
    {
        return logUrl.EndsWith(WellKnownWebVhValues.DidLogFile, StringComparison.Ordinal)
            ? string.Concat(logUrl.AsSpan(0, logUrl.Length - WellKnownWebVhValues.DidLogFile.Length), WellKnownWebVhValues.DidWitnessFile)
            : logUrl;
    }


    //did:webvh resolution maps every invalidating condition to the invalidDid error (did:webvh v1.0, Read:
    //"invalidDid — Any error that renders the did:webvh DID invalid during resolution"); a precise message is
    //carried as the occurrence-specific problemDetails.Detail. The detail-free form equals the shared
    //DidResolutionErrors.InvalidDid by problem-type, so callers can still compare by type.
    private static DidProblemDetails InvalidDid(string? detail)
    {
        return detail is null
            ? DidResolutionErrors.InvalidDid
            : new DidProblemDetails(DidErrorTypes.InvalidDid, Title: "Invalid DID", Detail: detail);
    }


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


    //Adds the did:webvh implicit #files (relativeRef) and #whois (LinkedVerifiablePresentation) services to the
    //resolved DIDDoc unless an explicit service of the same id is already present — an explicit service
    //overrides the implicit one (did:webvh v1.0, DID URL Resolution). The serviceEndpoint base is the DID Log
    //location with the did.jsonl file and any .well-known/ segment removed.
    private static void AddImplicitServices(DidDocument document, string did, string logUrl)
    {
        string baseUrl = ServiceBaseUrl(logUrl);

        if(!HasServiceWithFragment(document, WellKnownWebVhValues.FilesServiceFragment))
        {
            document.WithService(new Service
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
            document.WithService(new Service
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


    //Whether the DIDDoc already defines a service whose id carries the given fragment (an absolute
    //"&lt;did&gt;#files" or a relative "#files"), in which case the explicit service overrides the implicit one.
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


    //Selects the log entry index the resolution targets per the version-query parameters: an exact versionId,
    //an exact versionNumber, the entry active at versionTime (the latest entry whose versionTime is at or
    //before the requested time), or — with no version query — the latest entry. A requested version that is
    //absent or not active at the requested time is a NotFound (did:webvh v1.0, Reading did:webvh DID URLs).
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


    //A version selected by versionId/versionNumber is only valid at a requested versionTime if its own
    //versionTime is at or before that time.
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


    private static bool TryGetEntryTime(LogEntry<WebVhRawEntry, WebVhProof> entry, out DateTimeOffset value)
    {
        value = default;

        //Version SELECTION uses the same strict UTC-'Z' grammar as the verifier (WebVhProofVerification), so a
        //versionTime query selects the entry a conformant resolver would, not a different one a lenient parse
        //might admit (did:webvh v1.0, The DID Log File: versionTime is a UTC ISO8601 with an explicit 'Z').
        return entry.Operation?.VersionTime is { Length: > 0 } versionTime
            && WebVhProofVerification.TryParseVersionTime(versionTime, out value);
    }


    //The first entry is the genesis; an entry declaring deactivated:true is terminal; all others update.
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


    //Folds the declared parameters onto the accumulated state and advances to the active (or, for a
    //deactivation entry, terminal) state. The fold re-succeeds here because proof validation already ran it.
    private static ValueTask<(LogState<WebVhState> State, string? Error)> ApplyEntry(
        LogEntryClassification classification,
        LogState<WebVhState> currentState,
        LogEntry<WebVhRawEntry, WebVhProof> entry,
        CancellationToken cancellationToken)
    {
        if(entry.Operation is not WebVhRawEntry rawEntry)
        {
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


    //Splits the fetched did.jsonl into entries, slicing each line out of the fetched buffer (no re-encode);
    //the line slice backs the entry's CanonicalBytes that the canonicalizers re-parse.
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


    private static bool IsAsciiWhitespace(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';


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


    //A TimeProvider frozen at a single instant, so every versionTime and proof-expiry comparison in one
    //resolution is judged against the same committed resolution clock rather than a clock that advances
    //mid-replay. The underlying TimeProvider's UTC instant is captured once at the start of each resolve.
    private sealed class FrozenTimeProvider: TimeProvider
    {
        private readonly DateTimeOffset instant;

        public FrozenTimeProvider(DateTimeOffset instant)
        {
            this.instant = instant;
        }

        public override DateTimeOffset GetUtcNow()
        {
            return instant;
        }
    }
}
