using System;
using System.Buffers;
using System.Collections.Generic;
using Lumoin.Veritas.Cbor;
using System.Globalization;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;

namespace Verifiable.Cbor;

/// <summary>
/// The result of walking an SD-CWT payload once: every disclosure's resolved position, every
/// unconditionally disclosed node's value, and every node that exists only inside a resolved
/// disclosure's own value.
/// </summary>
/// <param name="DisclosurePaths">Each disclosure's resolved path.</param>
/// <param name="IssuerSignedClaims">Every unconditionally disclosed node, keyed by its path.</param>
/// <param name="DisclosureInteriorClaims">Every node interior to a resolved disclosure, keyed by its path.</param>
internal readonly record struct SdCwtWalkResult(
    IReadOnlyDictionary<SdDisclosure, CredentialPath> DisclosurePaths,
    IReadOnlyDictionary<CredentialPath, object?> IssuerSignedClaims,
    IReadOnlyDictionary<CredentialPath, object?> DisclosureInteriorClaims);

/// <summary>
/// Provides CBOR-specific path extraction for SD-CWT structures.
/// </summary>
/// <remarks>
/// <para>
/// This class implements the format-specific logic for extracting credential paths
/// from CBOR payloads. It works with <see cref="SdDisclosure"/> and produces
/// <see cref="CredentialPath"/> instances that can be used with <see cref="PathLattice"/>.
/// </para>
/// <para>
/// For JSON/SD-JWT path extraction, see <c>SdJwtPathExtraction</c> in Verifiable.Json.
/// </para>
/// </remarks>
public static class SdCwtPathExtraction
{
    /// <summary>
    /// The deepest chain of nested containers and recursive disclosures a payload may present
    /// before it is refused. A chain of recursive disclosures (the SD-CWT analog of RFC 9901
    /// §4.2.6) is an attacker-chosen nesting that spans encodings rather than one document's own,
    /// so it is bounded here rather than left to the call stack.
    /// </summary>
    private const int MaximumWalkDepth = 64;


    /// <summary>
    /// Extracts credential paths for all disclosures in an SD-CWT message.
    /// </summary>
    /// <param name="message">The SD-CWT message.</param>
    /// <param name="encoder">Delegate for Base64Url encoding (for digest computation).</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="hashAlgorithm">The hash algorithm name (default: "sha-256").</param>
    /// <returns>A dictionary mapping each disclosure to its credential path.</returns>
    public static IReadOnlyDictionary<SdDisclosure, CredentialPath> ExtractPaths(
        SdCwtMessage message,
        EncodeDelegate encoder,
        BaseMemoryPool pool,
        string hashAlgorithm = "sha-256")
    {
        ArgumentNullException.ThrowIfNull(message);

        return ExtractPaths(message.Payload, message.Disclosures, encoder, pool, hashAlgorithm);
    }


    /// <summary>
    /// Extracts the credential path each disclosure binds to, working from redacted payload
    /// bytes and an explicit disclosure set rather than a whole <see cref="SdCwtMessage"/>.
    /// </summary>
    /// <remarks>
    /// This is the seam the structural verifier uses: it parses only the payload from the
    /// signed envelope and supplies the holder-selected disclosures, so a narrowed
    /// presentation binds against exactly what was presented — never the original full set
    /// that the wire form's unprotected header still carries.
    /// </remarks>
    /// <param name="payload">The redacted CWT payload bytes (CBOR).</param>
    /// <param name="disclosures">The disclosures to bind against the payload's digests.</param>
    /// <param name="encoder">Delegate for Base64Url encoding (for digest computation).</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="hashAlgorithm">The hash algorithm name (default: "sha-256").</param>
    /// <returns>A dictionary mapping each bound disclosure to its credential path.</returns>
    public static IReadOnlyDictionary<SdDisclosure, CredentialPath> ExtractPaths(
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<SdDisclosure> disclosures,
        EncodeDelegate encoder,
        BaseMemoryPool pool,
        string hashAlgorithm = "sha-256")
    {
        ArgumentNullException.ThrowIfNull(disclosures);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);

        //Build a map from Base64Url-encoded digest to disclosure.
        //We use Base64Url encoding as the common comparison format.
        var digestToDisclosure = new Dictionary<string, SdDisclosure>(StringComparer.Ordinal);

        foreach(SdDisclosure disclosure in disclosures)
        {
            byte[] disclosureCbor = SdCwtSerializer.SerializeDisclosure(disclosure);
            byte[] digestBytes = SdCwtSerializer.ComputeDisclosureDigest(disclosureCbor, hashAlgorithm, pool);
            string digestBase64 = encoder(digestBytes);
            digestToDisclosure[digestBase64] = disclosure;
        }

        SdCwtWalkResult result = Walk(payload, digestToDisclosure, encoder);

        return result.DisclosurePaths;
    }


    /// <summary>
    /// Walks an SD-CWT payload once, resolving every disclosure's digest to its position and
    /// collecting every always-disclosed node — the core <see cref="SdCwtSerializer.ParseToken"/>
    /// and the standalone <see cref="ExtractPaths(SdCwtMessage, EncodeDelegate, BaseMemoryPool, string)"/>
    /// entry both run.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Enforces the digest-resolution rules
    /// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
    /// draft-ietf-spice-sd-cwt</see> mirrors from RFC 9901 §7.1 step 3.c (a resolved claim name
    /// must not collide with a name already at its level and must match its context) and step 4
    /// (no digest value repeats). These hold of the payload's own structure regardless of which
    /// disclosures the caller supplied, so both entry points enforce them alike.
    /// </para>
    /// <para>
    /// The two claim maps are disjoint by construction.
    /// <see cref="SdCwtWalkResult.IssuerSignedClaims"/> holds only nodes reachable without
    /// releasing any disclosure; a node that exists solely inside a resolved disclosure's own
    /// value goes to <see cref="SdCwtWalkResult.DisclosureInteriorClaims"/>, since reading it
    /// costs the release of the disclosure that carries it.
    /// </para>
    /// <para>
    /// Step 5 ("every Disclosure was referenced") is deliberately left to the caller:
    /// <see cref="SdCwtSerializer.ParseToken"/> enforces it because an unreferenced disclosure
    /// really did fail to parse, but a caller matching disclosures against a payload signed under
    /// a different digest algorithm than expected — the verification path's own digest-mismatch
    /// detection — legitimately produces disclosures with no match, and reports that on its own
    /// per-claim result rather than as a parse failure.
    /// </para>
    /// </remarks>
    /// <param name="payload">The redacted CWT payload bytes (CBOR).</param>
    /// <param name="digestToDisclosure">Every disclosure's wire digest, computed by the caller.</param>
    /// <param name="encoder">Delegate for Base64Url encoding used in digest comparison.</param>
    /// <returns>Each disclosure's resolved path, every unconditionally disclosed node and every disclosure-interior node.</returns>
    /// <exception cref="FormatException">
    /// Thrown when the payload fails a step 3.c or 4 rule, or when its nesting exceeds
    /// <see cref="MaximumWalkDepth"/>.
    /// </exception>
    internal static SdCwtWalkResult Walk(
        ReadOnlyMemory<byte> payload,
        IReadOnlyDictionary<string, SdDisclosure> digestToDisclosure,
        EncodeDelegate encoder)
    {
        var reader = new CborReader(payload, CborOptions.Lax);

        var disclosurePaths = new Dictionary<SdDisclosure, CredentialPath>(ReferenceEqualityComparer.Instance);
        var issuerSignedClaims = new Dictionary<CredentialPath, object?>();
        var interiorClaims = new Dictionary<CredentialPath, object?>();
        var seenDigests = new HashSet<string>(StringComparer.Ordinal);

        WalkAndClean(reader, CredentialPath.Root, digestToDisclosure, disclosurePaths, issuerSignedClaims, interiorClaims, seenDigests, encoder, depth: 0);

        return new SdCwtWalkResult(disclosurePaths, issuerSignedClaims, interiorClaims);
    }


    /// <summary>
    /// Extracts all paths from an SD-CWT payload (both disclosed and redacted).
    /// </summary>
    /// <param name="message">The SD-CWT message.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>All paths present in the credential structure.</returns>
    public static IReadOnlySet<CredentialPath> ExtractAllPaths(
        SdCwtMessage message,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(pool);

        var paths = new HashSet<CredentialPath>();
        CollectPathsFromCbor(message.Payload, CredentialPath.Root, paths);

        return paths;
    }


    /// <summary>
    /// Extracts mandatory paths from an SD-CWT payload (non-redacted claims).
    /// </summary>
    /// <param name="message">The SD-CWT message.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>Paths that are always disclosed (not redacted).</returns>
    public static IReadOnlySet<CredentialPath> ExtractMandatoryPaths(
        SdCwtMessage message,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(pool);

        var mandatory = new HashSet<CredentialPath>();
        CollectMandatoryPathsFromCbor(message.Payload, CredentialPath.Root, mandatory);

        return mandatory;
    }


    /// <summary>
    /// Creates a <see cref="PathLattice"/> from an SD-CWT message.
    /// </summary>
    /// <param name="message">The SD-CWT message.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="hashAlgorithm">The hash algorithm name.</param>
    /// <returns>A <see cref="PathLattice"/> configured for this message.</returns>
    public static PathLattice CreateLattice(
        SdCwtMessage message,
        EncodeDelegate encoder,
        BaseMemoryPool pool,
        string hashAlgorithm = "sha-256")
    {
        ArgumentNullException.ThrowIfNull(message);

        IReadOnlySet<CredentialPath> allPaths = ExtractAllPaths(message, pool);
        IReadOnlySet<CredentialPath> mandatoryPaths = ExtractMandatoryPaths(message, pool);

        var allPathsWithDisclosures = new HashSet<CredentialPath>(allPaths);
        IReadOnlyDictionary<SdDisclosure, CredentialPath> disclosurePaths =
            ExtractPaths(message, encoder, pool, hashAlgorithm);

        foreach(CredentialPath path in disclosurePaths.Values)
        {
            allPathsWithDisclosures.Add(path);
        }

        return new PathLattice(allPathsWithDisclosures, mandatoryPaths);
    }


    /// <summary>
    /// Recursively walks one CBOR node from the reader, resolving redacted-map-key digests
    /// (simple(59)) and redacted-array-element digests (tag 60) to disclosures and recursing
    /// into a resolved disclosure's own <see cref="SdDisclosure.ClaimValue"/> so a recursive
    /// disclosure resolves through its parent's path, mirroring RFC 9901 §4.2.6's SD-JWT rule
    /// for draft-ietf-spice-sd-cwt.
    /// </summary>
    /// <param name="reader">The reader, positioned at the node to walk.</param>
    /// <param name="currentPath">The node's own path.</param>
    /// <param name="digestToDisclosure">Every disclosure's wire digest.</param>
    /// <param name="disclosurePaths">Accumulates each resolved disclosure's path.</param>
    /// <param name="issuerSignedClaims">Accumulates every unconditionally disclosed node's cleaned value.</param>
    /// <param name="interiorClaims">Accumulates every node interior to a resolved disclosure.</param>
    /// <param name="seenDigests">Every digest value encountered so far, for the step 4 check.</param>
    /// <param name="encoder">Delegate for Base64Url encoding used in digest comparison.</param>
    /// <param name="depth">How many containers this node sits below.</param>
    /// <returns>
    /// This node's value with the redacted-claim-keys entry and the resolved or decoy array
    /// markers removed — what <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> stores for a
    /// container node.
    /// </returns>
    /// <exception cref="FormatException">
    /// Thrown when a step 3.c or 4 rule is violated, or when the nesting exceeds
    /// <see cref="MaximumWalkDepth"/>.
    /// </exception>
    private static object? WalkAndClean(
        CborReader reader,
        CredentialPath currentPath,
        IReadOnlyDictionary<string, SdDisclosure> digestToDisclosure,
        Dictionary<SdDisclosure, CredentialPath> disclosurePaths,
        Dictionary<CredentialPath, object?> issuerSignedClaims,
        Dictionary<CredentialPath, object?> interiorClaims,
        HashSet<string> seenDigests,
        EncodeDelegate encoder,
        int depth)
    {
        if(depth > MaximumWalkDepth)
        {
            throw new FormatException(
                $"draft-ietf-spice-sd-cwt (RFC 9901 §4.2.6's rule for recursive Disclosures): the payload's nesting exceeds the {MaximumWalkDepth} levels this parse admits.");
        }

        CborReaderState state = reader.PeekState();

        if(state == CborReaderState.StartMap)
        {
            reader.ReadStartMap();

            var localNames = new HashSet<string>(StringComparer.Ordinal);
            var redactedDigests = new List<string>();
            var cleaned = new Dictionary<string, object?>(StringComparer.Ordinal);

            while(reader.PeekState() != CborReaderState.EndMap)
            {
                //SD-CWT places redacted object-property claim digests under the simple(59) map
                //key, with an array of digest byte strings as the value (draft-ietf-spice-sd-cwt).
                //The key is a CBOR simple value — not an integer or text string.
                if(reader.PeekState() == CborReaderState.SimpleValue)
                {
                    int simpleKey = (int)reader.ReadSimpleValue();
                    if(simpleKey == SdCwtConstants.RedactedClaimKeysSimpleValue
                        && reader.PeekState() == CborReaderState.StartArray)
                    {
                        ReadDigestArray(reader, redactedDigests, encoder);
                    }
                    else
                    {
                        reader.SkipValue();
                    }

                    continue;
                }

                //Read key (could be int or string in CWT).
                object key = reader.PeekState() is CborReaderState.NegativeInteger or CborReaderState.UnsignedInteger
                    ? reader.ReadInt32()
                    : reader.ReadTextString();

                if(key is int intKey && intKey == SdCwtConstants.SdClaimsHeaderKey)
                {
                    //A COSE unprotected-header key never legitimately appears at the payload
                    //level; skipped defensively rather than misread as a claim.
                    if(reader.PeekState() == CborReaderState.StartArray)
                    {
                        ReadDigestArray(reader, redactedDigests, encoder);
                    }
                    else
                    {
                        reader.SkipValue();
                    }
                }
                else if(key is int algoKey && algoKey == SdCwtConstants.SdAlgHeaderKey)
                {
                    reader.SkipValue();
                }
                else
                {
                    string keyName = key is int ik ? ik.ToString(CultureInfo.InvariantCulture) : (string)key;

                    if(!localNames.Add(keyName))
                    {
                        throw new FormatException(
                            $"draft-ietf-spice-sd-cwt: the claim name '{keyName}' already exists at this level.");
                    }

                    CredentialPath childPath = currentPath.Append(keyName);
                    object? cleanedChild = WalkAndClean(reader, childPath, digestToDisclosure, disclosurePaths, issuerSignedClaims, interiorClaims, seenDigests, encoder, depth + 1);
                    issuerSignedClaims[childPath] = cleanedChild;
                    cleaned[keyName] = cleanedChild;
                }
            }

            reader.ReadEndMap();

            foreach(string digest in redactedDigests)
            {
                RecordDigest(digest, seenDigests);

                //A digest with no matching Disclosure is a decoy and is ignored.
                if(!digestToDisclosure.TryGetValue(digest, out SdDisclosure? disclosure))
                {
                    continue;
                }

                if(disclosure.ClaimName is not { } claimName)
                {
                    throw new FormatException(
                        "draft-ietf-spice-sd-cwt: a redacted-claim-key digest resolved to an array-element disclosure.");
                }

                //RFC 9901 §7.1 step 3.c.ii.2's rule for the CBOR profile: a resolved claim name
                //must not be one of the labels the redaction mechanism itself owns.
                if(IsMechanismLabel(claimName))
                {
                    throw new FormatException(
                        $"draft-ietf-spice-sd-cwt: the claim name '{claimName}' is a reserved mechanism label.");
                }

                if(!localNames.Add(claimName))
                {
                    throw new FormatException(
                        $"draft-ietf-spice-sd-cwt: the claim name '{claimName}' already exists at this level.");
                }

                CredentialPath disclosurePath = currentPath.Append(claimName);
                disclosurePaths[disclosure] = disclosurePath;

                //Recursively process the Disclosure's own value for further nested redaction.
                WalkDisclosureValue(disclosure.ClaimValue, disclosurePath, digestToDisclosure, disclosurePaths, interiorClaims, seenDigests, encoder, depth + 1);
            }

            return cleaned;
        }

        if(state == CborReaderState.StartArray)
        {
            reader.ReadStartArray();

            var cleaned = new List<object?>();
            int index = 0;

            while(reader.PeekState() != CborReaderState.EndArray)
            {
                if(reader.PeekState() == CborReaderState.Tag)
                {
                    CborTag tag = reader.ReadTag();
                    if(tag.Value == SdCwtConstants.RedactedClaimElementTag && reader.PeekState() == CborReaderState.ByteString)
                    {
                        string digest = encoder(reader.ReadByteString());
                        RecordDigest(digest, seenDigests);

                        if(digestToDisclosure.TryGetValue(digest, out SdDisclosure? disclosure))
                        {
                            if(disclosure.ClaimName is not null)
                            {
                                throw new FormatException(
                                    "draft-ietf-spice-sd-cwt: a redacted array-element digest resolved to an object-property disclosure.");
                            }

                            CredentialPath elementPath = currentPath.Append(index);
                            disclosurePaths[disclosure] = elementPath;

                            WalkDisclosureValue(disclosure.ClaimValue, elementPath, digestToDisclosure, disclosurePaths, interiorClaims, seenDigests, encoder, depth + 1);
                        }

                        //Decoy or resolved: the position still counts toward the index; the
                        //marker itself is not part of the visible structure.
                        index++;
                        continue;
                    }

                    //An ordinary tagged value that is not a redaction marker: walk the value
                    //the tag wraps in place; the reader is now positioned at it.
                    CredentialPath taggedPath = currentPath.Append(index);
                    object? cleanedTagged = WalkAndClean(reader, taggedPath, digestToDisclosure, disclosurePaths, issuerSignedClaims, interiorClaims, seenDigests, encoder, depth + 1);
                    issuerSignedClaims[taggedPath] = cleanedTagged;
                    cleaned.Add(cleanedTagged);
                    index++;
                    continue;
                }

                CredentialPath itemPath = currentPath.Append(index);
                object? cleanedItem = WalkAndClean(reader, itemPath, digestToDisclosure, disclosurePaths, issuerSignedClaims, interiorClaims, seenDigests, encoder, depth + 1);
                issuerSignedClaims[itemPath] = cleanedItem;
                cleaned.Add(cleanedItem);
                index++;
            }

            reader.ReadEndArray();

            return cleaned;
        }

        return CborValueConverter.ReadValue(ref reader);
    }


    /// <summary>
    /// Recursively walks a disclosure's own already-materialized <see cref="SdDisclosure.ClaimValue"/>,
    /// recording every node it carries as a disclosure-interior node and resolving a further
    /// redacted array element (tag 60) — the recursive-disclosure case per RFC 9901 §4.2.6's
    /// SD-CWT analog. A redacted-claim-key (map) marker cannot appear here: a disclosure whose
    /// value contained one could not have been parsed into a <see cref="SdDisclosure.ClaimValue"/>
    /// in the first place, since <see cref="CborValueConverter.ReadValue(ref CborReader)"/> has no
    /// case for the simple(59) key's <see cref="CborReaderState.SimpleValue"/> state, so such a
    /// disclosure is refused when its bytes are read.
    /// </summary>
    /// <remarks>
    /// The nodes recorded here are exactly the ones reading costs the release of the disclosure
    /// that carries them, which is why they are kept apart from
    /// <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> and populated the same way the SD-JWT
    /// walker populates its own interior map.
    /// </remarks>
    /// <param name="value">The disclosure's own materialized value.</param>
    /// <param name="currentPath">The disclosure's own path.</param>
    /// <param name="digestToDisclosure">Every disclosure's wire digest.</param>
    /// <param name="disclosurePaths">Accumulates each resolved disclosure's path.</param>
    /// <param name="interiorClaims">Accumulates every node interior to a resolved disclosure.</param>
    /// <param name="seenDigests">Every digest value encountered so far, for the step 4 check.</param>
    /// <param name="encoder">Delegate for Base64Url encoding used in digest comparison.</param>
    /// <param name="depth">How many containers and disclosure values this value sits below.</param>
    /// <exception cref="FormatException">
    /// Thrown when a digest repeats, resolves against its context, or when the chain of recursive
    /// disclosures exceeds <see cref="MaximumWalkDepth"/>.
    /// </exception>
    private static void WalkDisclosureValue(
        object? value,
        CredentialPath currentPath,
        IReadOnlyDictionary<string, SdDisclosure> digestToDisclosure,
        Dictionary<SdDisclosure, CredentialPath> disclosurePaths,
        Dictionary<CredentialPath, object?> interiorClaims,
        HashSet<string> seenDigests,
        EncodeDelegate encoder,
        int depth)
    {
        if(depth > MaximumWalkDepth)
        {
            throw new FormatException(
                $"draft-ietf-spice-sd-cwt (RFC 9901 §4.2.6's rule for recursive Disclosures): the chain of nested Disclosure values exceeds the {MaximumWalkDepth} levels this parse admits.");
        }

        if(value is IDictionary<object, object?> map)
        {
            foreach(KeyValuePair<object, object?> entry in map)
            {
                if(LabelOf(entry.Key) is not { } keyName)
                {
                    continue;
                }

                CredentialPath childPath = currentPath.Append(keyName);
                interiorClaims[childPath] = entry.Value;
                WalkDisclosureValue(entry.Value, childPath, digestToDisclosure, disclosurePaths, interiorClaims, seenDigests, encoder, depth + 1);
            }

            return;
        }

        if(value is List<object?> array)
        {
            int index = 0;
            foreach(object? item in array)
            {
                if(item is ValueTuple<ulong, object?> { Item1: SdCwtConstants.RedactedClaimElementTag, Item2: byte[] digestBytes })
                {
                    string digest = encoder(digestBytes);
                    RecordDigest(digest, seenDigests);

                    if(digestToDisclosure.TryGetValue(digest, out SdDisclosure? disclosure))
                    {
                        if(disclosure.ClaimName is not null)
                        {
                            throw new FormatException(
                                "draft-ietf-spice-sd-cwt: a redacted array-element digest resolved to an object-property disclosure.");
                        }

                        CredentialPath elementPath = currentPath.Append(index);
                        disclosurePaths[disclosure] = elementPath;

                        WalkDisclosureValue(disclosure.ClaimValue, elementPath, digestToDisclosure, disclosurePaths, interiorClaims, seenDigests, encoder, depth + 1);
                    }
                }
                else
                {
                    CredentialPath itemPath = currentPath.Append(index);
                    interiorClaims[itemPath] = item;
                    WalkDisclosureValue(item, itemPath, digestToDisclosure, disclosurePaths, interiorClaims, seenDigests, encoder, depth + 1);
                }

                index++;
            }
        }
    }


    /// <summary>
    /// Renders a CBOR map key as the path segment that addresses it: an integer label as its
    /// decimal text (the form the payload walk uses), a text-string label as itself. A key of any
    /// other CBOR type addresses no path segment and yields <see langword="null"/>.
    /// </summary>
    /// <param name="key">The map key as <see cref="CborValueConverter.ReadValue(ref CborReader)"/> materialized it.</param>
    private static string? LabelOf(object key) => key switch
    {
        int intKey => intKey.ToString(CultureInfo.InvariantCulture),
        long longKey => longKey.ToString(CultureInfo.InvariantCulture),
        ulong ulongKey => ulongKey.ToString(CultureInfo.InvariantCulture),
        string textKey => textKey,
        _ => null
    };


    /// <summary>
    /// Whether a resolved claim name is one of the labels the SD-CWT redaction mechanism owns —
    /// the <c>sd_claims</c> (<see cref="SdCwtConstants.SdClaimsHeaderKey"/>), <c>sd_alg</c>
    /// (<see cref="SdCwtConstants.SdAlgHeaderKey"/>) and AEAD-encrypted-claims
    /// (<see cref="SdCwtConstants.SdAeadEncryptedClaimsHeaderKey"/>) labels — rendered as the
    /// decimal text the walk addresses them by.
    /// </summary>
    /// <param name="claimName">The claim name a redacted-claim-key digest resolved to.</param>
    private static bool IsMechanismLabel(string claimName) =>
        string.Equals(claimName, SdCwtConstants.SdClaimsHeaderKey.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)
        || string.Equals(claimName, SdCwtConstants.SdAlgHeaderKey.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)
        || string.Equals(claimName, SdCwtConstants.SdAeadEncryptedClaimsHeaderKey.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);


    /// <summary>
    /// Reads a CBOR array of digest values (byte strings or, for interoperability, text
    /// strings) into <paramref name="digests"/>, encoding byte-string digests to Base64Url for
    /// comparison against the map built from <see cref="SdCwtSerializer.ComputeDisclosureDigest(ReadOnlySpan{byte}, string, BaseMemoryPool)"/>.
    /// </summary>
    /// <param name="reader">The reader, positioned at the start of the digest array.</param>
    /// <param name="digests">Accumulates every digest value read.</param>
    /// <param name="encoder">Delegate for Base64Url encoding byte-string digests.</param>
    private static void ReadDigestArray(CborReader reader, List<string> digests, EncodeDelegate encoder)
    {
        reader.ReadStartArray();

        while(reader.PeekState() != CborReaderState.EndArray)
        {
            CborReaderState digestState = reader.PeekState();
            if(digestState == CborReaderState.ByteString)
            {
                digests.Add(encoder(reader.ReadByteString()));
            }
            else if(digestState == CborReaderState.TextString)
            {
                digests.Add(reader.ReadTextString());
            }
            else
            {
                reader.SkipValue();
            }
        }

        reader.ReadEndArray();
    }


    /// <summary>
    /// Records a digest value for the step 4 duplicate check (RFC 9901 §7.1 step 4, mirrored by
    /// draft-ietf-spice-sd-cwt): a digest value encountered more than once in the payload
    /// (directly or recursively via other Disclosures) invalidates the token.
    /// </summary>
    /// <param name="digest">The digest value encountered.</param>
    /// <param name="seenDigests">Every digest value encountered so far.</param>
    /// <exception cref="FormatException">Thrown when the digest was already seen.</exception>
    private static void RecordDigest(string digest, HashSet<string> seenDigests)
    {
        if(!seenDigests.Add(digest))
        {
            throw new FormatException($"draft-ietf-spice-sd-cwt: the digest '{digest}' is encountered more than once.");
        }
    }


    private static void CollectPathsFromCbor(
        ReadOnlyMemory<byte> payload,
        CredentialPath currentPath,
        HashSet<CredentialPath> paths)
    {
        paths.Add(currentPath);

        var reader = new CborReader(payload.ToArray(), CborOptions.Lax);
        CollectPathsFromCborReader(reader, currentPath, paths);
    }


    private static void CollectPathsFromCborReader(
        CborReader reader,
        CredentialPath currentPath,
        HashSet<CredentialPath> paths)
    {
        CborReaderState state = reader.PeekState();

        if(state == CborReaderState.StartMap)
        {
            reader.ReadStartMap();

            while(reader.PeekState() != CborReaderState.EndMap)
            {
                object key = reader.PeekState() is CborReaderState.NegativeInteger or CborReaderState.UnsignedInteger
                    ? reader.ReadInt32()
                    : reader.ReadTextString();

                if(key is int intKey && (intKey == SdCwtConstants.SdClaimsHeaderKey || intKey == SdCwtConstants.SdAlgHeaderKey))
                {
                    reader.SkipValue();
                }
                else
                {
                    string keyName = key is int ik ? ik.ToString(CultureInfo.InvariantCulture) : (string)key;
                    CredentialPath childPath = currentPath.Append(keyName);
                    paths.Add(childPath);
                    CollectPathsFromCborReader(reader, childPath, paths);
                }
            }

            reader.ReadEndMap();
        }
        else if(state == CborReaderState.StartArray)
        {
            reader.ReadStartArray();
            int index = 0;

            while(reader.PeekState() != CborReaderState.EndArray)
            {
                CredentialPath childPath = currentPath.Append(index);
                paths.Add(childPath);
                CollectPathsFromCborReader(reader, childPath, paths);
                index++;
            }

            reader.ReadEndArray();
        }
        else
        {
            reader.SkipValue();
        }
    }


    private static void CollectMandatoryPathsFromCbor(
        ReadOnlyMemory<byte> payload,
        CredentialPath currentPath,
        HashSet<CredentialPath> mandatory)
    {
        mandatory.Add(currentPath);

        var reader = new CborReader(payload.ToArray(), CborOptions.Lax);
        CollectMandatoryPathsFromCborReader(reader, currentPath, mandatory);
    }


    private static void CollectMandatoryPathsFromCborReader(
        CborReader reader,
        CredentialPath currentPath,
        HashSet<CredentialPath> mandatory)
    {
        CborReaderState state = reader.PeekState();

        if(state == CborReaderState.StartMap)
        {
            reader.ReadStartMap();

            while(reader.PeekState() != CborReaderState.EndMap)
            {
                object key = reader.PeekState() is CborReaderState.NegativeInteger or CborReaderState.UnsignedInteger
                    ? reader.ReadInt32()
                    : reader.ReadTextString();

                //Skip SD-related keys.
                if(key is int intKey && (intKey == SdCwtConstants.SdClaimsHeaderKey || intKey == SdCwtConstants.SdAlgHeaderKey))
                {
                    reader.SkipValue();
                }
                else
                {
                    string keyName = key is int ik ? ik.ToString(CultureInfo.InvariantCulture) : (string)key;
                    CredentialPath childPath = currentPath.Append(keyName);
                    mandatory.Add(childPath);
                    CollectMandatoryPathsFromCborReader(reader, childPath, mandatory);
                }
            }

            reader.ReadEndMap();
        }
        else if(state == CborReaderState.StartArray)
        {
            reader.ReadStartArray();
            int index = 0;

            while(reader.PeekState() != CborReaderState.EndArray)
            {
                CredentialPath childPath = currentPath.Append(index);
                mandatory.Add(childPath);
                CollectMandatoryPathsFromCborReader(reader, childPath, mandatory);
                index++;
            }

            reader.ReadEndArray();
        }
        else
        {
            reader.SkipValue();
        }
    }
}
