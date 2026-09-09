using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Json.Sd;

namespace Verifiable.Json;

/// <summary>
/// The result of walking an SD-JWT issuer-signed payload once: every disclosure's resolved
/// position, every unconditionally disclosed node's value, and every node that exists only
/// inside a resolved disclosure's own value.
/// </summary>
/// <param name="DisclosurePaths">Each disclosure's resolved path.</param>
/// <param name="IssuerSignedClaims">Every unconditionally disclosed node, keyed by its path.</param>
/// <param name="DisclosureInteriorClaims">Every node interior to a resolved disclosure, keyed by its path.</param>
internal readonly record struct SdJwtWalkResult(
    IReadOnlyDictionary<SdDisclosure, CredentialPath> DisclosurePaths,
    IReadOnlyDictionary<CredentialPath, object?> IssuerSignedClaims,
    IReadOnlyDictionary<CredentialPath, object?> DisclosureInteriorClaims);

/// <summary>
/// Provides JSON-specific path extraction for SD-JWT structures.
/// </summary>
/// <remarks>
/// <para>
/// This class implements the format-specific logic for extracting credential paths
/// from JSON payloads. It works with <see cref="SdDisclosure"/> and produces
/// <see cref="CredentialPath"/> instances that can be used with <see cref="PathLattice"/>.
/// </para>
/// <para>
/// For CBOR/SD-CWT path extraction, see the equivalent in Verifiable.Cbor.
/// </para>
/// </remarks>
public static class SdJwtPathExtraction
{
    /// <summary>
    /// The deepest chain of nested containers and recursive disclosures a payload may present
    /// before it is refused. <see cref="JsonDocument"/> bounds one document's own nesting at 64
    /// levels; a chain of recursive disclosures (RFC 9901 §4.2.6) is an attacker-chosen nesting
    /// that spans documents, so it is bounded at the same order here rather than left to the
    /// call stack.
    /// </summary>
    private const int MaximumWalkDepth = 64;


    /// <summary>
    /// Extracts credential paths for all disclosures in an SD-JWT token.
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="hashAlgorithm">The hash algorithm name (default: "sha-256").</param>
    /// <returns>A dictionary mapping each disclosure to its credential path.</returns>
    public static IReadOnlyDictionary<SdDisclosure, CredentialPath> ExtractPaths(
        SdToken<string> token,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        BaseMemoryPool pool,
        string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);

        var digestToDisclosure = new Dictionary<string, SdDisclosure>(StringComparer.Ordinal);

        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            string encoded = SdJwtSerializer.SerializeDisclosure(disclosure, encoder);
            string digest = ComputeDisclosureDigest(encoded, hashAlgorithm, encoder, pool);
            digestToDisclosure[digest] = disclosure;
        }

        SdJwtWalkResult result = Walk(token.IssuerSigned, digestToDisclosure, decoder, pool);

        return result.DisclosurePaths;
    }


    /// <summary>
    /// Walks an SD-JWT issuer-signed payload once, resolving every disclosure's digest to its
    /// position and collecting every node the payload carries — the core the parse
    /// (<see cref="SdJwtSerializer.ParseToken"/>) and the standalone <see cref="ExtractPaths"/>
    /// entry both run, so a payload is walked the same way regardless of which one is called.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Enforces the digest-resolution rules of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> §7.1 step 3.c (a
    /// resolved claim name must not be a mechanism key, must not collide with a name already at
    /// its level, and must match its context — an object-property disclosure resolved from an
    /// array marker, or vice versa, is rejected) and step 4 (no digest value repeats). These hold
    /// of the payload's own structure regardless of which disclosures the caller supplied, so
    /// both entry points enforce them alike.
    /// </para>
    /// <para>
    /// §7.1 step 3.b.i reads the <c>_sd</c> key's value as "an array of strings". An <c>_sd</c>
    /// whose value is anything else, or an array carrying a member that is not a string,
    /// identifies no digest at all: the whole array is passed over rather than the string members
    /// being picked out of it, so a payload cannot smuggle a resolution through a value the
    /// specification does not admit.
    /// </para>
    /// <para>
    /// The two claim maps are disjoint by construction. <paramref name="issuerSignedClaims"/> —
    /// the result's <see cref="SdJwtWalkResult.IssuerSignedClaims"/> — holds only nodes reachable
    /// without releasing any disclosure. A node that exists solely inside a resolved disclosure's
    /// own value goes to <see cref="SdJwtWalkResult.DisclosureInteriorClaims"/>, since reading it
    /// costs the release of the disclosure that carries it.
    /// </para>
    /// <para>
    /// Step 5 ("every Disclosure was referenced") is deliberately left to the caller:
    /// <see cref="SdJwtSerializer.ParseToken"/> enforces it because an unreferenced disclosure
    /// really did fail to parse, but a caller matching disclosures against a payload signed under
    /// a different digest algorithm than expected — the verification path's own digest-mismatch
    /// detection — legitimately produces disclosures with no match, and reports that on its own
    /// per-claim result rather than as a parse failure.
    /// </para>
    /// </remarks>
    /// <param name="issuerJwt">The compact issuer-signed JWS.</param>
    /// <param name="digestToDisclosure">Every disclosure's wire digest, computed by the caller.</param>
    /// <param name="decoder">Delegate for Base64Url decoding the JWS payload segment.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>Each disclosure's resolved path, every unconditionally disclosed node and every disclosure-interior node.</returns>
    /// <exception cref="FormatException">
    /// Thrown when the payload fails a step 3.c or 4 rule, or when its nesting exceeds
    /// <see cref="MaximumWalkDepth"/>.
    /// </exception>
    internal static SdJwtWalkResult Walk(
        string issuerJwt,
        IReadOnlyDictionary<string, SdDisclosure> digestToDisclosure,
        DecodeDelegate decoder,
        BaseMemoryPool pool)
    {
        JsonElement payload = ParseJwtPayload(issuerJwt, decoder, pool);
        object? payloadGraph = JsonElementConversion.Convert(payload);

        var disclosurePaths = new Dictionary<SdDisclosure, CredentialPath>(ReferenceEqualityComparer.Instance);
        var issuerSignedClaims = new Dictionary<CredentialPath, object?>();
        var interiorClaims = new Dictionary<CredentialPath, object?>();
        var seenDigests = new HashSet<string>(StringComparer.Ordinal);

        WalkAndClean(payloadGraph, CredentialPath.Root, digestToDisclosure, disclosurePaths, issuerSignedClaims, interiorClaims, seenDigests, depth: 0);

        return new SdJwtWalkResult(disclosurePaths, issuerSignedClaims, interiorClaims);
    }


    /// <summary>
    /// Recursively walks one node of the payload's CLR object graph (a <see cref="Dictionary{TKey,TValue}"/>
    /// of <see cref="string"/> to <see cref="object"/> for a JSON object, a <see cref="List{T}"/>
    /// of <see cref="object"/> for a JSON array, or a scalar), resolving digests to disclosures and
    /// recursing into a resolved disclosure's own <see cref="SdDisclosure.ClaimValue"/> so a
    /// recursive disclosure (RFC 9901 §4.2.6 — one disclosed field revealing further
    /// selectively-disclosable fields) resolves through its parent's path.
    /// </summary>
    /// <param name="node">The node being walked.</param>
    /// <param name="currentPath">The node's own path.</param>
    /// <param name="digestToDisclosure">Every disclosure's wire digest.</param>
    /// <param name="disclosurePaths">Accumulates each resolved disclosure's path.</param>
    /// <param name="claims">
    /// Accumulates this node's children: the unconditionally disclosed map while the walk is over
    /// the payload itself, the interior map once it has descended into a disclosure's own value.
    /// </param>
    /// <param name="interiorClaims">Accumulates every node interior to a resolved disclosure.</param>
    /// <param name="seenDigests">Every digest value encountered so far, for the step 4 check.</param>
    /// <param name="depth">How many containers and disclosure values this node sits below.</param>
    /// <returns>
    /// This node's value with the <c>_sd</c>/<c>_sd_alg</c> mechanism keys and the resolved or
    /// decoy array markers removed — what <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/>
    /// stores for a container node.
    /// </returns>
    /// <exception cref="FormatException">
    /// Thrown when a step 3.c or 4 rule is violated, or when the nesting exceeds
    /// <see cref="MaximumWalkDepth"/>.
    /// </exception>
    private static object? WalkAndClean(
        object? node,
        CredentialPath currentPath,
        IReadOnlyDictionary<string, SdDisclosure> digestToDisclosure,
        Dictionary<SdDisclosure, CredentialPath> disclosurePaths,
        Dictionary<CredentialPath, object?> claims,
        Dictionary<CredentialPath, object?> interiorClaims,
        HashSet<string> seenDigests,
        int depth)
    {
        if(depth > MaximumWalkDepth)
        {
            throw new FormatException(
                $"RFC 9901 §4.2.6: the payload's nesting of containers and recursive Disclosures exceeds the {MaximumWalkDepth} levels this parse admits.");
        }

        if(node is Dictionary<string, object> obj)
        {
            var localNames = new HashSet<string>(StringComparer.Ordinal);
            foreach(string key in obj.Keys)
            {
                if(key != SdConstants.SdClaimName && key != SdConstants.SdAlgorithmClaimName)
                {
                    localNames.Add(key);
                }
            }

            if(obj.TryGetValue(SdConstants.SdClaimName, out object? sdArrayObj)
                && sdArrayObj is List<object> sdArray
                && IsArrayOfStrings(sdArray))
            {
                foreach(object? digestObj in sdArray)
                {
                    string digest = (string)digestObj!;

                    RecordDigest(digest, seenDigests);

                    //Step 3.c.i: a digest with no matching Disclosure is a decoy and is ignored.
                    if(!digestToDisclosure.TryGetValue(digest, out SdDisclosure? disclosure))
                    {
                        continue;
                    }

                    //Step 3.c.ii.1: a digest found in an object's _sd key must resolve to a
                    //three-element (object-property) Disclosure.
                    if(disclosure.ClaimName is not { } claimName)
                    {
                        throw new FormatException(
                            "RFC 9901 §7.1 step 3.c.ii.1: a digest in an object's _sd array resolved to an array-element Disclosure.");
                    }

                    //Step 3.c.ii.2: the claim name must not be a mechanism key.
                    if(SdConstants.IsReservedClaimName(claimName))
                    {
                        throw new FormatException(
                            $"RFC 9901 §7.1 step 3.c.ii.2: the claim name '{claimName}' is a reserved mechanism key.");
                    }

                    //Step 3.c.ii.3: the claim name must not already exist at this level.
                    if(!localNames.Add(claimName))
                    {
                        throw new FormatException(
                            $"RFC 9901 §7.1 step 3.c.ii.3: the claim name '{claimName}' already exists at this level.");
                    }

                    CredentialPath disclosurePath = currentPath.Append(claimName);
                    disclosurePaths[disclosure] = disclosurePath;

                    //Step 3.c.ii.5: recursively process the Disclosure's own value. Everything it
                    //carries is interior to it — reading any of it costs this Disclosure's release.
                    WalkAndClean(disclosure.ClaimValue, disclosurePath, digestToDisclosure, disclosurePaths, interiorClaims, interiorClaims, seenDigests, depth + 1);
                }
            }

            var cleaned = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach(KeyValuePair<string, object> property in obj)
            {
                if(property.Key == SdConstants.SdClaimName || property.Key == SdConstants.SdAlgorithmClaimName)
                {
                    continue;
                }

                CredentialPath childPath = currentPath.Append(property.Key);
                object? cleanedChild = WalkAndClean(property.Value, childPath, digestToDisclosure, disclosurePaths, claims, interiorClaims, seenDigests, depth + 1);
                claims[childPath] = cleanedChild;
                cleaned[property.Key] = cleanedChild;
            }

            return cleaned;
        }

        if(node is List<object> array)
        {
            var cleaned = new List<object?>();
            int index = 0;

            foreach(object? item in array)
            {
                if(item is Dictionary<string, object> marker
                    && marker.Count == 1
                    && marker.TryGetValue(SdConstants.ArrayDigestKey, out object? digestValue)
                    && digestValue is string digest)
                {
                    RecordDigest(digest, seenDigests);

                    //Step 3.c.i: a digest with no matching Disclosure is a decoy; step (d) removes
                    //it from the visible structure, but its position still counts toward the index.
                    if(digestToDisclosure.TryGetValue(digest, out SdDisclosure? disclosure))
                    {
                        //Step 3.c.iii.1: a digest found in an array element must resolve to a
                        //two-element (array-element) Disclosure.
                        if(disclosure.ClaimName is not null)
                        {
                            throw new FormatException(
                                "RFC 9901 §7.1 step 3.c.iii.1: a digest in an array resolved to an object-property Disclosure.");
                        }

                        CredentialPath elementPath = currentPath.Append(index);
                        disclosurePaths[disclosure] = elementPath;

                        //Step 3.c.iii.3: recursively process the Disclosure's own value, whose
                        //nodes are interior to it.
                        WalkAndClean(disclosure.ClaimValue, elementPath, digestToDisclosure, disclosurePaths, interiorClaims, interiorClaims, seenDigests, depth + 1);
                    }

                    index++;
                    continue;
                }

                CredentialPath itemPath = currentPath.Append(index);
                object? cleanedItem = WalkAndClean(item, itemPath, digestToDisclosure, disclosurePaths, claims, interiorClaims, seenDigests, depth + 1);
                claims[itemPath] = cleanedItem;
                cleaned.Add(cleanedItem);
                index++;
            }

            return cleaned;
        }

        return node;
    }


    /// <summary>
    /// Whether every member of an <c>_sd</c> value is a string, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> §7.1 step 3.b.i requires
    /// of the key's value ("an array of strings"). A single non-string member makes the whole
    /// value inadmissible, so none of its members identifies a digest.
    /// </summary>
    /// <param name="sdArray">The <c>_sd</c> key's array value.</param>
    private static bool IsArrayOfStrings(List<object> sdArray)
    {
        foreach(object? member in sdArray)
        {
            if(member is not string)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Records a digest value for the step 4 duplicate check, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> §7.1 step 4: "If any
    /// digest value is encountered more than once in the Issuer-signed JWT payload (directly or
    /// recursively via other Disclosures), the SD-JWT MUST be rejected."
    /// </summary>
    /// <param name="digest">The digest value encountered.</param>
    /// <param name="seenDigests">Every digest value encountered so far.</param>
    /// <exception cref="FormatException">Thrown when the digest was already seen.</exception>
    private static void RecordDigest(string digest, HashSet<string> seenDigests)
    {
        if(!seenDigests.Add(digest))
        {
            throw new FormatException($"RFC 9901 §7.1 step 4: the digest '{digest}' is encountered more than once.");
        }
    }


    /// <summary>
    /// Extracts all paths from an SD-JWT payload (both disclosed and redacted).
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>All paths present in the credential structure.</returns>
    public static IReadOnlySet<CredentialPath> ExtractAllPaths(
        SdToken<string> token,
        DecodeDelegate decoder,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        JsonElement payload = ParseJwtPayload(token.IssuerSigned, decoder, pool);

        var paths = new HashSet<CredentialPath>();
        CollectPathsRecursive(payload, CredentialPath.Root, paths);

        return paths;
    }


    /// <summary>
    /// Extracts mandatory paths from an SD-JWT payload (non-redacted claims).
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>Paths that are always disclosed (not redacted).</returns>
    public static IReadOnlySet<CredentialPath> ExtractMandatoryPaths(
        SdToken<string> token,
        DecodeDelegate decoder,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        JsonElement payload = ParseJwtPayload(token.IssuerSigned, decoder, pool);

        var mandatory = new HashSet<CredentialPath>();
        CollectMandatoryPathsRecursive(payload, CredentialPath.Root, mandatory);

        return mandatory;
    }


    /// <summary>
    /// Creates a <see cref="PathLattice"/> from an SD-JWT token.
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="hashAlgorithm">The hash algorithm name.</param>
    /// <returns>A <see cref="PathLattice"/> configured for this token.</returns>
    public static PathLattice CreateLattice(
        SdToken<string> token,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        BaseMemoryPool pool,
        string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana)
    {
        ArgumentNullException.ThrowIfNull(token);

        IReadOnlySet<CredentialPath> allPaths = ExtractAllPaths(token, decoder, pool);
        IReadOnlySet<CredentialPath> mandatoryPaths = ExtractMandatoryPaths(token, decoder, pool);

        var allPathsWithDisclosures = new HashSet<CredentialPath>(allPaths);
        IReadOnlyDictionary<SdDisclosure, CredentialPath> disclosurePaths =
            ExtractPaths(token, decoder, encoder, pool, hashAlgorithm);

        foreach(CredentialPath path in disclosurePaths.Values)
        {
            allPathsWithDisclosures.Add(path);
        }

        return new PathLattice(allPathsWithDisclosures, mandatoryPaths);
    }


    /// <summary>
    /// Computes the digest of an encoded disclosure.
    /// </summary>
    /// <param name="encodedDisclosure">The Base64Url-encoded disclosure.</param>
    /// <param name="algorithmName">The hash algorithm name (e.g., "sha-256").</param>
    /// <param name="encoder">Delegate for Base64Url encoding the hash result.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <returns>The Base64Url-encoded digest.</returns>
    public static string ComputeDisclosureDigest(
        string encodedDisclosure,
        string algorithmName,
        EncodeDelegate encoder,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(encodedDisclosure);
        ArgumentNullException.ThrowIfNull(algorithmName);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);
        byte[] disclosureBytes = Encoding.ASCII.GetBytes(encodedDisclosure);
        byte[] hashBytes = ComputeHash(disclosureBytes, algorithmName, pool);
        return encoder(hashBytes);
    }


    private static byte[] ComputeHash(byte[] data, string algorithmName, BaseMemoryPool pool)
    {
        //Route through the registered ComputeDigestDelegate so disclosure digests
        //pick up observability and CBOM provenance stamping. The byte[] return is
        //preserved to keep the public ComputeDisclosureDigest API stable; the
        //~32-64 byte allocation per call is negligible against the SD-JWT path.
        HashAlgorithmName algorithm = WellKnownHashAlgorithms.ToHashAlgorithmName(algorithmName);
        (int outputLength, Tag tag, string? hashQualifier) = algorithm.Name switch
        {
            WellKnownHashAlgorithms.Sha256 => (32, CryptoTags.Sha256Digest, null),
            WellKnownHashAlgorithms.Sha384 => (48, CryptoTags.Sha384Digest, nameof(HashAlgorithmName.SHA384)),
            WellKnownHashAlgorithms.Sha512 => (64, CryptoTags.Sha512Digest, nameof(HashAlgorithmName.SHA512)),
            _ => throw new ArgumentException($"Unsupported hash algorithm: '{algorithmName}'.", nameof(algorithmName))
        };

        //An SD-JWT disclosure digest is a hash of a local disclosure string — sync by nature, no hardware-async
        //backend — so it hashes through the registered synchronous HashFunctionDelegate seam. The digest is
        //algorithm-agile (_sd_alg), so a non-SHA-256 request selects the seam by qualifier.
        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(
            data, outputLength, tag, pool, hashQualifier);
        return digest.AsReadOnlySpan().ToArray();
    }

    private static JsonElement ParseJwtPayload(string jwt, DecodeDelegate decoder, BaseMemoryPool pool)
    {
        string[] parts = jwt.Split('.');

        if(parts.Length != 3)
        {
            throw new FormatException("Invalid JWT structure.");
        }

        using IMemoryOwner<byte> payloadBytes = decoder(parts[1], pool);
        using JsonDocument doc = JsonDocument.Parse(payloadBytes.Memory);

        return doc.RootElement.Clone();
    }


    private static void CollectPathsRecursive(
        JsonElement element,
        CredentialPath currentPath,
        HashSet<CredentialPath> paths)
    {
        paths.Add(currentPath);

        if(element.ValueKind == JsonValueKind.Object)
        {
            foreach(JsonProperty prop in element.EnumerateObject())
            {
                if(prop.Name == SdConstants.SdClaimName || prop.Name == SdConstants.SdAlgorithmClaimName)
                {
                    continue;
                }

                CredentialPath childPath = currentPath.Append(prop.Name);
                CollectPathsRecursive(prop.Value, childPath, paths);
            }
        }
        else if(element.ValueKind == JsonValueKind.Array)
        {
            int index = 0;

            foreach(JsonElement item in element.EnumerateArray())
            {
                if(item.ValueKind == JsonValueKind.Object &&
                    item.TryGetProperty(SdConstants.ArrayDigestKey, out _))
                {
                    paths.Add(currentPath.Append(index));
                }
                else
                {
                    CredentialPath childPath = currentPath.Append(index);
                    CollectPathsRecursive(item, childPath, paths);
                }

                index++;
            }
        }
    }


    private static void CollectMandatoryPathsRecursive(
        JsonElement element,
        CredentialPath currentPath,
        HashSet<CredentialPath> mandatory)
    {
        mandatory.Add(currentPath);

        if(element.ValueKind == JsonValueKind.Object)
        {
            foreach(JsonProperty prop in element.EnumerateObject())
            {
                if(prop.Name == SdConstants.SdClaimName || prop.Name == SdConstants.SdAlgorithmClaimName)
                {
                    continue;
                }

                CredentialPath childPath = currentPath.Append(prop.Name);
                CollectMandatoryPathsRecursive(prop.Value, childPath, mandatory);
            }
        }
        else if(element.ValueKind == JsonValueKind.Array)
        {
            int index = 0;

            foreach(JsonElement item in element.EnumerateArray())
            {
                if(item.ValueKind == JsonValueKind.Object &&
                    item.TryGetProperty(SdConstants.ArrayDigestKey, out _))
                {
                    index++;
                    continue;
                }

                CredentialPath childPath = currentPath.Append(index);
                CollectMandatoryPathsRecursive(item, childPath, mandatory);
                index++;
            }
        }
    }
}
