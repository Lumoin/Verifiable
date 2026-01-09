using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Disclosure;
using Verifiable.Cryptography;
using Verifiable.JCose.Sd;
using Verifiable.Json.Sd;

namespace Verifiable.Tests.Utilities;

/// <summary>
/// Extracts credential paths from SD-JWT structures by analyzing digest placement.
/// </summary>
/// <remarks>
/// <para>
/// This is a diagnostic utility for inspecting SD-JWT structure. Not needed for
/// normal issuance, presentation, or verification flows.
/// </para>
/// </remarks>
public static class SdJwtPathExtractor
{
    /// <summary>
    /// Extracts paths for all disclosures in an SD-JWT token.
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="hashAlgorithm">The hash algorithm (default: sha-256).</param>
    /// <returns>A dictionary mapping disclosures to their paths.</returns>
    public static IReadOnlyDictionary<SdDisclosure, CredentialPath> ExtractPaths(
        SdJwtToken token,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        MemoryPool<byte> pool,
        string hashAlgorithm = SdConstants.DefaultHashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);

        JsonElement payload = ParseJwtPayload(token.IssuerSigned, decoder, pool);

        var digestToDisclosure = new Dictionary<string, SdDisclosure>(StringComparer.Ordinal);

        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            string encoded = SdJwtSerializer.SerializeDisclosure(disclosure, encoder);
            string digest = ComputeDisclosureDigest(encoded, hashAlgorithm, encoder);
            digestToDisclosure[digest] = disclosure;
        }

        var result = new Dictionary<SdDisclosure, CredentialPath>();
        ExtractPathsRecursive(payload, CredentialPath.Root, digestToDisclosure, result);

        return result;
    }


    /// <summary>
    /// Extracts all paths from an SD-JWT payload (both disclosed and redacted).
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>All paths present in the credential structure.</returns>
    public static IReadOnlySet<CredentialPath> ExtractAllPaths(
        SdJwtToken token,
        DecodeDelegate decoder,
        MemoryPool<byte> pool)
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
        SdJwtToken token,
        DecodeDelegate decoder,
        MemoryPool<byte> pool)
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
    /// Creates a PathLattice from an SD-JWT token.
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <returns>A PathLattice configured for this token.</returns>
    public static PathLattice CreateLattice(
        SdJwtToken token,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        MemoryPool<byte> pool,
        string hashAlgorithm = SdConstants.DefaultHashAlgorithm)
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


    private static string ComputeDisclosureDigest(string encodedDisclosure, string algorithm, EncodeDelegate encoder)
    {
        byte[] disclosureBytes = Encoding.ASCII.GetBytes(encodedDisclosure);
        byte[] hashBytes = ComputeHash(disclosureBytes, algorithm);
        return encoder(hashBytes);
    }


    private static byte[] ComputeHash(byte[] data, string algorithmName)
    {
        return algorithmName.ToLowerInvariant() switch
        {
            "sha-256" => SHA256.HashData(data),
            "sha-384" => SHA384.HashData(data),
            "sha-512" => SHA512.HashData(data),
            _ => throw new ArgumentException($"Unsupported hash algorithm: {algorithmName}", nameof(algorithmName))
        };
    }


    private static JsonElement ParseJwtPayload(string jwt, DecodeDelegate decoder, MemoryPool<byte> pool)
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


    private static void ExtractPathsRecursive(
        JsonElement element,
        CredentialPath currentPath,
        Dictionary<string, SdDisclosure> digestToDisclosure,
        Dictionary<SdDisclosure, CredentialPath> result)
    {
        if(element.ValueKind == JsonValueKind.Object)
        {
            if(element.TryGetProperty(SdConstants.SdClaimName, out JsonElement sdArray) &&
                sdArray.ValueKind == JsonValueKind.Array)
            {
                foreach(JsonElement digestElement in sdArray.EnumerateArray())
                {
                    string? digest = digestElement.GetString();

                    if(digest is not null && digestToDisclosure.TryGetValue(digest, out SdDisclosure? disclosure))
                    {
                        if(disclosure.ClaimName is not null)
                        {
                            CredentialPath disclosurePath = currentPath.Append(disclosure.ClaimName);
                            result[disclosure] = disclosurePath;
                        }
                    }
                }
            }

            foreach(JsonProperty prop in element.EnumerateObject())
            {
                if(prop.Name == SdConstants.SdClaimName || prop.Name == SdConstants.SdAlgorithmClaimName)
                {
                    continue;
                }

                CredentialPath childPath = currentPath.Append(prop.Name);
                ExtractPathsRecursive(prop.Value, childPath, digestToDisclosure, result);
            }
        }
        else if(element.ValueKind == JsonValueKind.Array)
        {
            int index = 0;

            foreach(JsonElement item in element.EnumerateArray())
            {
                if(item.ValueKind == JsonValueKind.Object &&
                    item.TryGetProperty(SdConstants.ArrayDigestKey, out JsonElement digestElement))
                {
                    string? digest = digestElement.GetString();

                    if(digest is not null && digestToDisclosure.TryGetValue(digest, out SdDisclosure? disclosure))
                    {
                        CredentialPath arrayElementPath = currentPath.Append(index);
                        result[disclosure] = arrayElementPath;
                    }
                }
                else
                {
                    CredentialPath childPath = currentPath.Append(index);
                    ExtractPathsRecursive(item, childPath, digestToDisclosure, result);
                }

                index++;
            }
        }
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