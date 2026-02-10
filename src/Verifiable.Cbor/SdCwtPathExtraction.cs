using System.Buffers;
using System.Formats.Cbor;
using System.Globalization;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose.Sd;

namespace Verifiable.Cbor;

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
        MemoryPool<byte> pool,
        string hashAlgorithm = "sha-256")
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);

        //Build a map from Base64Url-encoded digest to disclosure.
        //We use Base64Url encoding as the common comparison format.
        var digestToDisclosure = new Dictionary<string, SdDisclosure>(StringComparer.Ordinal);

        foreach(SdDisclosure disclosure in message.Disclosures)
        {
            byte[] disclosureCbor = SdCwtSerializer.SerializeDisclosure(disclosure);
            byte[] digestBytes = SdCwtSerializer.ComputeDisclosureDigest(disclosureCbor, hashAlgorithm);
            string digestBase64 = encoder(digestBytes);
            digestToDisclosure[digestBase64] = disclosure;
        }

        var result = new Dictionary<SdDisclosure, CredentialPath>();
        ExtractPathsFromCbor(message.Payload, CredentialPath.Root, digestToDisclosure, result, encoder);

        return result;
    }


    /// <summary>
    /// Extracts all paths from an SD-CWT payload (both disclosed and redacted).
    /// </summary>
    /// <param name="message">The SD-CWT message.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>All paths present in the credential structure.</returns>
    public static IReadOnlySet<CredentialPath> ExtractAllPaths(
        SdCwtMessage message,
        MemoryPool<byte> pool)
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
        MemoryPool<byte> pool)
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
        MemoryPool<byte> pool,
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


    private static void ExtractPathsFromCbor(
        ReadOnlyMemory<byte> payload,
        CredentialPath currentPath,
        Dictionary<string, SdDisclosure> digestToDisclosure,
        Dictionary<SdDisclosure, CredentialPath> result,
        EncodeDelegate encoder)
    {
        var reader = new CborReader(payload.ToArray(), CborConformanceMode.Lax);
        ExtractPathsFromCborReader(reader, currentPath, digestToDisclosure, result, encoder);
    }


    private static void ExtractPathsFromCborReader(
        CborReader reader,
        CredentialPath currentPath,
        Dictionary<string, SdDisclosure> digestToDisclosure,
        Dictionary<SdDisclosure, CredentialPath> result,
        EncodeDelegate encoder)
    {
        CborReaderState state = reader.PeekState();

        if(state == CborReaderState.StartMap)
        {
            int? mapLength = reader.ReadStartMap();
            var sdDigests = new List<string>();

            //First pass: collect SD digests and process other keys.
            var entries = new List<(object key, CborReaderState valueState, int startOffset)>();

            while(reader.PeekState() != CborReaderState.EndMap)
            {
                //Read key (could be int or string in CWT).
                object key;
                if(reader.PeekState() == CborReaderState.NegativeInteger || reader.PeekState() == CborReaderState.UnsignedInteger)
                {
                    key = reader.ReadInt32();
                }
                else
                {
                    key = reader.ReadTextString();
                }

                //Check if this is the SD digest array.
                if(key is int intKey && intKey == SdCwtConstants.SdClaimsHeaderKey)
                {
                    if(reader.PeekState() == CborReaderState.StartArray)
                    {
                        int? arrayLength = reader.ReadStartArray();
                        while(reader.PeekState() != CborReaderState.EndArray)
                        {
                            CborReaderState digestState = reader.PeekState();
                            if(digestState == CborReaderState.TextString)
                            {
                                //Digest stored as text string (Base64Url encoded).
                                sdDigests.Add(reader.ReadTextString());
                            }
                            else if(digestState == CborReaderState.ByteString)
                            {
                                //Digest stored as byte string - encode to Base64Url for comparison.
                                byte[] digestBytes = reader.ReadByteString();
                                sdDigests.Add(encoder(digestBytes));
                            }
                            else
                            {
                                reader.SkipValue();
                            }
                        }
                        reader.ReadEndArray();
                    }
                    else
                    {
                        reader.SkipValue();
                    }
                }
                else if(key is int algoKey && algoKey == SdCwtConstants.SdAlgHeaderKey)
                {
                    //Skip the algorithm claim.
                    reader.SkipValue();
                }
                else
                {
                    //Recurse into child.
                    string keyName = key is int ik ? ik.ToString(CultureInfo.InvariantCulture) : (string)key;
                    CredentialPath childPath = currentPath.Append(keyName);
                    ExtractPathsFromCborReader(reader, childPath, digestToDisclosure, result, encoder);
                }
            }

            reader.ReadEndMap();

            //Process collected SD digests.
            foreach(string digest in sdDigests)
            {
                if(digestToDisclosure.TryGetValue(digest, out SdDisclosure? disclosure))
                {
                    if(disclosure.ClaimName != null)
                    {
                        CredentialPath disclosurePath = currentPath.Append(disclosure.ClaimName);
                        result[disclosure] = disclosurePath;
                    }
                }
            }
        }
        else if(state == CborReaderState.StartArray)
        {
            int? arrayLength = reader.ReadStartArray();
            int index = 0;

            while(reader.PeekState() != CborReaderState.EndArray)
            {
                CredentialPath childPath = currentPath.Append(index);
                ExtractPathsFromCborReader(reader, childPath, digestToDisclosure, result, encoder);
                index++;
            }

            reader.ReadEndArray();
        }
        else
        {
            reader.SkipValue();
        }
    }


    private static void CollectPathsFromCbor(
        ReadOnlyMemory<byte> payload,
        CredentialPath currentPath,
        HashSet<CredentialPath> paths)
    {
        paths.Add(currentPath);

        var reader = new CborReader(payload.ToArray(), CborConformanceMode.Lax);
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
            int? mapLength = reader.ReadStartMap();

            while(reader.PeekState() != CborReaderState.EndMap)
            {
                object key;
                if(reader.PeekState() == CborReaderState.NegativeInteger || reader.PeekState() == CborReaderState.UnsignedInteger)
                {
                    key = reader.ReadInt32();
                }
                else
                {
                    key = reader.ReadTextString();
                }

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
            int? arrayLength = reader.ReadStartArray();
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

        var reader = new CborReader(payload.ToArray(), CborConformanceMode.Lax);
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
            int? mapLength = reader.ReadStartMap();

            while(reader.PeekState() != CborReaderState.EndMap)
            {
                object key;
                if(reader.PeekState() == CborReaderState.NegativeInteger || reader.PeekState() == CborReaderState.UnsignedInteger)
                {
                    key = reader.ReadInt32();
                }
                else
                {
                    key = reader.ReadTextString();
                }

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
            int? arrayLength = reader.ReadStartArray();
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