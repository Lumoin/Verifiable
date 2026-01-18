using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Delegate for extracting credential paths from disclosure structures.
/// </summary>
/// <typeparam name="TDisclosure">The type of disclosure (e.g., SdDisclosure for SD-JWT/SD-CWT).</typeparam>
/// <param name="payload">The credential payload bytes (JSON or CBOR).</param>
/// <param name="disclosures">The list of disclosures to map to paths.</param>
/// <param name="encoder">Delegate for encoding (used for digest computation).</param>
/// <param name="pool">Memory pool for allocations.</param>
/// <returns>A dictionary mapping each disclosure to its credential path.</returns>
/// <remarks>
/// <para>
/// This delegate abstracts the format-specific logic for extracting paths from
/// credential payloads. Implementations exist in format-specific libraries:
/// </para>
/// <list type="bullet">
/// <item><description>Verifiable.Json provides JSON/SD-JWT implementation.</description></item>
/// <item><description>Verifiable.Cbor provides CBOR/SD-CWT implementation.</description></item>
/// </list>
/// </remarks>
public delegate IReadOnlyDictionary<TDisclosure, CredentialPath> ExtractDisclosurePathsDelegate<TDisclosure>(
    ReadOnlySpan<byte> payload,
    IReadOnlyList<TDisclosure> disclosures,
    EncodeDelegate encoder,
    MemoryPool<byte> pool);


/// <summary>
/// Delegate for computing disclosure digests.
/// </summary>
/// <param name="encodedDisclosure">The encoded disclosure string.</param>
/// <param name="encoder">Delegate for encoding the hash result.</param>
/// <returns>The computed digest as a string.</returns>
/// <remarks>
/// <para>
/// The digest computation typically involves:
/// </para>
/// <list type="number">
/// <item><description>Converting the encoded disclosure to ASCII bytes.</description></item>
/// <item><description>Hashing with the specified algorithm (e.g., SHA-256).</description></item>
/// <item><description>Encoding the hash using Base64Url.</description></item>
/// </list>
/// </remarks>
public delegate string ComputeDisclosureDigestDelegate(
    string encodedDisclosure,
    EncodeDelegate encoder);


/// <summary>
/// Delegate for serializing a disclosure to its encoded form.
/// </summary>
/// <typeparam name="TDisclosure">The type of disclosure.</typeparam>
/// <param name="disclosure">The disclosure to serialize.</param>
/// <param name="encoder">Delegate for Base64Url encoding.</param>
/// <returns>The encoded disclosure string.</returns>
public delegate string SerializeDisclosureDelegate<TDisclosure>(
    TDisclosure disclosure,
    EncodeDelegate encoder);