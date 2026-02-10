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
/// credential payloads (Layer 5 of the DCQL Disclosure Architecture). The path
/// extraction bridges between format-specific token structures and the
/// format-neutral <see cref="CredentialPath"/>-based lattice operations in
/// <see cref="DisclosureComputation{TCredential}"/> (Layer 3).
/// </para>
/// <para>
/// Implementations exist in format-specific libraries:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>Verifiable.Json</c>: <c>SdJwtPathExtraction.ExtractPaths</c> for SD-JWT tokens.
/// Walks JSON payloads, matches <c>_sd</c> digests to disclosures, and produces paths.
/// </description></item>
/// <item><description>
/// <c>Verifiable.Cbor</c>: Equivalent for SD-CWT tokens. Walks CBOR maps and produces paths.
/// </description></item>
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
/// <param name="algorithmName">The hash algorithm name in IANA format (e.g., <c>"sha-256"</c>).</param>
/// <param name="encoder">Delegate for encoding the hash result.</param>
/// <returns>The computed digest as a string.</returns>
/// <remarks>
/// <para>
/// This delegate is used in both issuance (computing digests for the <c>_sd</c> array)
/// and verification (recomputing digests to match against the signed payload). The
/// two-phase pipeline — serialize then digest — enables the verifier to reuse only
/// this delegate since it already has the encoded disclosure strings from the wire format.
/// </para>
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
    string algorithmName,
    EncodeDelegate encoder);


/// <summary>
/// Delegate for serializing a disclosure to its encoded form.
/// </summary>
/// <typeparam name="TDisclosure">The type of disclosure.</typeparam>
/// <param name="disclosure">The disclosure to serialize.</param>
/// <param name="encoder">Delegate for Base64Url encoding.</param>
/// <returns>The encoded disclosure string.</returns>
/// <remarks>
/// <para>
/// This is the first phase of the two-phase digest pipeline used during issuance.
/// The output of this delegate is passed to <see cref="ComputeDisclosureDigestDelegate"/>
/// to produce the digest that goes into the <c>_sd</c> array. Format-specific
/// implementations serialize the <c>[salt, name, value]</c> triple (for SD-JWT) or
/// the equivalent CBOR structure (for SD-CWT) into their Base64Url-encoded wire form.
/// </para>
/// </remarks>
public delegate string SerializeDisclosureDelegate<TDisclosure>(
    TDisclosure disclosure,
    EncodeDelegate encoder);