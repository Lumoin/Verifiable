using System.Buffers;
using System.Security.Cryptography;

namespace Verifiable.JCose.Sd;

/// <summary>
/// Delegate definitions for selective disclosure serialization operations.
/// </summary>
/// <remarks>
/// <para>
/// These delegates define the contract for format-specific serialization.
/// Implementations live in Verifiable.Json (for SD-JWT) and Verifiable.Cbor (for SD-CWT).
/// </para>
/// <code>
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    Serialization Architecture                           │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                         │
/// │  Verifiable.JCose          Verifiable.Json       Verifiable.Cbor        │
/// │  ┌─────────────────┐       ┌─────────────────┐   ┌─────────────────┐    │
/// │  │ Delegate        │       │ JSON            │   │ CBOR            │    │
/// │  │ Definitions     │◄──────│ Implementations │   │ Implementations │    │
/// │  │                 │       │                 │   │                 │    │
/// │  │ SdDisclosure    │       │ SdJwtSerializer │   │ SdCwtSerializer │    │
/// │  │ SdToken&lt;T&gt;      │       │                 │   │                 │    │
/// │  └─────────────────┘       └─────────────────┘   └─────────────────┘    │
/// │                                                                         │
/// └─────────────────────────────────────────────────────────────────────────┘
/// </code>
/// </remarks>
public static class SdSerializerDelegates
{
    /// <summary>
    /// Serializes a disclosure to its encoded wire format.
    /// </summary>
    /// <typeparam name="TEncoded">
    /// The encoded type: <see cref="string"/> for SD-JWT (Base64Url),
    /// <see cref="ReadOnlyMemory{T}"/> of <see cref="byte"/> for SD-CWT (CBOR).
    /// </typeparam>
    /// <param name="disclosure">The disclosure to serialize.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>The encoded disclosure.</returns>
    /// <remarks>
    /// <para>
    /// For SD-JWT: Produces Base64Url-encoded JSON array <c>[salt, name?, value]</c>.
    /// </para>
    /// <para>
    /// For SD-CWT: Produces CBOR-encoded array.
    /// </para>
    /// </remarks>
    public delegate TEncoded SerializeDisclosureDelegate<TEncoded>(
        SdDisclosure disclosure,
        MemoryPool<byte> pool);


    /// <summary>
    /// Parses a disclosure from its encoded wire format.
    /// </summary>
    /// <typeparam name="TEncoded">The encoded type.</typeparam>
    /// <param name="encoded">The encoded disclosure.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>The parsed disclosure.</returns>
    public delegate SdDisclosure ParseDisclosureDelegate<TEncoded>(
        TEncoded encoded,
        MemoryPool<byte> pool);


    /// <summary>
    /// Computes the digest of an encoded disclosure.
    /// </summary>
    /// <typeparam name="TEncoded">The encoded type.</typeparam>
    /// <param name="encoded">The encoded disclosure.</param>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <param name="pool">Memory pool for output allocation.</param>
    /// <returns>The digest bytes.</returns>
    /// <remarks>
    /// <para>
    /// For SD-JWT: Hash is computed over ASCII bytes of the Base64Url string.
    /// </para>
    /// <para>
    /// For SD-CWT: Hash is computed over the CBOR-encoded bytes.
    /// </para>
    /// </remarks>
    public delegate IMemoryOwner<byte> ComputeDisclosureDigestDelegate<TEncoded>(
        TEncoded encoded,
        HashAlgorithmName algorithm,
        MemoryPool<byte> pool);


    /// <summary>
    /// Serializes a complete SD token to its wire format.
    /// </summary>
    /// <typeparam name="TEnvelope">The envelope type (string or bytes).</typeparam>
    /// <typeparam name="TWire">The wire format type.</typeparam>
    /// <param name="token">The token to serialize.</param>
    /// <param name="serializeDisclosure">Delegate to serialize individual disclosures.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>The serialized token.</returns>
    /// <remarks>
    /// <para>
    /// For SD-JWT: Produces <c>jwt~disclosure1~disclosure2~[kb-jwt]</c>.
    /// </para>
    /// <para>
    /// For SD-CWT: Produces CBOR structure with CWT and disclosures.
    /// </para>
    /// </remarks>
    public delegate TWire SerializeSdTokenDelegate<TEnvelope, TWire>(
        SdToken<TEnvelope> token,
        SerializeDisclosureDelegate<string> serializeDisclosure,
        MemoryPool<byte> pool)
        where TEnvelope : notnull;


    /// <summary>
    /// Parses a complete SD token from its wire format.
    /// </summary>
    /// <typeparam name="TEnvelope">The envelope type.</typeparam>
    /// <typeparam name="TWire">The wire format type.</typeparam>
    /// <param name="input">The wire format input.</param>
    /// <param name="parseDisclosure">Delegate to parse individual disclosures.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>The parsed token.</returns>
    public delegate SdToken<TEnvelope> ParseSdTokenDelegate<TEnvelope, TWire>(
        TWire input,
        ParseDisclosureDelegate<string> parseDisclosure,
        MemoryPool<byte> pool)
        where TEnvelope : notnull;


    /// <summary>
    /// Computes the SD hash for key binding validation.
    /// </summary>
    /// <typeparam name="TEnvelope">The envelope type.</typeparam>
    /// <param name="token">The token (without key binding portion).</param>
    /// <param name="serializeDisclosure">Delegate to serialize disclosures.</param>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>The SD hash bytes.</returns>
    /// <remarks>
    /// The SD hash is computed over the serialized token without the key binding,
    /// and is included in the key binding JWT/CWT payload.
    /// </remarks>
    public delegate IMemoryOwner<byte> ComputeSdHashDelegate<TEnvelope>(
        SdToken<TEnvelope> token,
        SerializeDisclosureDelegate<string> serializeDisclosure,
        HashAlgorithmName algorithm,
        MemoryPool<byte> pool)
        where TEnvelope : notnull;


    /// <summary>
    /// Generates cryptographic salt for a disclosure.
    /// </summary>
    /// <param name="pool">Memory pool for allocation.</param>
    /// <returns>Salt bytes (minimum 128 bits / 16 bytes).</returns>
    public delegate IMemoryOwner<byte> GenerateSaltDelegate(MemoryPool<byte> pool);
}