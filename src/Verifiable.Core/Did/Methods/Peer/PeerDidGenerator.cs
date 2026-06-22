using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Did.Methods.Peer;

/// <summary>
/// Serializes a <see cref="DidDocument"/> (the <c>did:peer:4</c> input document) into its UTF-8 JSON
/// bytes. Supplied by the JSON layer because <see cref="Verifiable.Core"/> takes no JSON-serializer
/// dependency — full DID-document serialization is the <c>Verifiable.Json</c> leaf's responsibility,
/// reached through this seam (the generation counterpart of the resolution-side deserializer).
/// </summary>
/// <param name="document">The input document to serialize, with relative ids and no root id.</param>
/// <returns>The compact (whitespace-free) JSON representation of the document.</returns>
public delegate string PeerDidDocumentSerializer(DidDocument document);

/// <summary>
/// The verification relationship a <c>did:peer:2</c> key element grants, mapped to its purpose code
/// (V/A/E/I/D) during generation.
/// </summary>
public enum PeerDidPurpose
{
    /// <summary>Authentication (purpose code V).</summary>
    Authentication,

    /// <summary>Assertion method (purpose code A).</summary>
    AssertionMethod,

    /// <summary>Key agreement (purpose code E).</summary>
    KeyAgreement,

    /// <summary>Capability invocation (purpose code I).</summary>
    CapabilityInvocation,

    /// <summary>Capability delegation (purpose code D).</summary>
    CapabilityDelegation
}

/// <summary>
/// A public key together with the single verification relationship it is granted in a generated
/// <c>did:peer:2</c> identifier. A key needed in more than one relationship is supplied once per
/// relationship, producing one key element each.
/// </summary>
/// <param name="Key">The public key material, carrying its algorithm in its tag.</param>
/// <param name="Purpose">The verification relationship the key is granted.</param>
public sealed record PeerDidPurposedKey(PublicKeyMemory Key, PeerDidPurpose Purpose);

/// <summary>
/// Generates <c>did:peer</c> identifiers, the inverse of the resolution performed by
/// <see cref="Verifiable.Core.Did.Methods.Peer.PeerDidResolver"/>. This is the document-to-DID construction
/// side, sitting alongside the other DID generators (for example <see cref="KeyDidBuilder"/>).
/// </summary>
public static class PeerDidGenerator
{
    private const int Sha256DigestLength = 32;

    /// <summary>
    /// Generates a <c>did:peer:4</c> long-form identifier from an input document per the
    /// <see href="https://identity.foundation/peer-did-4/">did:peer:4 specification</see>: the document
    /// is JSON-serialized, multibase-base58btc-encoded behind the json multicodec, and a SHA2-256
    /// multihash over that encoded string is prefixed to produce the self-certifying long form.
    /// </summary>
    /// <param name="inputDocument">
    /// The input document. Per the specification it MUST NOT carry a root <c>id</c> and MUST use relative
    /// references; the value is filled in when the DID is later resolved.
    /// </param>
    /// <param name="documentSerializer">Serializes the document to compact JSON (the JSON layer).</param>
    /// <param name="hashFunction">
    /// The hash function for the embedded multihash, which the specification fixes to SHA-256.
    /// </param>
    /// <param name="pool">Memory pool for the transient encode buffers.</param>
    /// <returns>The long-form <c>did:peer:4</c> identifier.</returns>
    public static string GenerateNumalgo4(
        DidDocument inputDocument,
        PeerDidDocumentSerializer documentSerializer,
        HashFunctionDelegate hashFunction,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(inputDocument);
        ArgumentNullException.ThrowIfNull(documentSerializer);
        ArgumentNullException.ThrowIfNull(hashFunction);
        ArgumentNullException.ThrowIfNull(pool);

        EncodeDelegate base58Encoder = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase));

        //Encoded document = multibase-base58btc( json multicodec || utf8(serialized document) ).
        string json = documentSerializer(inputDocument);
        string encodedDocument;
        int jsonByteCount = Encoding.UTF8.GetByteCount(json);
        using(IMemoryOwner<byte> jsonBytes = pool.Rent(jsonByteCount))
        {
            Span<byte> jsonSpan = jsonBytes.Memory.Span[..jsonByteCount];
            Encoding.UTF8.GetBytes(json, jsonSpan);
            encodedDocument = MultibaseSerializer.Encode(jsonSpan, MulticodecHeaders.Json, MultibaseAlgorithms.Base58Btc, base58Encoder, pool);
        }

        //Hash = multibase-base58btc( sha2-256 multihash || hash(utf8(encoded document string)) ).
        Span<byte> digest = stackalloc byte[Sha256DigestLength];
        int encodedByteCount = Encoding.UTF8.GetByteCount(encodedDocument);
        using(IMemoryOwner<byte> encodedBytes = pool.Rent(encodedByteCount))
        {
            Span<byte> encodedSpan = encodedBytes.Memory.Span[..encodedByteCount];
            Encoding.UTF8.GetBytes(encodedDocument, encodedSpan);
            hashFunction(encodedSpan, digest);
        }

        ReadOnlySpan<byte> sha256Code = MultihashHeaders.Sha2Bits256;
        Span<byte> multihashPrefix = stackalloc byte[sha256Code.Length + 1];
        sha256Code.CopyTo(multihashPrefix);
        multihashPrefix[sha256Code.Length] = (byte)Sha256DigestLength;
        string hashPortion = MultibaseSerializer.Encode(digest, multihashPrefix, MultibaseAlgorithms.Base58Btc, base58Encoder, pool);

        return $"did:peer:4{hashPortion}:{encodedDocument}";
    }


    /// <summary>
    /// Generates a <c>did:peer:2</c> identifier from purposed keys and services per the
    /// <see href="https://identity.foundation/peer-did-method-spec/">Peer DID Method specification</see>:
    /// each key becomes a <c>.</c>purpose-code multibase-key element, and each service a <c>.S</c>
    /// element carrying the base64url-encoded abbreviated service block. Keys are emitted first, then
    /// services, in the supplied order.
    /// </summary>
    /// <param name="keys">The purposed keys; their order fixes the <c>#key-N</c> numbering on resolution.</param>
    /// <param name="services">The services to advertise (typically a DIDCommMessaging endpoint).</param>
    /// <param name="pool">Memory pool for the transient service-encode buffers.</param>
    /// <returns>The <c>did:peer:2</c> identifier.</returns>
    public static string GenerateNumalgo2(
        IReadOnlyList<PeerDidPurposedKey> keys,
        IReadOnlyList<Service> services,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(pool);

        EncodeDelegate base58Encoder = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase));

        StringBuilder builder = new("did:peer:2");

        foreach(PeerDidPurposedKey key in keys)
        {
            builder.Append('.').Append(PurposeCode(key.Purpose));
            builder.Append(MultibaseSerializer.EncodeKey(key.Key, base58Encoder));
        }

        foreach(Service service in services)
        {
            string abbreviated = PeerDidServiceWriter.Write(service);
            int byteCount = Encoding.UTF8.GetByteCount(abbreviated);
            using IMemoryOwner<byte> serviceBytes = pool.Rent(byteCount);
            Span<byte> serviceSpan = serviceBytes.Memory.Span[..byteCount];
            Encoding.UTF8.GetBytes(abbreviated, serviceSpan);
            builder.Append(".S").Append(Base64Url.EncodeToString(serviceSpan));
        }

        return builder.ToString();
    }


    private static char PurposeCode(PeerDidPurpose purpose) => purpose switch
    {
        PeerDidPurpose.Authentication => 'V',
        PeerDidPurpose.AssertionMethod => 'A',
        PeerDidPurpose.KeyAgreement => 'E',
        PeerDidPurpose.CapabilityInvocation => 'I',
        PeerDidPurpose.CapabilityDelegation => 'D',
        _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "Unknown peer DID purpose.")
    };
}
