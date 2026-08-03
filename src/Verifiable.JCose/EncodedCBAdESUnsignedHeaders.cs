using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Semantic carrier for the CBOR-encoded <c>uHeaders</c> array bytes (label 268) of a CB-AdES
/// <c>COSE_Sign1</c> message's unprotected header map, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.3.1. Owns its underlying pool-rented memory; disposing the
/// carrier returns the buffer.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Mirrors <see cref="EncodedCoseProtectedHeader"/>'s shape exactly</strong> (wavecb S4 coordinator
/// ruling (3), the wavecb S3 FX-A raw-bytes precedent): sealed, <see cref="SensitiveMemory"/>-derived,
/// carries <see cref="CryptoTags.CoseEncodedUnsignedHeaders"/> for CBOM/OTel provenance. The encoded bytes
/// are the exact byte sequence the wire carried as the unprotected header map's <c>uHeaders</c> (268)
/// member — the Annex A.1.2.1.2 (<c>sigRTst</c>) and A.1.2.2.2 (<c>rfsTst</c>) message-imprint builders must
/// consume THESE bytes at validation time, never a re-encoding of the decoded
/// <see cref="Verifiable.Cryptography.Pki.CBAdESUnsignedHeaders"/> model, for exactly the reason
/// <see cref="CBAdESSign1ParseResult.RawProtectedHeader"/>'s own remarks give for the protected header:
/// a re-encoder cannot be relied upon to reproduce a CDDL union arm (or, here, an unprofiled/opaque
/// <c>uHeaders</c> element) the decoded model does not itself retain enough information to choose between.
/// </para>
/// </remarks>
[DebuggerDisplay("EncodedCBAdESUnsignedHeaders({Length} bytes)")]
public sealed class EncodedCBAdESUnsignedHeaders(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
    : SensitiveMemory(sensitiveMemory, tag, lifetime)
{
    /// <summary>Gets the length of the encoded <c>uHeaders</c> array in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Rents pool memory of <paramref name="bytes"/>'s length, copies the bytes in, and wraps the buffer in
    /// an <see cref="EncodedCBAdESUnsignedHeaders"/> carrying <see cref="CryptoTags.CoseEncodedUnsignedHeaders"/>.
    /// Caller takes ownership of the returned carrier.
    /// </summary>
    /// <param name="bytes">The encoded <c>uHeaders</c> array's own wire bytes.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The owned carrier.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static EncodedCBAdESUnsignedHeaders FromBytes(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new EncodedCBAdESUnsignedHeaders(owner, CryptoTags.CoseEncodedUnsignedHeaders);
    }
}
