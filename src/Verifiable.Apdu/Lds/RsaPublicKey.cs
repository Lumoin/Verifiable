using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// A DER-encoded RSA public key — the <c>RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent
/// INTEGER }</c> (PKCS#1 / RFC 8017) an eMRTD carries inside an EF.DG15 RSA Active Authentication
/// SubjectPublicKeyInfo. A tracked carrier rather than a naked buffer: it owns its pooled memory, clears it
/// on disposal, and carries <see cref="ApduTags.RsaPublicKey"/> for provenance.
/// </summary>
/// <remarks>
/// <para>
/// The bytes are the DER <c>RSAPublicKey</c> sequence — both the modulus and the public exponent, unlike the
/// modulus-only form the library's PKCS#1/PSS RSA functions assume — because RSA Active Authentication
/// (ISO/IEC 9796-2) needs the exact exponent. A verifier reconstructs the RSA key from these bytes.
/// </para>
/// </remarks>
[DebuggerDisplay("RsaPublicKey({Length} bytes)")]
public sealed class RsaPublicKey: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="RsaPublicKey"/> from owned DER <c>RSAPublicKey</c> bytes.
    /// </summary>
    /// <param name="storage">The owned, exact-size buffer holding the DER <c>RSAPublicKey</c> sequence. Ownership transfers to this instance.</param>
    public RsaPublicKey(IMemoryOwner<byte> storage)
        : base(storage, ApduTags.RsaPublicKey)
    {
        ArgumentNullException.ThrowIfNull(storage);
    }


    /// <summary>Gets the length of the DER <c>RSAPublicKey</c> in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Copies <paramref name="bytes"/> into a pooled <see cref="RsaPublicKey"/>.
    /// </summary>
    public static RsaPublicKey FromBytes(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new RsaPublicKey(owner);
    }
}
