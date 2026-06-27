using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// A chip's Active Authentication private key — the personalisation secret that matches the public key
/// the chip announces in EF.DG15. A software card holds this single key and uses it to sign the
/// terminal's INTERNAL AUTHENTICATE challenge (the card side of <see cref="ActiveAuthentication"/>).
/// </summary>
/// <remarks>
/// <para>
/// A tracked carrier rather than a naked scalar: it owns its pooled memory, clears it on disposal, and
/// carries <see cref="ApduTags.ActiveAuthenticationPrivateKey"/> for provenance. The private key is an
/// unsigned big-endian scalar on the curve of the EF.DG15 public key; the curve is read from DG15, so
/// this carrier holds only the scalar. Unlike Chip Authentication, Active Authentication uses a single
/// key, so there is no key identifier. The card borrows it — the producer that minted the chip key pair
/// retains ownership and disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("ActiveAuthenticationKey")]
public sealed class ActiveAuthenticationKey: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="ActiveAuthenticationKey"/> from owned private-key bytes.
    /// </summary>
    /// <param name="privateKey">The owned private-key scalar bytes. Ownership transfers to this instance.</param>
    public ActiveAuthenticationKey(IMemoryOwner<byte> privateKey)
        : base(privateKey, ApduTags.ActiveAuthenticationPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
    }
}
