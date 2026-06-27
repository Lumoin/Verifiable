using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// A chip's static Chip Authentication private key — the personalisation secret that matches the public
/// key a chip announces in EF.DG14. A software card holds one of these per Chip Authentication key it
/// supports and uses it to agree the static–ephemeral ECDH secret with a terminal (the card side of
/// <see cref="ChipAuthentication"/>).
/// </summary>
/// <remarks>
/// <para>
/// A tracked carrier rather than a naked scalar: it owns its pooled memory, clears it on disposal, and
/// carries <see cref="ApduTags.ChipAuthenticationPrivateKey"/> for provenance. The private key is an
/// unsigned big-endian scalar on the curve of the matching DG14 public key; the curve and the Secure
/// Messaging cipher are read from DG14, so this carrier only pairs the scalar with its
/// <see cref="KeyId"/>. The card borrows it — the producer that minted the chip key pair retains
/// ownership and disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("ChipAuthenticationKey(KeyId={KeyId})")]
public sealed class ChipAuthenticationKey: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="ChipAuthenticationKey"/> from owned private-key bytes.
    /// </summary>
    /// <param name="privateKey">The owned private-key scalar bytes. Ownership transfers to this instance.</param>
    /// <param name="keyId">The key identifier pairing this key with its EF.DG14 info, or <see langword="null"/> for a single-key chip.</param>
    public ChipAuthenticationKey(IMemoryOwner<byte> privateKey, int? keyId)
        : base(privateKey, ApduTags.ChipAuthenticationPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        KeyId = keyId;
    }


    /// <summary>Gets the key identifier pairing this key with its EF.DG14 info, or <see langword="null"/> for a single-key chip.</summary>
    public int? KeyId { get; }
}
