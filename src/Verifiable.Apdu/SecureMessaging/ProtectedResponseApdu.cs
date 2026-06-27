using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu.SecureMessaging;

/// <summary>
/// The encoded wire bytes of a Secure Messaging protected response APDU — the encrypted response data
/// (DO'87', if any), the protected status word (DO'99'), and the cryptographic checksum (DO'8E'),
/// followed by the transport status word — ready for the card to return to a terminal.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <see cref="SecureMessagingCardSession.ProtectResponseAsync"/>, the card-side counterpart
/// of <see cref="ProtectedCommandApdu"/>. A tracked carrier rather than a naked buffer: it owns its
/// pooled memory and clears it on disposal, and carries <see cref="ApduTags.ProtectedResponseApdu"/> for
/// provenance.
/// </para>
/// </remarks>
[DebuggerDisplay("ProtectedResponseApdu({Length} bytes)")]
public sealed class ProtectedResponseApdu: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="ProtectedResponseApdu"/> from owned wire bytes.
    /// </summary>
    /// <param name="storage">The owned, exact-size buffer holding the protected response APDU. Ownership transfers to this instance.</param>
    public ProtectedResponseApdu(IMemoryOwner<byte> storage)
        : base(storage, ApduTags.ProtectedResponseApdu)
    {
        ArgumentNullException.ThrowIfNull(storage);
    }


    /// <summary>Gets the length of the protected response APDU in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;
}
