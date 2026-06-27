using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu.SecureMessaging;

/// <summary>
/// The encoded wire bytes of a Secure Messaging protected command APDU — the masked header, the
/// encrypted command data (DO'87'), the expected length (DO'97'), and the cryptographic checksum
/// (DO'8E') — ready to transmit to the card.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <see cref="SecureMessagingSession.ProtectCommandAsync"/>. A tracked carrier rather
/// than a naked buffer: it owns its pooled memory and clears it on disposal, and carries
/// <see cref="ApduTags.ProtectedCommandApdu"/> for provenance.
/// </para>
/// </remarks>
[DebuggerDisplay("ProtectedCommandApdu({Length} bytes)")]
public sealed class ProtectedCommandApdu: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="ProtectedCommandApdu"/> from owned wire bytes.
    /// </summary>
    /// <param name="storage">The owned, exact-size buffer holding the protected command APDU. Ownership transfers to this instance.</param>
    public ProtectedCommandApdu(IMemoryOwner<byte> storage)
        : base(storage, ApduTags.ProtectedCommandApdu)
    {
        ArgumentNullException.ThrowIfNull(storage);
    }


    /// <summary>Gets the length of the protected command APDU in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;
}
