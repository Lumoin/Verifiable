using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu.Pace;

/// <summary>
/// The bytes of a GENERAL AUTHENTICATE dynamic authentication data object (BER-TLV tag <c>0x7C</c>)
/// — the command object the terminal sends in a PACE round, and the response value the chip returns
/// (the encrypted nonce, an ephemeral public key, or an authentication token, depending on the round).
/// </summary>
/// <remarks>
/// <para>
/// A tracked carrier rather than a naked buffer: it owns its pooled memory, clears it on disposal,
/// and carries <see cref="ApduTags.DynamicAuthenticationData"/> for provenance. Produced and consumed
/// by <see cref="PaceProtocol"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("DynamicAuthenticationData({Length} bytes)")]
public sealed class DynamicAuthenticationData: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="DynamicAuthenticationData"/> from owned bytes.
    /// </summary>
    /// <param name="storage">The owned, exact-size buffer. Ownership transfers to this instance.</param>
    public DynamicAuthenticationData(IMemoryOwner<byte> storage)
        : base(storage, ApduTags.DynamicAuthenticationData)
    {
        ArgumentNullException.ThrowIfNull(storage);
    }


    /// <summary>Gets the length of the data object in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;
}
