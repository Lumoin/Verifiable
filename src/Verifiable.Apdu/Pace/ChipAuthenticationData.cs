using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu.Pace;

/// <summary>
/// The PACE Chip Authentication Mapping authentication data <c>CA_IC = s_IC⁻¹ · s_Map,IC mod n</c>
/// (ICAO Doc 9303 Part 11 §4.4.3.5.1): the scalar the chip derives from its static Chip Authentication
/// private key and the ephemeral mapping private key. The chip encrypts it and sends it to the terminal,
/// which recovers it and verifies <c>PK_Map,IC = CA_IC · PK_IC</c> to authenticate the chip.
/// </summary>
/// <remarks>
/// A tracked carrier rather than a naked scalar: it owns its pooled memory and clears it on disposal. The
/// value is derived from the chip's static private key, so it is held in pinned, zeroized memory. The
/// <see cref="Verifiable.Foundation.SensitiveMemory.Tag"/> carries the curve the scalar is reduced over,
/// needed for the verification scalar multiplication.
/// </remarks>
[DebuggerDisplay("ChipAuthenticationData({Length} bytes)")]
public sealed class ChipAuthenticationData: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="ChipAuthenticationData"/> from owned bytes.
    /// </summary>
    /// <param name="storage">The owned, exact-size buffer holding the scalar. Ownership transfers to this instance.</param>
    /// <param name="curve">A tag carrying the curve <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> the scalar is reduced over.</param>
    public ChipAuthenticationData(IMemoryOwner<byte> storage, Tag curve)
        : base(storage, curve)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(curve);
    }


    /// <summary>Gets the length of the scalar in bytes (the curve's group-order width).</summary>
    public int Length => MemoryOwner.Memory.Length;
}
