using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu;

/// <summary>
/// Parsed response to an EXTERNAL AUTHENTICATE command: the raw bytes the card returns to prove
/// its own knowledge of the shared keys.
/// </summary>
/// <remarks>
/// <para>
/// EXTERNAL AUTHENTICATE (INS <c>0x82</c>) carries the terminal's authentication token; the card
/// answers with its own. In ICAO Doc 9303 Basic Access Control the response data is the 40-byte
/// <c>EIC || MIC</c> — the chip's encrypted nonce/key material and its Retail MAC — which the
/// terminal verifies and from which both sides derive the Secure Messaging session keys.
/// </para>
/// <para>
/// It inherits from <see cref="SensitiveMemory"/> so the bytes are cleared and returned to the
/// pool on disposal.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ExternalAuthenticateResponse : SensitiveMemory, IApduWireType
{
    internal ExternalAuthenticateResponse(IMemoryOwner<byte> storage, int length)
        : base(storage, ApduTags.Response)
    {
        Length = length;
    }

    /// <summary>
    /// Gets the length of the response data in bytes. Zero when the card returned no data
    /// (a bare <c>9000</c> response).
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the raw response data the card returned.
    /// </summary>
    public ReadOnlySpan<byte> Data => MemoryOwner.Memory.Span[..Length];

    /// <summary>
    /// Parses an EXTERNAL AUTHENTICATE response from its data field (the status word is already stripped).
    /// </summary>
    /// <param name="reader">The reader positioned at the response data.</param>
    /// <param name="pool">The memory pool for the data buffer.</param>
    /// <returns>The parsed response. The caller owns it and must dispose it.</returns>
    public static ExternalAuthenticateResponse Parse(ref ApduReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> data = reader.ReadRemainingBytes();
        IMemoryOwner<byte> owner = pool.Rent(data.Length);
        data.CopyTo(owner.Memory.Span);

        return new ExternalAuthenticateResponse(owner, data.Length);
    }

    private string DebuggerDisplay => $"ExternalAuthenticateResponse(Data {Length}B)";
}
