using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu;

/// <summary>
/// Parsed response to a GET CHALLENGE command: the random bytes the card generated for use as a
/// challenge in a subsequent authentication step.
/// </summary>
/// <remarks>
/// <para>
/// GET CHALLENGE (INS <c>0x84</c>) asks the card to produce Le bytes of fresh randomness. The
/// challenge is typically consumed by an EXTERNAL AUTHENTICATE or a mutual-authentication exchange
/// (for example the eMRTD Basic Access Control protocol, which requests an 8-byte challenge). This
/// type carries the raw challenge bytes; the caller feeds them into the authentication step.
/// </para>
/// <para>
/// It inherits from <see cref="SensitiveMemory"/> so the bytes are cleared and returned to the
/// pool on disposal.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class GetChallengeResponse : SensitiveMemory, IApduWireType
{
    internal GetChallengeResponse(IMemoryOwner<byte> storage, int length)
        : base(storage, ApduTags.Response)
    {
        Length = length;
    }

    /// <summary>
    /// Gets the length of the challenge in bytes. Zero when the card returned no data
    /// (a bare <c>9000</c> response).
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the raw challenge bytes the card generated.
    /// </summary>
    public ReadOnlySpan<byte> Challenge => MemoryOwner.Memory.Span[..Length];

    /// <summary>
    /// Parses a GET CHALLENGE response from its data field (the status word is already stripped).
    /// </summary>
    /// <param name="reader">The reader positioned at the response data.</param>
    /// <param name="pool">The memory pool for the challenge buffer.</param>
    /// <returns>The parsed response. The caller owns it and must dispose it.</returns>
    public static GetChallengeResponse Parse(ref ApduReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> challenge = reader.ReadRemainingBytes();
        IMemoryOwner<byte> owner = pool.Rent(challenge.Length);
        challenge.CopyTo(owner.Memory.Span);

        return new GetChallengeResponse(owner, challenge.Length);
    }

    private string DebuggerDisplay => $"GetChallengeResponse(Challenge {Length}B)";
}
