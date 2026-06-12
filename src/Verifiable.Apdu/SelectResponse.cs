using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Apdu;

/// <summary>
/// Parsed response to a SELECT command: the File Control Information (FCI) template the card
/// returns for the selected application or file.
/// </summary>
/// <remarks>
/// <para>
/// When SELECT is issued with P2 requesting the FCI (the default for
/// <see cref="ApduCommandExtensions"/>'s SELECT), the card answers with a BER-TLV template
/// (tag <c>0x6F</c> for an FCI template, <c>0x62</c> for an FCP template, or <c>0x64</c> for an
/// FMD template). This type carries the raw template bytes; higher layers parse individual data
/// objects as needed.
/// </para>
/// <para>
/// It inherits from <see cref="SensitiveMemory"/> so the bytes are cleared and returned to the
/// pool on disposal.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SelectResponse : SensitiveMemory, IApduWireType
{
    internal SelectResponse(IMemoryOwner<byte> storage, int length)
        : base(storage, ApduTags.Response)
    {
        Length = length;
    }

    /// <summary>
    /// Gets the length of the File Control Information in bytes. Zero when the card returned
    /// no FCI (a bare <c>9000</c> response).
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the raw File Control Information template as returned by the card.
    /// </summary>
    public ReadOnlySpan<byte> FileControlInformation => MemoryOwner.Memory.Span[..Length];

    /// <summary>
    /// Parses a SELECT response from its data field (the status word is already stripped).
    /// </summary>
    /// <param name="reader">The reader positioned at the response data.</param>
    /// <param name="pool">The memory pool for the FCI buffer.</param>
    /// <returns>The parsed response. The caller owns it and must dispose it.</returns>
    public static SelectResponse Parse(ref ApduReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> fci = reader.ReadRemainingBytes();
        IMemoryOwner<byte> owner = pool.Rent(fci.Length);
        fci.CopyTo(owner.Memory.Span);

        return new SelectResponse(owner, fci.Length);
    }

    private string DebuggerDisplay => $"SelectResponse(FCI {Length}B)";
}
