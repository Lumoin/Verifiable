using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cesr;

/// <summary>
/// The result of decoding a CESR indexed signature from either domain: the code, the signature index, the
/// optional other-index, and the recovered raw signature held in pooled memory.
/// </summary>
/// <remarks>
/// The raw value is owned by the caller, who MUST dispose this instance to return the buffer to its pool.
/// </remarks>
[SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "This is a disposable owner of pooled memory, not a comparable value; equality is not meaningful.")]
public readonly struct CesrParsedIndexedSignature: IDisposable
{
    private readonly IMemoryOwner<byte> rawOwner;

    /// <summary>
    /// Initializes a new instance of the <see cref="CesrParsedIndexedSignature"/> struct.
    /// </summary>
    /// <param name="code">The stable (hard) part of the code.</param>
    /// <param name="index">The signature index into the key list.</param>
    /// <param name="ondex">The other-index for a dual-indexed signature, or <see langword="null"/> when single-indexed.</param>
    /// <param name="rawOwner">The pooled buffer holding the raw signature.</param>
    /// <param name="rawLength">The number of valid raw bytes at the start of <paramref name="rawOwner"/>.</param>
    public CesrParsedIndexedSignature(string code, int index, int? ondex, IMemoryOwner<byte> rawOwner, int rawLength)
    {
        Code = code;
        Index = index;
        Ondex = ondex;
        this.rawOwner = rawOwner;
        RawLength = rawLength;
    }

    /// <summary>
    /// The stable (hard) part of the code, for example <c>A</c> for an Ed25519 indexed signature.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// The signature index into the (current) key list.
    /// </summary>
    public int Index { get; }

    /// <summary>
    /// The other-index into the prior key list for a dual-indexed signature, or <see langword="null"/> when
    /// the signature appears in the current list only.
    /// </summary>
    public int? Ondex { get; }

    /// <summary>
    /// The number of valid raw bytes in <see cref="Raw"/>.
    /// </summary>
    public int RawLength { get; }

    /// <summary>
    /// The recovered raw signature, without code or lead bytes.
    /// </summary>
    public ReadOnlySpan<byte> Raw => rawOwner.Memory.Span[..RawLength];

    /// <summary>
    /// Returns the pooled raw buffer to its pool.
    /// </summary>
    public void Dispose() => rawOwner.Dispose();
}
