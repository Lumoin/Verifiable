using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cesr;

/// <summary>
/// The result of decoding a single CESR primitive from either the text or binary domain: the stable code,
/// the soft value (empty unless the code carries one), and the recovered raw value held in pooled memory.
/// </summary>
/// <remarks>
/// The raw value is owned by the caller, who MUST dispose this instance to return the buffer to its pool.
/// </remarks>
[SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "This is a disposable owner of pooled memory, not a comparable value; equality is not meaningful.")]
public readonly struct CesrParsedPrimitive: IDisposable
{
    private readonly IMemoryOwner<byte> rawOwner;

    /// <summary>
    /// Initializes a new instance of the <see cref="CesrParsedPrimitive"/> struct.
    /// </summary>
    /// <param name="code">The stable (hard) part of the code.</param>
    /// <param name="soft">The soft value, exclusive of any extra prepad; empty when the code has none.</param>
    /// <param name="rawOwner">The pooled buffer holding the raw value.</param>
    /// <param name="rawLength">The number of valid raw bytes at the start of <paramref name="rawOwner"/>.</param>
    public CesrParsedPrimitive(string code, string soft, IMemoryOwner<byte> rawOwner, int rawLength)
    {
        Code = code;
        Soft = soft;
        this.rawOwner = rawOwner;
        RawLength = rawLength;
    }

    /// <summary>
    /// The stable (hard) part of the code, for example <c>0B</c> for an Ed25519 signature.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// The soft value carried in the code, exclusive of any extra prepad; empty when the code carries none.
    /// </summary>
    public string Soft { get; }

    /// <summary>
    /// The number of valid raw bytes in <see cref="Raw"/>.
    /// </summary>
    public int RawLength { get; }

    /// <summary>
    /// The recovered raw value (the unframed cryptographic material), without code or lead bytes.
    /// </summary>
    public ReadOnlySpan<byte> Raw => rawOwner.Memory.Span[..RawLength];

    /// <summary>
    /// Returns the pooled raw buffer to its pool.
    /// </summary>
    public void Dispose() => rawOwner.Dispose();
}
