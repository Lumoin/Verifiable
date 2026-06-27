using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu;

/// <summary>
/// Delegate for parsing APDU response data into a typed result.
/// </summary>
/// <typeparam name="TResponse">The response type.</typeparam>
/// <param name="reader">The reader positioned at the response data (SW already stripped).</param>
/// <param name="pool">The memory pool for allocations.</param>
/// <returns>The parsed response.</returns>
public delegate TResponse ApduResponseParser<TResponse>(
    ref ApduReader reader,
    MemoryPool<byte> pool) where TResponse: IApduWireType;

/// <summary>
/// Internal delegate for type-erased response parsing.
/// </summary>
internal delegate IApduWireType ApduResponseParserInternal(
    ref ApduReader reader,
    MemoryPool<byte> pool);

/// <summary>
/// Codec for parsing APDU command responses.
/// </summary>
/// <remarks>
/// <para>
/// A codec encapsulates knowledge of how to parse a specific command's response data.
/// The executor handles envelope mechanics (status word extraction, response chaining),
/// then invokes the codec's parser on the data portion.
/// </para>
/// <para>
/// <strong>Usage:</strong>
/// </para>
/// <code>
/// var registry = new ApduResponseRegistry();
/// registry.Register(
///     InstructionCode.Select,
///     ApduResponseCodec.Create(SelectResponse.Parse));
/// </code>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ApduResponseCodec
{
    private readonly ApduResponseParserInternal? parser;

    /// <summary>
    /// Gets whether this codec has response data to parse.
    /// </summary>
    /// <remarks>
    /// Some commands (e.g., VERIFY with correct PIN) return only a status word
    /// with no data. Their codec has no parser.
    /// </remarks>
    public bool HasResponseData => parser is not null;

    private ApduResponseCodec(ApduResponseParserInternal? parser)
    {
        this.parser = parser;
    }

    /// <summary>
    /// Creates a codec with a typed parser.
    /// </summary>
    /// <typeparam name="TResponse">The response type.</typeparam>
    /// <param name="parser">The parser delegate.</param>
    /// <returns>The codec.</returns>
    public static ApduResponseCodec Create<TResponse>(ApduResponseParser<TResponse> parser)
        where TResponse: IApduWireType
    {
        ArgumentNullException.ThrowIfNull(parser);
        return new ApduResponseCodec(
            (ref ApduReader r, MemoryPool<byte> p) => parser(ref r, p));
    }

    /// <summary>
    /// Creates a codec for a command with no response data.
    /// </summary>
    /// <returns>The codec.</returns>
    public static ApduResponseCodec NoData()
    {
        return new ApduResponseCodec(null);
    }

    /// <summary>
    /// Parses the response data.
    /// </summary>
    /// <param name="reader">The reader positioned at the data.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parsed response as <see cref="IApduWireType"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown if this codec has no parser.</exception>
    internal IApduWireType ParseResponse(ref ApduReader reader, MemoryPool<byte> pool)
    {
        if(parser is null)
        {
            throw new InvalidOperationException("This codec has no response data parser.");
        }

        return parser(ref reader, pool);
    }

    private string DebuggerDisplay => $"ApduResponseCodec(HasData={HasResponseData})";
}
