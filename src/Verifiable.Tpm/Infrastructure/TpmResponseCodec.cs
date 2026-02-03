using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Delegate for parsing TPM response parameters (no output handles).
/// </summary>
/// <typeparam name="TResponse">The response type.</typeparam>
/// <param name="reader">The reader positioned at the response parameter area.</param>
/// <param name="pool">The memory pool for allocations.</param>
/// <returns>The parsed response.</returns>
public delegate TResponse TpmResponseParser<TResponse>(ref TpmReader reader, MemoryPool<byte> pool)
    where TResponse : ITpmWireType;

/// <summary>
/// Delegate for parsing TPM response with one output handle.
/// </summary>
/// <typeparam name="TResponse">The response type.</typeparam>
/// <param name="reader">The reader positioned at the response parameter area.</param>
/// <param name="handle">The output handle from the response handle area.</param>
/// <param name="pool">The memory pool for allocations.</param>
/// <returns>The parsed response.</returns>
public delegate TResponse TpmResponseParserWithHandle<TResponse>(ref TpmReader reader, uint handle, MemoryPool<byte> pool)
    where TResponse : ITpmWireType;

/// <summary>
/// Internal delegate for type-erased response parsing with ref support.
/// </summary>
internal delegate ITpmWireType TpmResponseParserInternal(ref TpmReader reader, uint[] outHandles, MemoryPool<byte> pool);

/// <summary>
/// Codec for parsing TPM command responses.
/// </summary>
/// <remarks>
/// <para>
/// A codec encapsulates knowledge of a specific command's response structure:
/// </para>
/// <list type="bullet">
///   <item><description>Number of output handles in the response handle area.</description></item>
///   <item><description>Parser delegate that reads the response parameter area.</description></item>
/// </list>
/// <para>
/// <b>Design:</b>
/// </para>
/// <para>
/// The codec separates envelope parsing (handled by the executor) from parameter
/// parsing (handled by the codec's delegate). The executor handles:
/// </para>
/// <list type="bullet">
///   <item><description>Response header (tag, size, response code).</description></item>
///   <item><description>Output handles (count determined by <see cref="OutHandleCount"/>).</description></item>
///   <item><description>Authorization area (when sessions are present).</description></item>
/// </list>
/// <para>
/// The codec's parser delegate receives the parameter area bytes and any output
/// handles, returning a strongly-typed response object. Response types that include
/// handles receive them via the parser delegate, keeping the response self-contained.
/// </para>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <code>
/// //Command with no output handles.
/// registry.Register(TpmCcConstants.TPM_CC_GetRandom,
///     TpmResponseCodec.Create(GetRandomResponse.Parse));
///
/// //Command with one output handle.
/// registry.Register(TpmCcConstants.TPM_CC_CreatePrimary,
///     TpmResponseCodec.CreateWithHandle&lt;CreatePrimaryResponse&gt;(
///         (ref TpmReader r, uint h, MemoryPool&lt;byte&gt; p) =&gt;
///             CreatePrimaryResponse.Parse(ref r, TpmiDhObject.FromValue(h), p)));
/// </code>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmResponseCodec
{
    private readonly TpmResponseParserInternal? parser;

    /// <summary>
    /// Gets the number of handles in the response handle area.
    /// </summary>
    public int OutHandleCount { get; }

    /// <summary>
    /// Gets whether this command has response parameters.
    /// </summary>
    public bool HasResponseParameters => parser != null;

    private TpmResponseCodec(int outHandleCount, TpmResponseParserInternal? parser)
    {
        OutHandleCount = outHandleCount;
        this.parser = parser;
    }

    /// <summary>
    /// Creates a codec with no output handles.
    /// </summary>
    /// <typeparam name="TResponse">The response type.</typeparam>
    /// <param name="parser">The parser delegate.</param>
    /// <returns>The codec.</returns>
    public static TpmResponseCodec Create<TResponse>(TpmResponseParser<TResponse> parser)
        where TResponse : ITpmWireType
    {
        return new TpmResponseCodec(0, (ref TpmReader r, uint[] _, MemoryPool<byte> p) => parser(ref r, p));
    }

    /// <summary>
    /// Creates a codec with one output handle.
    /// </summary>
    /// <typeparam name="TResponse">The response type.</typeparam>
    /// <param name="parser">The parser delegate that receives the handle.</param>
    /// <returns>The codec.</returns>
    public static TpmResponseCodec CreateWithHandle<TResponse>(TpmResponseParserWithHandle<TResponse> parser)
        where TResponse : ITpmWireType
    {
        return new TpmResponseCodec(1, (ref TpmReader r, uint[] h, MemoryPool<byte> p) => parser(ref r, h[0], p));
    }

    /// <summary>
    /// Creates a codec for a command with no output handles and no response parameters.
    /// </summary>
    /// <returns>The codec.</returns>
    public static TpmResponseCodec NoParameters()
    {
        return new TpmResponseCodec(0, null);
    }

    /// <summary>
    /// Creates a codec for a command with one output handle and no response parameters.
    /// </summary>
    /// <returns>The codec.</returns>
    public static TpmResponseCodec OneHandleNoParameters()
    {
        return new TpmResponseCodec(1, null);
    }

    /// <summary>
    /// Parses the response parameters.
    /// </summary>
    /// <param name="reader">The reader positioned at the parameter area.</param>
    /// <param name="outHandles">The output handles from the response handle area.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parsed response as <see cref="ITpmWireType"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if this command has no response parameters.
    /// </exception>
    internal ITpmWireType ParseResponse(ref TpmReader reader, uint[] outHandles, MemoryPool<byte> pool)
    {
        if(parser == null)
        {
            throw new InvalidOperationException("This command has no response parameters.");
        }

        return parser(ref reader, outHandles, pool);
    }

    private string DebuggerDisplay => $"TpmResponseCodec(Handles={OutHandleCount}, HasParams={HasResponseParameters})";
}