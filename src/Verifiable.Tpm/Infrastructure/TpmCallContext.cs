using System;
using System.Buffers;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Internal working context used during request build and response verification.
/// </summary>
/// <remarks>
/// <para>
/// This ref struct carries crypto state and buffer references needed by sessions
/// during HMAC computation and verification. It is internal to the executor and
/// not exposed to callers.
/// </para>
/// <para>
/// <b>Lifetime:</b> This context exists only during a single <c>Execute</c> call.
/// It references buffers owned by the executor. Do not store or return this struct.
/// </para>
/// <para>
/// <b>Key fields for sessions:</b>
/// </para>
/// <list type="bullet">
///   <item><description><see cref="CpHashSlice"/> - Slice of computed cpHash for request HMAC.</description></item>
///   <item><description><see cref="RpHashSlice"/> - Slice of computed rpHash for response verification.</description></item>
///   <item><description><see cref="RequestBytes"/> - Full request buffer for slice extraction.</description></item>
///   <item><description><see cref="ResponseBytes"/> - Full response buffer for slice extraction.</description></item>
/// </list>
/// </remarks>
public ref struct TpmCallContext
{
    //Command identification.

    /// <summary>
    /// Gets the command code.
    /// </summary>
    public TpmCcConstants CommandCode { get; init; }

    /// <summary>
    /// Gets or sets the request tag.
    /// </summary>
    public ushort RequestTag { get; set; }

    /// <summary>
    /// Gets or sets the response tag.
    /// </summary>
    public ushort ResponseTag { get; set; }

    //Request slices (offsets into RequestBytes).

    /// <summary>
    /// Gets or sets the request header slice.
    /// </summary>
    public TpmSlice RequestHeader { get; set; }

    /// <summary>
    /// Gets or sets the request handles slice.
    /// </summary>
    public TpmSlice RequestHandles { get; set; }

    /// <summary>
    /// Gets or sets the request auth area slice.
    /// </summary>
    public TpmSlice RequestAuth { get; set; }

    /// <summary>
    /// Gets or sets the request parameters slice.
    /// </summary>
    public TpmSlice RequestParameters { get; set; }

    //Response slices (offsets into ResponseBytes).

    /// <summary>
    /// Gets or sets the response header slice.
    /// </summary>
    public TpmSlice ResponseHeader { get; set; }

    /// <summary>
    /// Gets or sets the response handles slice.
    /// </summary>
    public TpmSlice ResponseHandles { get; set; }

    /// <summary>
    /// Gets or sets the response auth area slice.
    /// </summary>
    public TpmSlice ResponseAuth { get; set; }

    /// <summary>
    /// Gets or sets the response parameters slice.
    /// </summary>
    public TpmSlice ResponseParameters { get; set; }

    //Crypto state for sessions.

    /// <summary>
    /// Gets or sets the cpHash slice (into CpHashBuffer).
    /// </summary>
    /// <remarks>
    /// cpHash = hash(commandCode || handles || parameters).
    /// Computed after request is built, before auth HMAC.
    /// </remarks>
    public TpmSlice CpHashSlice { get; set; }

    /// <summary>
    /// Gets or sets the rpHash slice (into RpHashBuffer).
    /// </summary>
    /// <remarks>
    /// rpHash = hash(responseCode || commandCode || parameters).
    /// Computed after response parameters are split, before auth verification.
    /// </remarks>
    public TpmSlice RpHashSlice { get; set; }

    /// <summary>
    /// Gets or sets the buffer containing the computed cpHash.
    /// </summary>
    public Span<byte> CpHashBuffer { get; set; }

    /// <summary>
    /// Gets or sets the buffer containing the computed rpHash.
    /// </summary>
    public Span<byte> RpHashBuffer { get; set; }

    //Retained buffers.

    /// <summary>
    /// Gets or sets the full request buffer.
    /// </summary>
    public ReadOnlySpan<byte> RequestBytes { get; set; }

    /// <summary>
    /// Gets or sets the full response buffer.
    /// </summary>
    public ReadOnlySpan<byte> ResponseBytes { get; set; }

    //Resources.

    /// <summary>
    /// Gets the memory pool for buffer allocation.
    /// </summary>
    public MemoryPool<byte> Pool { get; init; }

    /// <summary>
    /// Gets the cpHash bytes from the buffer.
    /// </summary>
    public ReadOnlySpan<byte> CpHash => CpHashSlice.IsEmpty ? [] : CpHashBuffer.Slice(CpHashSlice.Offset, CpHashSlice.Length);

    /// <summary>
    /// Gets the rpHash bytes from the buffer.
    /// </summary>
    public ReadOnlySpan<byte> RpHash => RpHashSlice.IsEmpty ? [] : RpHashBuffer.Slice(RpHashSlice.Offset, RpHashSlice.Length);
}