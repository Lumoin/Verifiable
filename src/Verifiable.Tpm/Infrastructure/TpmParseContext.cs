using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Internal accumulator state used during TPM response parsing.
/// </summary>
/// <remarks>
/// <para>
/// This class serves as the "fold state" for the response parsing pipeline.
/// It accumulates intermediate results as the executor processes the response:
/// </para>
/// <list type="bullet">
///   <item><description>Response header (tag, size, response code).</description></item>
///   <item><description>Output handles from the handle area.</description></item>
///   <item><description>Session auth responses from the authorization area.</description></item>
///   <item><description>Retained buffers for lifetime management.</description></item>
/// </list>
/// <para>
/// <b>Design:</b>
/// </para>
/// <para>
/// The executor uses this context internally during parsing. The strongly-typed
/// response (e.g., <c>GetCapabilityResponse</c>) is produced by the codec's
/// parser delegate, which receives only the parameter area bytes. The final
/// <c>TpmResult&lt;T&gt;</c> returned to the caller contains the typed response,
/// not this context.
/// </para>
/// <para>
/// This separation keeps the context as generic infrastructure while response
/// types are command-specific and strongly-typed.
/// </para>
/// <para>
/// <b>Lifetime:</b>
/// </para>
/// <para>
/// The context retains the response buffer to enable zero-copy access to
/// response data. The typed response objects may reference this buffer
/// (via <see cref="TpmBlob"/>) or own their own memory (via <see cref="IMemoryOwner{T}"/>).
/// </para>
/// </remarks>
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Internal parsing accumulator. Properties are set during response parsing, not exposed to consumers.")]
public sealed class TpmParseContext
{
    /// <summary>
    /// Gets the command code that was executed.
    /// </summary>
    public required TpmCcConstants CommandCode { get; init; }

    /// <summary>
    /// Gets the memory pool for allocations during parsing.
    /// </summary>
    public required MemoryPool<byte> Pool { get; init; }

    /// <summary>
    /// Gets or sets the parsed response header.
    /// </summary>
    public TpmHeader ResponseHeader { get; set; }

    /// <summary>
    /// Gets or sets the output handles from the response handle area.
    /// </summary>
    /// <remarks>
    /// Handles are returned as raw uint values. The caller interprets them
    /// based on the command (e.g., session handle, object handle).
    /// </remarks>
    public uint[] OutHandles { get; set; } = [];

    /// <summary>
    /// Gets or sets the session auth responses from the authorization area.
    /// </summary>
    public TpmsAuthResponse[] OutSessions { get; set; } = [];

    /// <summary>
    /// Gets or sets the retained request buffer.
    /// </summary>
    /// <remarks>
    /// Retained for debugging and diagnostics. Contains the full command
    /// that was sent to the TPM.
    /// </remarks>
    public ReadOnlyMemory<byte> RequestBytes { get; set; }

    /// <summary>
    /// Gets or sets the retained response buffer.
    /// </summary>
    /// <remarks>
    /// Retained for zero-copy access and debugging. Response wire types
    /// may reference this buffer.
    /// </remarks>
    public ReadOnlyMemory<byte> ResponseBytes { get; set; }

    /// <summary>
    /// Gets the response bytes as a span.
    /// </summary>
    public ReadOnlySpan<byte> ResponseSpan => ResponseBytes.Span;

    /// <summary>
    /// Gets or sets the labeled slices for the request buffer.
    /// </summary>
    /// <remarks>
    /// Used for debugging and visualization of the command structure.
    /// </remarks>
    public IReadOnlyList<TpmSlice> RequestSlices { get; set; } = [];

    /// <summary>
    /// Gets or sets the labeled slices for the response buffer.
    /// </summary>
    /// <remarks>
    /// Used for debugging and visualization of the response structure.
    /// </remarks>
    public IReadOnlyList<TpmSlice> ResponseSlices { get; set; } = [];
}