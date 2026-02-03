using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;

namespace Verifiable.Tpm;

/// <summary>
/// A TPM command response containing the raw response bytes.
/// </summary>
/// <remarks>
/// <para>
/// This type wraps the raw bytes returned by the TPM device. It inherits from
/// <see cref="SensitiveMemory"/> to ensure proper handling of potentially sensitive
/// response data (keys, secrets, random bytes, etc.).
/// </para>
/// <para>
/// <strong>Ownership:</strong> The caller owns this response and must dispose it
/// when done. Disposing clears the memory and returns it to the pool.
/// </para>
/// <para>
/// <strong>Usage:</strong>
/// </para>
/// <code>
/// using TpmResponse response = device.Submit(commandBytes, pool);
/// 
/// //Parse the response.
/// var reader = new TpmReader(response.AsReadOnlySpan());
/// ushort tag = reader.ReadUInt16();
/// uint size = reader.ReadUInt32();
/// uint responseCode = reader.ReadUInt32();
/// </code>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmResponse: SensitiveMemory
{
    /// <summary>
    /// Initializes a new TPM response with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the response bytes.</param>
    /// <param name="length">The actual length of valid response data.</param>
    internal TpmResponse(IMemoryOwner<byte> storage, int length) : base(storage, TpmTags.Response)
    {
        Length = length;
    }

    /// <summary>
    /// Gets the length of the response in bytes.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the response bytes as a span.
    /// </summary>
    /// <returns>A read-only span of the response bytes.</returns>
    public new ReadOnlySpan<byte> AsReadOnlySpan() => base.AsReadOnlySpan().Slice(0, Length);

    /// <summary>
    /// Gets the response bytes as memory.
    /// </summary>
    /// <returns>A read-only memory of the response bytes.</returns>
    public new ReadOnlyMemory<byte> AsReadOnlyMemory() => base.AsReadOnlyMemory().Slice(0, Length);

    private string DebuggerDisplay => $"TpmResponse({Length} bytes)";
}