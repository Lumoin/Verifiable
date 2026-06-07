using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Semantic carrier for the wire bytes of a complete <c>COSE_Mac0</c>
/// message per
/// <see href="https://www.rfc-editor.org/rfc/rfc9052">RFC 9052</see> —
/// the CBOR tag(17)-wrapped 4-array carrying protected header,
/// unprotected header, payload, and MAC tag. Owns its underlying
/// pool-rented memory; disposing the carrier returns the buffer.
/// </summary>
/// <remarks>
/// <para>
/// Parallels <see cref="EncodedCoseSign1"/> on the MAC side. Used as the
/// storage type for credential-side fields that hold a COSE_Mac0 wire
/// form (e.g. mdoc's <c>MdocDeviceMac.EncodedCoseMac0</c>).
/// </para>
/// </remarks>
[DebuggerDisplay("EncodedCoseMac0({Length} bytes)")]
public sealed class EncodedCoseMac0(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
    : SensitiveMemory(sensitiveMemory, tag, lifetime)
{
    /// <summary>Gets the length of the encoded message in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;
}
