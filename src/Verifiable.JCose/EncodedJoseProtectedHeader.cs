using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Semantic carrier for the base64url-encoded <c>protected</c> header TEXT of a JAdES/JWS signature, per
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.1">RFC 7515 §5.1</see>: the ASCII bytes of
/// <c>BASE64URL(UTF8(JWS Protected Header))</c>. Owns its underlying pool-rented memory; disposing the carrier
/// returns the buffer.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="EncodedCoseProtectedHeader"/>'s shape and rationale, one wire format removed. The JWS
/// Signing Input is <c>ASCII(BASE64URL(UTF8(JWS Protected Header))) || '.' || BASE64URL(JWS Payload)</c> (RFC
/// 7515 §5.1), and JAdES's own message-imprint algorithms (clause 5.3.6.2.3 step 4) fold this exact base64url
/// TEXT into a time-stamp input — never a re-derived encoding of the decoded header object
/// (<see cref="JAdESArchiveTimestampImprintContext.ProtectedHeaderBase64Url"/>'s own remarks). This carrier
/// preserves the original encoding for that reason, matching <see cref="CryptoTags.JoseEncodedProtectedHeader"/>'s
/// own rationale.
/// </para>
/// </remarks>
[DebuggerDisplay("EncodedJoseProtectedHeader({Length} bytes)")]
public sealed class EncodedJoseProtectedHeader(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
    : SensitiveMemory(sensitiveMemory, tag, lifetime)
{
    /// <summary>Gets the length of the encoded base64url TEXT, in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Rents pool memory of <paramref name="base64UrlText"/>'s length, copies the ASCII bytes in, and wraps the
    /// buffer in an <see cref="EncodedJoseProtectedHeader"/> carrying
    /// <see cref="CryptoTags.JoseEncodedProtectedHeader"/>. Caller takes ownership of the returned carrier.
    /// </summary>
    /// <remarks>
    /// A JAdES protected header always carries a mandatory <c>alg</c> member (JA-5.1.2-01), so its base64url
    /// TEXT is never genuinely empty in practice; the empty-input arm below exists only for the same structural
    /// reason <see cref="EncodedCoseProtectedHeader.FromBytes"/> keeps one — <see cref="BaseMemoryPool.Rent"/>
    /// refuses a zero-length rental.
    /// </remarks>
    /// <param name="base64UrlText">The base64url-encoded protected-header TEXT, ASCII bytes.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    public static EncodedJoseProtectedHeader FromBytes(ReadOnlySpan<byte> base64UrlText, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(base64UrlText.IsEmpty)
        {
            return new EncodedJoseProtectedHeader(EmptyMemoryOwner.Instance, CryptoTags.JoseEncodedProtectedHeader);
        }

        IMemoryOwner<byte> owner = pool.Rent(base64UrlText.Length);
        base64UrlText.CopyTo(owner.Memory.Span);

        return new EncodedJoseProtectedHeader(owner, CryptoTags.JoseEncodedProtectedHeader);
    }
}
