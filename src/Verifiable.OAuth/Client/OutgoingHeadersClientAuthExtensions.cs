using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Composes <c>client_secret_basic</c> HTTP Basic client authentication onto <see cref="OutgoingHeaders"/>.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class OutgoingHeadersClientAuthExtensions
{
    /// <summary>
    /// The largest combined form-url-encoded <c>id:secret</c> credentials buffer, in bytes, encoded
    /// on the stack. Each input octet expands to at most three encoded output bytes (a <c>%XX</c>
    /// triplet), so this bounds the combined stack-eligible input (<c>client_id</c> plus the client
    /// secret) at 128 UTF-8 bytes — generous for any realistic client identifier and shared secret.
    /// Longer inputs fall back to a pooled buffer.
    /// </summary>
    private const int MaxStackEncodedLength = 384;

    extension(OutgoingHeaders headers)
    {
        /// <summary>
        /// Returns a new <see cref="OutgoingHeaders"/> with the <c>Authorization</c> header set to the
        /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1">RFC 6749 §2.3.1</see> HTTP
        /// Basic construction: <paramref name="clientId"/> and the UTF-8 decoding of
        /// <paramref name="clientSecretUtf8"/> are each <c>application/x-www-form-urlencoded</c>-encoded
        /// (RFC 6749 Appendix B) FIRST, joined with a single <c>:</c>, and the joined octets are then
        /// Base64-encoded — never a raw <c>id:secret</c> concatenation. Getting this ordering backwards
        /// is the one place a hand-rolled Basic header most easily diverges from the RFC, for any
        /// identifier or secret containing a character the form-urlencoded and Base64 alphabets treat
        /// differently (for example <c>:</c>, <c>+</c>, or space).
        /// </summary>
        /// <remarks>
        /// <paramref name="clientSecretUtf8"/> is read once during the call and not retained anywhere
        /// by this method — the caller owns clearing its own pooled backing buffer afterward. The
        /// combined form-url-encoded <c>id:secret</c> scratch buffer this method writes directly into
        /// (on the stack, or rented from <see cref="ArrayPool{T}"/> for unusually long inputs) is
        /// cleared before return, and is Base64-encoded in place — the plaintext secret never
        /// materializes as a managed <see cref="string"/> or an unpooled byte array anywhere in this
        /// method; the returned Base64 credentials string is the only value that carries it onward.
        /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 §2.3</see>: "The
        /// client MUST NOT use more than one authentication method in each request." A caller composing
        /// a token request MUST choose exactly one of this method or
        /// <see cref="OutgoingFormFieldsClientAuthExtensions.WithClientSecretPost"/> per request — never
        /// both — since neither helper can see whether the other has already been applied to the same
        /// request.
        /// </remarks>
        /// <param name="clientId">The client identifier (RFC 6749 §2.3.1 <c>client_id</c>), used as the Basic username.</param>
        /// <param name="clientSecretUtf8">The client secret, UTF-8 encoded, used as the Basic password. Confidential.</param>
        public OutgoingHeaders WithClientSecretBasic(string clientId, ReadOnlySpan<byte> clientSecretUtf8)
        {
            ArgumentNullException.ThrowIfNull(headers);
            ArgumentException.ThrowIfNullOrEmpty(clientId);

            ReadOnlySpan<byte> clientIdUtf8 = Encoding.UTF8.GetBytes(clientId);

            //Every octet of clientIdUtf8 and clientSecretUtf8 expands to at most 3 encoded bytes (a
            //%XX triplet), plus one byte for the joining ':' — the upper bound for the combined
            //credentials buffer this method Base64-encodes directly from, below.
            int maxCombinedLength = (clientIdUtf8.Length * 3) + 1 + (clientSecretUtf8.Length * 3);
            byte[]? rented = null;
            Span<byte> combined = maxCombinedLength <= MaxStackEncodedLength
                ? stackalloc byte[maxCombinedLength]
                : (rented = ArrayPool<byte>.Shared.Rent(maxCombinedLength));

            try
            {
                int written = FormUrlEncodeUtf8Into(clientIdUtf8, combined);
                combined[written++] = (byte)':';
                written += FormUrlEncodeUtf8Into(clientSecretUtf8, combined[written..]);

                string base64Credentials = Convert.ToBase64String(combined[..written]);

                return headers.WithAuthorization(WellKnownAuthenticationSchemes.Basic, base64Credentials);
            }
            finally
            {
                combined.Clear();
                if(rented is not null)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }
    }


    /// <summary>
    /// The RFC 6749 Appendix B <c>application/x-www-form-urlencoded</c> byte-level encoding, written
    /// directly into <paramref name="destination"/>: each unreserved octet (ALPHA, DIGIT, <c>-</c>,
    /// <c>.</c>, <c>_</c>, <c>*</c>) is copied verbatim, the space octet becomes <c>+</c>, and every
    /// other octet becomes an uppercase-hex <c>%XX</c> triplet — the rule RFC 6749's own worked
    /// example applies to space, <c>%</c>, <c>&amp;</c>, <c>+</c>, and non-ASCII octets alike
    /// (encoding UTF-8 bytes, not Unicode code points, so multi-byte characters become one
    /// <c>%XX</c> triplet per octet). <paramref name="destination"/> must be large enough for the
    /// worst case (three output bytes per input octet); the caller owns sizing and clearing it.
    /// </summary>
    /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
    private static int FormUrlEncodeUtf8Into(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        int written = 0;
        foreach(byte b in value)
        {
            if(IsUnreservedOctet(b))
            {
                destination[written++] = b;
            }
            else if(b == (byte)' ')
            {
                destination[written++] = (byte)'+';
            }
            else
            {
                destination[written++] = (byte)'%';
                destination[written++] = ToUpperHexDigit(b >> 4);
                destination[written++] = ToUpperHexDigit(b & 0xF);
            }
        }

        return written;
    }


    /// <summary>The application/x-www-form-urlencoded unreserved octet set: ALPHA, DIGIT, <c>-</c>, <c>.</c>, <c>_</c>, <c>*</c>.</summary>
    private static bool IsUnreservedOctet(byte b) =>
        (b >= (byte)'A' && b <= (byte)'Z')
        || (b >= (byte)'a' && b <= (byte)'z')
        || (b >= (byte)'0' && b <= (byte)'9')
        || b == (byte)'-' || b == (byte)'.' || b == (byte)'_' || b == (byte)'*';


    /// <summary>Renders <paramref name="nibble"/> (0-15) as an uppercase hex digit.</summary>
    private static byte ToUpperHexDigit(int nibble) =>
        (byte)(nibble < 10 ? '0' + nibble : 'A' + (nibble - 10));
}
