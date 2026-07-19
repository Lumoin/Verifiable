using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Attaches <c>client_secret_post</c> client authentication onto an outgoing token-request body.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class OutgoingFormFieldsClientAuthExtensions
{
    extension(OutgoingFormFields form)
    {
        /// <summary>
        /// Returns <paramref name="form"/> with <c>client_id</c> set to <paramref name="clientId"/> and
        /// <c>client_secret</c> set to the UTF-8 decoding of <paramref name="clientSecretUtf8"/> — the
        /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1">RFC 6749 §2.3.1</see>
        /// body-parameter client-authentication method. Per §2.3.1, "the client MAY omit the
        /// parameter if the client secret is an empty string": an empty
        /// <paramref name="clientSecretUtf8"/> sets only <c>client_id</c>.
        /// </summary>
        /// <remarks>
        /// No percent-encoding happens here — <see cref="OutgoingFormFields"/> values are
        /// wire-decoded strings; the transport's <see cref="Verifiable.OAuth.AuthCode.SendFormPostDelegate"/> owns
        /// <c>application/x-www-form-urlencoded</c> encoding (the builder-output ruling). This is
        /// unlike <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/>, which
        /// composes a header value the library must encode itself and so can Base64-encode straight
        /// from a cleared scratch buffer. Here the single <see cref="Encoding.GetString(ReadOnlySpan{byte})"/>
        /// call is the irreducible copy: <see cref="OutgoingFormFields"/> is a plain string-keyed
        /// dictionary matching the RFC 6749 §2.3.1 body-parameter shape, so the <c>client_secret</c>
        /// field value itself — not an extra intermediate — is where this method's copy of the secret
        /// ends up, exactly as long as <paramref name="form"/> retains it.
        /// <paramref name="clientSecretUtf8"/> is read once during the call and not retained anywhere
        /// by this method — the caller owns clearing its own pooled backing buffer afterward.
        /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 §2.3</see>: "The
        /// client MUST NOT use more than one authentication method in each request." A caller composing
        /// a token request MUST choose exactly one of this method or
        /// <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/> per request — never
        /// both — since neither helper can see whether the other has already been applied to the same
        /// request.
        /// </remarks>
        /// <param name="clientId">The client identifier (RFC 6749 §2.3.1 <c>client_id</c>).</param>
        /// <param name="clientSecretUtf8">The client secret, UTF-8 encoded. Confidential.</param>
        public OutgoingFormFields WithClientSecretPost(string clientId, ReadOnlySpan<byte> clientSecretUtf8)
        {
            ArgumentNullException.ThrowIfNull(form);
            ArgumentException.ThrowIfNullOrEmpty(clientId);

            form[OAuthRequestParameterNames.ClientId] = clientId;

            if(clientSecretUtf8.Length > 0)
            {
                form[OAuthRequestParameterNames.ClientSecret] = Encoding.UTF8.GetString(clientSecretUtf8);
            }

            return form;
        }
    }
}
