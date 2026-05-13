using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Groups the encoding, decoding, hashing, and serialization delegates the
/// Authorization Server uses to convert between bytes and structured data.
/// </summary>
/// <remarks>
/// <para>
/// The library does not import any specific encoding or JSON library. Every
/// codec the library calls — Base64url, hash function selection, JWT header
/// and payload serialization — is supplied by the application as a delegate.
/// Wire from the library's coder and hash-function registries at startup, the
/// same way <see cref="Verifiable.Cryptography.CryptoLibrary"/> wires its
/// providers.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServerCodecs Validated={IsValidated}")]
public sealed class AuthorizationServerCodecs
{
    /// <summary>
    /// Base64url encoder delegate. Required. Used for PKCE code challenge
    /// computation, correlation key encoding, and any other place where the
    /// server produces Base64url-encoded values.
    /// </summary>
    public EncodeDelegate? Encoder { get; set; }

    /// <summary>
    /// Base64url decoder delegate. Required. Used for JWE header parsing, JWKS
    /// key coordinate decoding, and any other place where the server consumes
    /// Base64url-encoded values.
    /// </summary>
    public DecodeDelegate? Decoder { get; set; }

    /// <summary>
    /// Computes a digest. Required.
    /// Called at request time for PKCE S256 verification, authorization-code
    /// hashing, and any other digest computation. Allocates the digest from the
    /// supplied <see cref="System.Buffers.MemoryPool{T}"/>; the algorithm is
    /// carried in the <see cref="Tag"/> argument.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Wire to a provider-side implementation registered on
    /// <see cref="CryptographicKeyFactory"/>:
    /// </para>
    /// <code>
    /// codecs.ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync;
    /// </code>
    /// <para>
    /// The delegate's <see cref="Tag"/> argument carries the
    /// <see cref="System.Security.Cryptography.HashAlgorithmName"/>; the same
    /// server can therefore use SHA-256 for PKCE per RFC 7636 §4.2, SHA-512 for
    /// token binding, or post-quantum hash functions when specifications adopt
    /// them — the algorithm decision lives at the call site, not in the slot.
    /// </para>
    /// <para>
    /// Earlier versions of this group held a <c>HashFunctionSelector</c>
    /// returning a naked-bytes <c>HashFunction</c>. That surface has been
    /// deleted in favour of the pool-aware, semantic-typed
    /// <see cref="ComputeDigestDelegate"/>.
    /// </para>
    /// </remarks>
    public ComputeDigestDelegate? ComputeDigest { get; set; }

    /// <summary>
    /// Serializes a <see cref="JwtHeader"/> to UTF-8 JSON bytes. Required.
    /// </summary>
    /// <remarks>
    /// Wire to the application's chosen JSON library. The library does not
    /// import any JSON serialization library; the application decides whether
    /// <c>System.Text.Json</c>, <c>Utf8Json</c>, or another library is used,
    /// and supplies a delegate that calls it.
    /// </remarks>
    public JwtHeaderSerializer? JwtHeaderSerializer { get; set; }

    /// <summary>
    /// Serializes a <see cref="JwtPayload"/> to UTF-8 JSON bytes. Required.
    /// </summary>
    /// <remarks>
    /// Wire to the application's chosen JSON library. See
    /// <see cref="JwtHeaderSerializer"/> for the rationale.
    /// </remarks>
    public JwtPayloadSerializer? JwtPayloadSerializer { get; set; }

    /// <summary>
    /// Deserializes the protected header bytes of a compact JWS into a claim
    /// dictionary. Required when the AS consumes JWTs from the wire — for
    /// example, when an Authorization Code JAR arrives at the PAR or
    /// Authorize endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>.
    /// </summary>
    /// <remarks>
    /// Wire to the application's chosen JSON library. See
    /// <see cref="JwtHeaderSerializer"/> for the rationale on why
    /// the library does not import a JSON library directly.
    /// </remarks>
    public JwtHeaderDeserializer? JwtHeaderDeserializer { get; set; }

    /// <summary>
    /// Deserializes the payload bytes of a compact JWS into a claim
    /// dictionary. Required when the AS consumes JWTs from the wire.
    /// </summary>
    /// <remarks>
    /// Wire to the application's chosen JSON library. See
    /// <see cref="JwtHeaderSerializer"/> for the rationale.
    /// </remarks>
    public JwtPayloadDeserializer? JwtPayloadDeserializer { get; set; }


    /// <summary>
    /// Whether <see cref="Validate"/> has been called successfully on this group.
    /// </summary>
    public bool IsValidated { get; private set; }


    /// <summary>
    /// Validates that the required delegates on this group are set.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when one or more required delegates are missing.
    /// </exception>
    public void Validate()
    {
        var missing = new List<string>();

        if(Encoder is null) { missing.Add(nameof(Encoder)); }
        if(Decoder is null) { missing.Add(nameof(Decoder)); }
        if(ComputeDigest is null) { missing.Add(nameof(ComputeDigest)); }
        if(JwtHeaderSerializer is null) { missing.Add(nameof(JwtHeaderSerializer)); }
        if(JwtPayloadSerializer is null) { missing.Add(nameof(JwtPayloadSerializer)); }
        if(JwtHeaderDeserializer is null) { missing.Add(nameof(JwtHeaderDeserializer)); }
        if(JwtPayloadDeserializer is null) { missing.Add(nameof(JwtPayloadDeserializer)); }

        if(missing.Count > 0)
        {
            var sb = new StringBuilder(
                "AuthorizationServerCodecs is missing required delegates: ");
            sb.AppendJoin(", ", missing);
            sb.Append('.');
            throw new InvalidOperationException(sb.ToString());
        }

        IsValidated = true;
    }
}
