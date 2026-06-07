using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Configuration for JWS-envelope (JOSE) signing on a <see cref="CredentialBuilder"/>.
/// </summary>
/// <remarks>
/// <para>
/// Captures the signing parameters that are fixed across multiple builds —
/// the private key, verification method, and codec wiring. Per-build
/// parameters (issuer, subject, validity period) are supplied at
/// <see cref="CredentialBuilder.BuildJwsAsync(Issuer, CredentialSubjectInput, DateTime, CancellationToken)"/>
/// or
/// <see cref="CredentialBuilder.BuildJwsFullAsync(Issuer, CredentialSubjectInput, DateTime, IEnumerable{string}?, DateTime?, CancellationToken)"/>
/// time.
/// </para>
/// <para>
/// The config is set on the builder via
/// <see cref="CredentialBuilderExtensions.WithJoseSigning(CredentialBuilder, JoseSigningConfig)"/>.
/// <see cref="CredentialBuilder.BuildJwsAsync(Issuer, CredentialSubjectInput, DateTime, CancellationToken)"/>
/// reads the config, builds a credential, and produces a
/// <see cref="JwsMessage"/> wrapping it.
/// </para>
/// <para>
/// Unlike Data Integrity proofs, the JWS envelope does not embed a proof in
/// the credential JSON; the entire credential becomes the JWS payload. The
/// algorithm is derived from <see cref="PrivateKey"/>'s
/// <see cref="Tag"/>; the cryptosuite is implicit in the key.
/// </para>
/// </remarks>
[DebuggerDisplay("JoseSigningConfig VerificationMethodId={VerificationMethodId,nq}")]
public sealed record JoseSigningConfig
{
    /// <summary>
    /// The private key material used to sign the JWS. The key's
    /// <see cref="Tag"/> determines the JWS <c>alg</c> header value.
    /// </summary>
    public required PrivateKeyMemory PrivateKey { get; init; }

    /// <summary>
    /// The DID URL identifying the verification method that resolves to the
    /// public counterpart of <see cref="PrivateKey"/>, written into the
    /// JWS <c>kid</c> header.
    /// </summary>
    public required string VerificationMethodId { get; init; }

    /// <summary>
    /// Serializes a <see cref="VerifiableCredential"/> into the JSON bytes
    /// that become the JWS payload.
    /// </summary>
    public required CredentialToJsonBytesDelegate CredentialSerializer { get; init; }

    /// <summary>
    /// Serializes the JWS protected header into JSON bytes.
    /// </summary>
    public required JwtHeaderSerializer HeaderSerializer { get; init; }

    /// <summary>
    /// Base64Url encoder applied to the protected header, payload, and
    /// signature segments per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-3.1">RFC 7515 §3.1</see>.
    /// </summary>
    public required EncodeDelegate Base64UrlEncoder { get; init; }

    /// <summary>
    /// Memory pool for signature allocations. Production deployments
    /// typically pass <c>SensitiveMemoryPool&lt;byte&gt;.Shared</c>; tests may
    /// inject a different pool for instrumentation.
    /// </summary>
    public required MemoryPool<byte> MemoryPool { get; init; }

    /// <summary>
    /// Optional media type for the JWS <c>typ</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>.
    /// Common values include <c>"vc+jwt"</c> for VC-JWT envelopes.
    /// </summary>
    public string? MediaType { get; init; }

    /// <summary>
    /// Optional content type for the JWS <c>cty</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.10">RFC 7515 §4.1.10</see>.
    /// </summary>
    public string? ContentType { get; init; }
}
