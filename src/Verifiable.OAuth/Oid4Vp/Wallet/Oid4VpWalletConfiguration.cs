using System.Buffers;
using System.Diagnostics;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.JCose;
using Verifiable.JCose.Sd;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Wallet-specific configuration carrying the delegates an
/// <see cref="Oid4VpWalletClient{TCredential}"/> uses to parse the inbound JAR,
/// sign the KB-JWT, encrypt the response, and resolve candidate credentials.
/// </summary>
/// <typeparam name="TCredential">
/// The application-supplied credential type. For SD-JWT VC use
/// <see cref="SdJwtVcCredential"/> or a derived type.
/// </typeparam>
/// <remarks>
/// Bundles wallet plumbing in one record rather than fanning the delegates
/// across <see cref="Client.OAuthClientInfrastructure"/>. The wallet's surface stays
/// self-contained; the shared <see cref="Client.OAuthClientInfrastructure"/> exposes
/// only the flow-agnostic identifiers and transport delegates that every
/// client surface shares.
/// </remarks>
[DebuggerDisplay("Oid4VpWalletConfiguration")]
public sealed record Oid4VpWalletConfiguration<TCredential> where TCredential : SdJwtVcCredential
{
    /// <summary>
    /// Returns the wallet-held credentials that satisfy the inbound JAR's DCQL
    /// query.
    /// </summary>
    public required ResolveCandidateCredentialsDelegate<TCredential> ResolveCandidateCredentials { get; init; }

    /// <summary>Base64url decoder used when parsing the JAR and the holder's stored SD-JWT.</summary>
    public required DecodeDelegate Base64UrlDecoder { get; init; }

    /// <summary>Serialises a <see cref="JwtHeader"/> to UTF-8 JSON bytes for KB-JWT and JWE-header signing.</summary>
    public required JwtHeaderSerializer JwtHeaderSerializer { get; init; }

    /// <summary>Serialises a <see cref="JwtPayload"/> to UTF-8 JSON bytes for KB-JWT signing and <c>vp_token</c> wrapping.</summary>
    public required JwtPayloadSerializer JwtPayloadSerializer { get; init; }

    /// <summary>Deserialises the JAR's protected header bytes into a dictionary.</summary>
    public required Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> JarHeaderDeserializer { get; init; }

    /// <summary>Deserialises the JAR's payload bytes into a dictionary.</summary>
    public required Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> JarPayloadDeserializer { get; init; }

    /// <summary>Deserialises the JAR's <c>dcql_query</c> claim from JSON.</summary>
    public required JarClaimDeserializer<DcqlQuery> DcqlQueryDeserializer { get; init; }

    /// <summary>Deserialises the JAR's <c>client_metadata</c> claim from JSON.</summary>
    public required JarClaimDeserializer<VerifierClientMetadata> ClientMetadataDeserializer { get; init; }

    /// <summary>Maps a key <see cref="Tag"/> to the JWK <c>crv</c> string for the JWE EPK header parameter.</summary>
    public required TagToEpkCrvDelegate TagToEpkCrvConverter { get; init; }

    /// <summary>ECDH-ES key agreement delegate for JWE encryption.</summary>
    public required KeyAgreementEncryptDelegate KeyAgreementEncrypt { get; init; }

    /// <summary>Concat KDF delegate per RFC 7518 §4.6.2.</summary>
    public required KeyDerivationDelegate KeyDerivation { get; init; }

    /// <summary>AES-GCM content encryption delegate for the JWE response.</summary>
    public required AeadEncryptDelegate AeadEncrypt { get; init; }

    /// <summary>
    /// Parses an SD-JWT compact string into a structured
    /// <see cref="SdToken{TEnvelope}"/>. Wired by the application to its SD-JWT
    /// implementation — typically <c>Verifiable.Json.Sd.SdJwtSerializer.ParseToken</c>
    /// with the wallet's salt tag, base64url decoder, and memory pool baked in.
    /// </summary>
    public required Func<string, SdToken<string>> ParseSdJwt { get; init; }

    /// <summary>
    /// Serialises an <see cref="SdToken{TEnvelope}"/> back to compact wire form
    /// — issuer JWS, all selected disclosures, optional KB-JWT, separated by
    /// <c>~</c>. Wired by the application to
    /// <c>Verifiable.Json.Sd.SdJwtSerializer.SerializeToken</c> with the
    /// wallet's base64url encoder baked in.
    /// </summary>
    public required Func<SdToken<string>, string> SerializeSdJwt { get; init; }

    /// <summary>
    /// Computes the <c>sd_hash</c> input string: the SD-JWT plus selected
    /// disclosures with a trailing tilde and no KB-JWT, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901#section-4.3">RFC 9901 §4.3</see>.
    /// Wired by the application to
    /// <c>Verifiable.Json.Sd.SdJwtSerializer.GetSdJwtForHashing</c>.
    /// </summary>
    public required Func<SdToken<string>, string> ComputeSdJwtHashInput { get; init; }

    /// <summary>Memory pool for transient cryptographic buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }
}
