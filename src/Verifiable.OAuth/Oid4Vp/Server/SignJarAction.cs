using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Action produced by <see cref="States.VerifierParReceivedState"/> indicating that
/// the JAR must be signed before the flow can advance to
/// <see cref="States.VerifierJarServedState"/>.
/// </summary>
/// <remarks>
/// Carries exactly the per-flow values needed to build and sign the JAR.
/// Per-registration static values — <c>client_id</c>, <c>response_uri</c>,
/// <c>client_metadata</c> — are resolved by the handler from
/// <see cref="Verifiable.OAuth.Server.ClientRecord"/>. JWT timing claim
/// values (<c>iat</c>, <c>nbf</c>, <c>exp</c>) are computed by the handler from
/// <see cref="Verifiable.OAuth.Server.TimingPolicy.Oid4VpRequestObjectLifetime"/>
/// at sign time.
/// </remarks>
/// <param name="ParHandle">
/// The opaque per-flow token. The handler writes it as the JAR's <c>state</c>
/// claim per RFC 6749 §4.1.1 / RFC 9700 §4.7. The Wallet echoes the value as
/// the <c>state</c> form field in the direct_post per OID4VP 1.0 §6.1, and
/// the application's
/// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration.ResolveCorrelationKeyAsync"/>
/// maps it back to the internal flow identifier.
/// </param>
/// <param name="Nonce">The transaction nonce to embed in the JAR.</param>
/// <param name="Query">The prepared DCQL query to embed in the JAR.</param>
/// <param name="SigningKeyId">
/// The identifier of the signing key. The handler resolves this to live key material
/// via <see cref="Verifiable.OAuth.Server.AuthorizationServerCryptography.SigningKeyResolver"/>.
/// </param>
/// <param name="WalletNonce">
/// The <c>wallet_nonce</c> value to echo as a JAR claim per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.
/// <see langword="null"/> on the <c>request_uri_method=get</c> path; non-null
/// when produced from <see cref="States.VerifierWalletPostReceivedState"/>.
/// </param>
/// <param name="TransactionData">
/// Optional <c>transaction_data</c> descriptors to bind into the JAR per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4">OID4VP 1.0 §8.4</see>.
/// </param>
/// <param name="AdditionalHeaderClaims">
/// Optional additional JOSE header claims to merge into the JAR header per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3">OID4VP 1.0 §5.9.3</see>
/// — the <c>trust_chain</c> array for the <c>openid_federation:</c> prefix,
/// the <c>x5c</c> array for <c>x509_san_dns:</c>, the <c>jwt</c> attestation
/// for <c>verifier_attestation:</c>.
/// </param>
/// <param name="ResponseMode">
/// Optional <c>response_mode</c> override on the JAR.
/// <see langword="null"/> defers to <c>direct_post.jwt</c> (HAIP 1.0 §5.1).
/// </param>
/// <param name="WalletEncryptionJwksJson">
/// Optional Wallet JWKS JSON text — the value of the <c>jwks</c> member of
/// <c>wallet_metadata</c> as it arrived on the request_uri_method=post body
/// per <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.
/// When non-null the executor JWE-wraps the signed JWS using the public
/// exchange key extracted from this JWKS.
/// </param>
/// <param name="JarEncryptionEnc">
/// Optional content-encryption algorithm (JWA <c>enc</c>) the executor uses
/// when JWE-wrapping the JAR. Ignored when
/// <paramref name="WalletEncryptionJwksJson"/> is <see langword="null"/>.
/// <see langword="null"/> defers to
/// <see cref="Verifiable.JCose.WellKnownJweEncryptionAlgorithms.A128Gcm"/>.
/// </param>
public sealed record SignJarAction(
    string ParHandle,
    TransactionNonce Nonce,
    PreparedDcqlQuery Query,
    KeyId SigningKeyId,
    string? WalletNonce = null,
    IReadOnlyList<string>? TransactionData = null,
    JwtHeader? AdditionalHeaderClaims = null,
    string? ResponseMode = null,
    string? WalletEncryptionJwksJson = null,
    string? JarEncryptionEnc = null): OAuthAction;
