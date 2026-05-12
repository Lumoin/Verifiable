using Verifiable.Core.Dcql;
using Verifiable.Cryptography;

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
public sealed record SignJarAction(
    string ParHandle,
    TransactionNonce Nonce,
    PreparedDcqlQuery Query,
    KeyId SigningKeyId): OAuthAction;
