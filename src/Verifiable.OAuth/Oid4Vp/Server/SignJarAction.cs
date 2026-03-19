using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.OAuth;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Action produced by <see cref="States.VerifierParReceivedState"/> indicating that
/// the JAR must be signed before the flow can advance to
/// <see cref="States.VerifierJarReady"/>.
/// </summary>
/// <remarks>
/// Carries exactly the per-flow values needed to build and sign the JAR.
/// Per-registration static values — <c>client_id</c>, <c>response_uri</c>,
/// <c>client_metadata</c> — are resolved by the handler from
/// <see cref="Verifiable.OAuth.Server.ClientRegistration"/>.
/// </remarks>
/// <param name="Nonce">The transaction nonce to embed in the JAR.</param>
/// <param name="Query">The prepared DCQL query to embed in the JAR.</param>
/// <param name="SigningKeyId">
/// The identifier of the signing key. The handler resolves this to live key material
/// via <see cref="Verifiable.OAuth.Server.AuthorizationServerOptions.SigningKeyResolver"/>.
/// </param>
public sealed record SignJarAction(
    TransactionNonce Nonce,
    PreparedDcqlQuery Query,
    KeyId SigningKeyId): OAuthAction;
