using Verifiable.Core;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;

namespace Verifiable.OAuth;

/// <summary>
/// Supplies the signing algorithms discovery advertises for a protocol usage.
/// </summary>
/// <param name="registration">The registration whose metadata is being composed.</param>
/// <param name="usage">The protocol usage whose supported algorithms are requested.</param>
/// <param name="context">The per-request context passed to discovery composition.</param>
/// <param name="cancellationToken">Cancellation token for the resolution operation.</param>
/// <returns>
/// The supported JWA identifiers in publication order. An empty list omits the
/// member; it does not request fallback to the default.
/// </returns>
/// <remarks>
/// <para>
/// Set <see cref="AuthorizationServerCryptography.ResolveSupportedSigningAlgorithmsAsync"/>
/// beside <see cref="AuthorizationServerCryptography.SelectSigningKey"/> and the
/// key resolvers. Derive names from key material tags through
/// <see cref="CryptoFormatConversions.DefaultTagToJwaConverter"/>. The list
/// describes all algorithms offered for the usage, independently of the single
/// key selected for a particular consumer.
/// </para>
/// <para>
/// The same input feeds both OAuth authorization server metadata and OpenID
/// provider configuration. Discovery asks only for members it already composes:
/// <see cref="KeyUsageContext.IdTokenIssuance"/>,
/// <see cref="KeyUsageContext.AuthorizationResponseSigning"/>,
/// <see cref="KeyUsageContext.IntrospectionResponseSigning"/>,
/// <see cref="KeyUsageContext.DpopProof"/> and
/// <see cref="KeyUsageContext.ClientAssertion"/>. The last two describe signatures
/// accepted from clients. Existing endpoint and validation gates still apply;
/// supplying algorithms does not introduce a request-object or other new member.
/// The <see cref="KeyUsageContext.ClientAssertion"/> list is also the set the validators
/// <see cref="PrivateKeyJwtClientAuthentication"/> builds hold a client assertion's
/// <c>alg</c> to, so what discovery publishes is what client authentication accepts.
/// </para>
/// <para>
/// When no delegate is supplied, <see cref="DefaultSupportedSigningAlgorithms.ResolveAsync"/>
/// preserves the library's existing declarations. A host may call that helper
/// for usages it does not override, passing the integration admitted for the request.
/// </para>
/// </remarks>
public delegate ValueTask<IReadOnlyList<string>> ResolveSupportedSigningAlgorithmsDelegate(
    ClientRecord registration,
    KeyUsageContext usage,
    ExchangeContext context,
    CancellationToken cancellationToken);
