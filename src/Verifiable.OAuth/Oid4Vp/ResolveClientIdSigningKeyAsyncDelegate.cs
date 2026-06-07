using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Resolves the Verifier's JAR signing public key for a given OID4VP
/// <c>client_id</c> (including prefix) and JAR header. The wallet wires one
/// slot; the deployment composes a handler that dispatches to the
/// appropriate underlying resolver based on the
/// <see cref="WellKnownClientIdPrefixes"/> prefix in <paramref name="clientId"/>.
/// </summary>
/// <param name="context">
/// The threaded per-operation <see cref="ExchangeContext"/>. Carries the
/// per-tenant trust material the handler evaluates against (placed by the
/// application via <see cref="Oid4VpExchangeContextExtensions"/>) and the
/// <see cref="ExchangeContextExtensions.ValidationTime"/> at which to evaluate
/// trust-material validity, stamped by the operation driver. Threading the
/// material through the context — rather than capturing it — lets one stateless
/// resolver serve every tenant in a recursive multi-tenant deployment.
/// </param>
/// <param name="clientId">
/// The full <c>client_id</c> from the JAR, including the prefix (e.g.
/// <c>openid_federation:https://verifier.example.com</c>,
/// <c>x509_san_dns:verifier.example.com</c>,
/// <c>verifier_attestation:https://verifier.example.com</c>).
/// </param>
/// <param name="jarHeader">
/// The JAR's JWS protected header. Different prefixes consume different
/// header parameters: <c>x5c</c> for X.509,
/// <see cref="WellKnownFederationClaimNames.TrustChain"/> for OpenID
/// Federation, <see cref="WellKnownJoseHeaderNames.Jwt"/> for verifier
/// attestation. <c>kid</c> may also be consulted when the prefix's
/// underlying resolver picks among multiple candidate keys.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>
/// The Verifier's JAR signing key. The caller owns the returned
/// <see cref="PublicKeyMemory"/> and is responsible for disposing it
/// after the JAR signature-verification call.
/// </returns>
/// <remarks>
/// <para>
/// Unifies the three HAIP-mandatory plus the federation client identifier
/// prefixes behind a single signature so the wallet's PDA flow doesn't
/// branch on prefix. <see cref="CompositeClientIdSigningKeyResolver"/>
/// provides the standard prefix-dispatching implementation; deployments
/// register handlers for the prefixes they support.
/// </para>
/// </remarks>
public delegate ValueTask<PublicKeyMemory> ResolveClientIdSigningKeyAsyncDelegate(
    ExchangeContext context,
    string clientId,
    UnverifiedJwtHeader jarHeader,
    CancellationToken cancellationToken);
