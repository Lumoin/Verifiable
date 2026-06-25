using Verifiable.Core;
using Verifiable.JCose;

using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// An optional application-supplied delegate that classifies a raw token
/// string into a typed <see cref="JoseTokenShape"/> by structural inspection.
/// </summary>
/// <remarks>
/// <para>
/// The dispatch-time wrapper around
/// <see cref="JoseTokenClassifier.ClassifyAsync"/> from
/// <see cref="Verifiable.JCose"/>. Token-aware matchers — introspection,
/// revocation, userinfo, OID4VCI proof, end-session — call this delegate
/// when they receive a token in the inbound request and need to know its
/// shape before routing to the right handler.
/// </para>
/// <para>
/// The return type is the JCose-defined <see cref="JoseTokenShape"/>:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="JwsShape"/> — three-segment compact JWS.</description></item>
/// <item><description><see cref="JweShape"/> — five-segment compact JWE.</description></item>
/// <item><description><see cref="OpaqueShape"/> — anything else non-empty.</description></item>
/// <item><description><see cref="MalformedShape"/> — empty input or structurally inconsistent.</description></item>
/// </list>
/// <para>
/// <strong>Why the OAuth-side wrapper exists.</strong>
/// <see cref="JoseTokenClassifier.ClassifyAsync"/> is a pure JCose-level
/// operation and does not take a <see cref="ExchangeContext"/>. Some
/// applications need per-request context to drive deployment-specific
/// classification — for example, distinguishing tenant-specific opaque
/// token formats, or recognizing non-JOSE shapes (paseto, biscuit) that
/// only certain tenants issue. This delegate's signature includes
/// <see cref="ExchangeContext"/> so applications can inspect it; wiring
/// implementations that don't need it simply ignore the parameter and
/// forward to the JCose classifier directly.
/// </para>
/// <para>
/// <strong>Why the slot is optional.</strong>
/// Endpoints whose matchers do not consume tokens — PAR, JAR, direct_post,
/// JWKS, discovery — run without this delegate set. Token-aware matchers
/// (userinfo, introspection, revocation, OID4VCI proof) require
/// it; their builders fail validation when the slot is null.
/// </para>
/// <para>
/// <strong>Trust boundary.</strong>
/// Classification is structural only. Reading any header parameter from a
/// returned <see cref="JwsShape"/> or <see cref="JweShape"/> before
/// signature verification or AEAD decryption is reading attacker-controlled
/// data. The trust-marker types in <see cref="JoseTokenShape"/>'s subtypes
/// (<see cref="UnverifiedJwsMessage"/>, <see cref="UnverifiedCompactJwe"/>,
/// <see cref="UnverifiedJwtHeader"/>) carry the warning at the type level
/// throughout the dispatch pipeline.
/// </para>
/// <para>
/// <strong>Cancellation.</strong>
/// Implementations must honor <paramref name="cancellationToken"/>. A
/// classifier that ignores cancellation gives hostile inbound requests an
/// avenue for resource exhaustion.
/// </para>
/// </remarks>
/// <param name="token">
/// The raw token string from the request. Attacker-controlled bytes;
/// no parsing or trust assumptions allowed before classification.
/// </param>
/// <param name="context">
/// The per-request context. Classifiers may read tenant or request data
/// when classification depends on deployment configuration.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The classified token. Always non-<see langword="null"/>; malformed
/// inputs produce <see cref="MalformedShape"/> rather than null.
/// </returns>
public delegate ValueTask<JoseTokenShape> ClassifyTokenDelegate(
    string token,
    ExchangeContext context,
    CancellationToken cancellationToken);
