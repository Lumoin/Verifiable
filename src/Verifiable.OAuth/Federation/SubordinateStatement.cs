using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// A superior-issued Entity Statement per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1">Federation §3.1</see>.
/// A Subordinate Statement has <c>iss</c> != <c>sub</c>: the issuer is
/// the immediate superior of the subject (a Trust Anchor over an
/// Intermediate, an Intermediate over a Leaf, or an Intermediate over
/// another Intermediate).
/// </summary>
/// <remarks>
/// <para>
/// Carries the subject's <c>jwks</c> (so the chain can verify the
/// subject's Entity Configuration signature) and may carry
/// <c>metadata_policy</c> entries attenuating the subject's declared
/// metadata. Trust marks attesting to the subject's status, constraints
/// applied by the issuer, and the <c>source_endpoint</c> the statement
/// was fetched from also live here per Federation §3.1.2.
/// </para>
/// <para>
/// Fetched from the issuer's <c>federation_fetch_endpoint</c> in
/// HTTP-resolved chain construction (B.5), or carried inline in the
/// <c>trust_chain</c> JWS header per Federation §4.3 in the
/// inline-validation path (B.1's primary mode).
/// </para>
/// </remarks>
[DebuggerDisplay("SubordinateStatement Iss={Issuer,nq} Sub={Subject,nq}")]
public sealed record SubordinateStatement: EntityStatement;
