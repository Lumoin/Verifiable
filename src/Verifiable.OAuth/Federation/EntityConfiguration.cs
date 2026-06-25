using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// A self-issued Entity Statement per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1">Federation §3.1</see>.
/// An Entity Configuration has <c>iss</c> == <c>sub</c> and MUST carry
/// a <c>jwks</c> claim with the entity's own signing keys.
/// </summary>
/// <remarks>
/// <para>
/// Published by every Federation entity at
/// <c>/.well-known/openid-federation</c> per Federation §9. Trust anchors,
/// intermediates, and leaves all publish Entity Configurations; the
/// shape is identical, only the <c>metadata</c> per-entity-type contents
/// and the presence of <c>authority_hints</c> differ.
/// </para>
/// <para>
/// Validation of the <c>jwks</c>-presence invariant happens via the
/// <see cref="WellKnownFederationClaimIds.JwksPresentWhenSelfSigned"/>
/// check; this record holds the structural classification only.
/// </para>
/// </remarks>
[DebuggerDisplay("EntityConfiguration Iss=Sub={Issuer,nq}")]
public sealed record EntityConfiguration: EntityStatement;
