using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Server;

/// <summary>
/// A rotation-aware collection of key identifiers for a single protocol usage
/// context. One of these is attached to a <see cref="ClientRegistration"/> per
/// active <see cref="Verifiable.Cryptography.Context.KeyUsageContext"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Rotation lifecycle</strong>
/// </para>
/// <para>
/// A key participating in signing for an authorization server passes through
/// three publicly-visible states plus an optional post-publication state:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="Incoming"/> — pre-published. Appears in JWKS so relying
///       parties can cache the key before the first token signed with it
///       appears. Does not sign yet. Verifies tokens that shouldn't yet exist
///       (defensive, but correct if they appear after the cutover is observed
///       elsewhere).
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="Current"/> — actively signing. Appears in JWKS. Verifies
///       tokens it has signed. For algorithm-agile tenants this is a list: one
///       <see cref="KeyId"/> per algorithm in concurrent use (e.g., ES256 and
///       ML-DSA during a PQ migration).
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="Retiring"/> — no longer signing, still publishing. Appears
///       in JWKS during the rotation grace period so relying parties can still
///       verify tokens that were signed just before the cutover and may still
///       be in flight. Verifies.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="Historical"/> — no longer appears in JWKS but remains
///       resolvable for verification of long-lived or audit-replay tokens.
///       Optional — many deployments drop keys entirely after the grace window.
///     </description>
///   </item>
/// </list>
/// <para>
/// <strong>Usage model</strong>
/// </para>
/// <para>
/// The library's default behaviour when signing for a given
/// <see cref="Verifiable.Cryptography.Context.KeyUsageContext"/>: pick one
/// <see cref="KeyId"/> from <see cref="Current"/> — typically the first, or the
/// one whose algorithm matches the requested signing algorithm. Applications
/// that need finer control — per-caller binding, weighted rotation,
/// region-specific selection — override the
/// <see cref="SelectSigningKeyDelegate"/> on
/// <see cref="AuthorizationServerOptions"/>.
/// </para>
/// <para>
/// The library's default behaviour when publishing JWKS: emit <see cref="Incoming"/>,
/// <see cref="Current"/>, and <see cref="Retiring"/>. Omit <see cref="Historical"/>.
/// Applications that need different publication rules write them into their
/// <see cref="AuthorizationServerOptions.BuildJwksDocumentAsync"/> body.
/// </para>
/// <para>
/// <strong>Multi-algorithm concurrency</strong>
/// </para>
/// <para>
/// <see cref="Current"/>, <see cref="Incoming"/>, and <see cref="Retiring"/> are
/// lists to accommodate tenants that sign with multiple algorithms at once. A
/// tenant migrating to post-quantum signatures may carry two current signing
/// keys — one ES256, one ML-DSA — so that relying parties accepting either
/// algorithm see a valid signature. Single-algorithm tenants use lists of one.
/// </para>
/// </remarks>
[DebuggerDisplay("SigningKeySet Current={Current.Count} Incoming={Incoming.Count} Retiring={Retiring.Count} Historical={Historical.Count}")]
public sealed record SigningKeySet
{
    /// <summary>
    /// The keys currently used for signing. For algorithm-agile tenants this
    /// contains one key per concurrent algorithm; for single-algorithm tenants
    /// it contains one key. Must be non-empty in any set representing an
    /// actively-used usage context.
    /// </summary>
    public required ImmutableList<KeyId> Current { get; init; }

    /// <summary>
    /// Keys pre-published in JWKS ahead of their activation. Relying parties
    /// that cache the JWKS will have these keys available before the first
    /// token signed with them appears.
    /// </summary>
    public ImmutableList<KeyId> Incoming { get; init; } = [];

    /// <summary>
    /// Keys that have been rotated out of signing but remain published in
    /// JWKS during the rotation grace period. Tokens signed just before the
    /// cutover remain verifiable for the duration of the grace window.
    /// </summary>
    public ImmutableList<KeyId> Retiring { get; init; } = [];

    /// <summary>
    /// Keys no longer published in JWKS but still resolvable for verification
    /// of long-lived or audit-replay tokens. The library does not reference
    /// this list when emitting JWKS by default; applications that need
    /// post-publication verification capability keep keys here and consult the
    /// list in their verification-key resolution delegate.
    /// </summary>
    public ImmutableList<KeyId> Historical { get; init; } = [];


    /// <summary>
    /// Returns the union of <see cref="Incoming"/>, <see cref="Current"/>, and
    /// <see cref="Retiring"/> — the keys that should be published in JWKS for
    /// this usage context under default rotation publication rules.
    /// </summary>
    public IEnumerable<KeyId> PublishedKeys
    {
        get
        {
            foreach(KeyId keyId in Incoming)
            {
                yield return keyId;
            }
            foreach(KeyId keyId in Current)
            {
                yield return keyId;
            }
            foreach(KeyId keyId in Retiring)
            {
                yield return keyId;
            }
        }
    }


    /// <summary>
    /// Returns the union of all four lists — every <see cref="KeyId"/> the
    /// verification path might encounter. Used by verification-key resolvers
    /// that accept any key this tenant has ever signed with within the
    /// retention window.
    /// </summary>
    public IEnumerable<KeyId> AllKnownKeys
    {
        get
        {
            foreach(KeyId keyId in Incoming)
            {
                yield return keyId;
            }
            foreach(KeyId keyId in Current)
            {
                yield return keyId;
            }
            foreach(KeyId keyId in Retiring)
            {
                yield return keyId;
            }
            foreach(KeyId keyId in Historical)
            {
                yield return keyId;
            }
        }
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="keyId"/> is currently
    /// signing. Callers use this to decide whether a signing selection is valid
    /// — per-caller selection delegates that return a <see cref="KeyId"/> not in
    /// <see cref="Current"/> indicate misconfiguration.
    /// </summary>
    public bool IsCurrent(KeyId keyId) => Current.Contains(keyId);
}
