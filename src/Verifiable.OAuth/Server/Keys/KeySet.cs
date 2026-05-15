using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.OAuth.Server.Keys;

/// <summary>
/// A rotation-aware set of keys parameterized over the key material type.
/// Used for symmetric HMAC keys (<c>KeySet&lt;HmacKey&gt;</c>) and any future
/// key types that the library composes (e.g. MTLS X.509 chains,
/// post-quantum signing material).
/// </summary>
/// <remarks>
/// <para>
/// Slot semantics:
/// </para>
/// <list type="bullet">
///   <item><see cref="Incoming"/> — pre-published; appears in publication
///         surface (JWKS, CWKS); NOT used for new issuance / signing / MAC;
///         verifiers may fetch and cache. Provides a fetch window before
///         the key becomes active.</item>
///   <item><see cref="Current"/> — actively used for new issuance and for verification.</item>
///   <item><see cref="Retiring"/> — no longer used for new issuance; still valid for
///         verification of artefacts produced under it during its <c>Current</c>
///         window; still appears in publication surface.</item>
///   <item><see cref="Historical"/> — archived; NOT valid for verification; does NOT
///         appear in publication. Provides audit-trail shape without operational
///         meaning.</item>
/// </list>
/// <para>
/// Slot promotions (<c>Incoming → Current</c>, <c>Current → Retiring</c>,
/// <c>Retiring → Historical</c>) are application-driven; the library doesn't
/// ship a scheduler. Single-instance deployments wire transitions via
/// configuration or admin commands; multi-instance deployments coordinate via
/// a shared secret store or KMS key versions.
/// </para>
/// <para>
/// The signing-key side of the library uses the analogous identifier-slot
/// abstraction <see cref="SigningKeySet"/>, which stores <c>KeyId</c> values
/// (with material loaded lazily via <see cref="AuthorizationServerCryptography.SigningKeyResolver"/>)
/// to support HSM/KMS-backed key flows. <c>KeySet&lt;TKey&gt;</c> stores
/// material-bearing records directly and is the right shape for in-process
/// HMAC keys where the symmetric material lives in the application's process
/// memory anyway.
/// </para>
/// </remarks>
[DebuggerDisplay("KeySet Incoming={Incoming.Count} Current={Current.Count} Retiring={Retiring.Count} Historical={Historical.Count}")]
public sealed record KeySet<TKey> where TKey : class, IRotatableKey
{
    /// <summary>
    /// Keys pre-published in the publication surface ahead of activation.
    /// </summary>
    public ImmutableList<TKey> Incoming { get; init; } = [];

    /// <summary>
    /// Keys currently used for new issuance and accepted for verification.
    /// </summary>
    public ImmutableList<TKey> Current { get; init; } = [];

    /// <summary>
    /// Keys rotated out of issuance but still accepted for verification
    /// during the grace window. Continue to appear in the publication surface.
    /// </summary>
    public ImmutableList<TKey> Retiring { get; init; } = [];

    /// <summary>
    /// Keys archived after the grace window. Not accepted for verification
    /// and not published.
    /// </summary>
    public ImmutableList<TKey> Historical { get; init; } = [];


    /// <summary>
    /// Enumerates keys valid for verification: <see cref="Current"/> + <see cref="Retiring"/>.
    /// <see cref="Incoming"/> is excluded (pre-published but not yet active);
    /// <see cref="Historical"/> is excluded (archived).
    /// </summary>
    public IEnumerable<TKey> ValidForVerification()
    {
        foreach(TKey key in Current) { yield return key; }
        foreach(TKey key in Retiring) { yield return key; }
    }


    /// <summary>
    /// Enumerates keys visible in publication surface (JWKS / CWKS):
    /// <see cref="Incoming"/> + <see cref="Current"/> + <see cref="Retiring"/>.
    /// <see cref="Historical"/> is excluded.
    /// </summary>
    public IEnumerable<TKey> Publishable()
    {
        foreach(TKey key in Incoming) { yield return key; }
        foreach(TKey key in Current) { yield return key; }
        foreach(TKey key in Retiring) { yield return key; }
    }


    /// <summary>
    /// Returns <see langword="true"/> when a key with <paramref name="kid"/>
    /// is in <see cref="Current"/> or <see cref="Retiring"/> — the slots
    /// accepted for verification. Used by validation paths after the
    /// byte-loader has produced material for the kid, to confirm the kid
    /// is in an operationally-valid slot.
    /// </summary>
    public bool IsKidValidForVerification(string kid)
    {
        foreach(TKey key in Current)
        {
            if(string.Equals(key.Kid, kid, StringComparison.Ordinal)) { return true; }
        }
        foreach(TKey key in Retiring)
        {
            if(string.Equals(key.Kid, kid, StringComparison.Ordinal)) { return true; }
        }
        return false;
    }
}
