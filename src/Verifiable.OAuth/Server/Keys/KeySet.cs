using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Server.Keys;

/// <summary>
/// A rotation-aware collection of <see cref="KeyId"/> values for a single
/// key-bearing role (typically symmetric HMAC keys). Structurally mirrors
/// <see cref="SigningKeySet"/>: slots hold identifiers; material is loaded
/// on demand via the role-appropriate byte-loading delegate.
/// </summary>
/// <remarks>
/// <para>
/// Slot semantics:
/// </para>
/// <list type="bullet">
///   <item><see cref="Incoming"/> — pre-published; appears in publication
///         surface (JWKS, CWKS); NOT used for new issuance / signing / MAC.
///         Provides a fetch window before the key becomes active.</item>
///   <item><see cref="Current"/> — actively used for new issuance and for verification.</item>
///   <item><see cref="Retiring"/> — no longer used for new issuance; still
///         valid for verification of artefacts produced under it during its
///         <c>Current</c> window; still published.</item>
///   <item><see cref="Historical"/> — archived; NOT valid for verification;
///         does NOT appear in publication.</item>
/// </list>
/// <para>
/// Slot promotions are application-driven; the library doesn't ship a
/// scheduler. The library's byte-loaders accept any <see cref="KeyId"/>
/// and don't gate on slot membership — verifiability gating happens at
/// validation time via <see cref="IsKidValidForVerification"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("KeySet Incoming={Incoming.Count} Current={Current.Count} Retiring={Retiring.Count} Historical={Historical.Count}")]
public sealed record KeySet
{
    /// <summary>Keys pre-published ahead of activation; not yet used for issuance.</summary>
    public ImmutableList<KeyId> Incoming { get; init; } = [];

    /// <summary>Keys currently used for new issuance and accepted for verification.</summary>
    public ImmutableList<KeyId> Current { get; init; } = [];

    /// <summary>
    /// Keys rotated out of issuance but still accepted for verification
    /// during the grace window.
    /// </summary>
    public ImmutableList<KeyId> Retiring { get; init; } = [];

    /// <summary>Keys archived after the grace window; not accepted for verification.</summary>
    public ImmutableList<KeyId> Historical { get; init; } = [];


    /// <summary>
    /// Enumerates kids valid for verification: <see cref="Current"/> + <see cref="Retiring"/>.
    /// </summary>
    public IEnumerable<KeyId> ValidForVerification()
    {
        foreach(KeyId kid in Current) { yield return kid; }
        foreach(KeyId kid in Retiring) { yield return kid; }
    }


    /// <summary>
    /// Enumerates kids visible in publication surface (JWKS / CWKS):
    /// <see cref="Incoming"/> + <see cref="Current"/> + <see cref="Retiring"/>.
    /// </summary>
    public IEnumerable<KeyId> Publishable()
    {
        foreach(KeyId kid in Incoming) { yield return kid; }
        foreach(KeyId kid in Current) { yield return kid; }
        foreach(KeyId kid in Retiring) { yield return kid; }
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="kid"/> is in
    /// <see cref="Current"/> or <see cref="Retiring"/> — the slots accepted
    /// for verification.
    /// </summary>
    public bool IsKidValidForVerification(KeyId kid)
    {
        foreach(KeyId k in Current)
        {
            if(k.Equals(kid)) { return true; }
        }
        foreach(KeyId k in Retiring)
        {
            if(k.Equals(kid)) { return true; }
        }
        return false;
    }
}
