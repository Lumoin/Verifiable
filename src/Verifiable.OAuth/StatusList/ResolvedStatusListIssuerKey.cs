using System;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.StatusList;

/// <summary>
/// A <see cref="ResolveStatusListIssuerKeyDelegate"/>'s answer: the public key a Status List Token's
/// signature is checked under, together with whether releasing that key is the verification's job.
/// </summary>
/// <remarks>
/// <para>
/// The same declaration <see cref="Verifiable.Core.StatusList.ResolvedStatusListToken.IsTokenOwned"/>
/// makes for the resolved token, made for the key. A resolver that mints a key per call — a
/// <c>did:web</c> document fetched and decoded on the spot, an X.509 chain validated into a fresh leaf
/// key — hands back an <see cref="Owned(PublicKeyMemory)"/> key: nothing else holds it, so
/// <see cref="Dispose"/> is the only release its pooled buffer gets, and
/// <see cref="StatusListTokenVerification.VerifyAsync"/> calls it on every path once the key is
/// resolved. A resolver that answers from a key set it keeps alive itself hands back a
/// <see cref="Borrowed(PublicKeyMemory)"/> key, which the verification never touches.
/// </para>
/// <para>
/// A carrier with reference identity, not a value: it owns a disposal decision and a mutable
/// disposal state, and an equality synthesized over that state would change what an instance equals
/// and hashes to at the moment <see cref="Dispose"/> runs. Two resolutions of the same key are two
/// distinct lifetimes and compare as such.
/// </para>
/// </remarks>
public sealed class ResolvedStatusListIssuerKey: IDisposable
{
    /// <summary>The public key the Status List Token's signature is verified under.</summary>
    public required PublicKeyMemory Key { get; init; }

    /// <summary>
    /// Whether <see cref="Key"/>'s pooled memory is this resolution's to release on
    /// <see cref="Dispose"/>. <see langword="false"/> when the resolver keeps the key alive itself and
    /// only lent it for the verification.
    /// </summary>
    public required bool IsKeyOwned { get; init; }

    /// <summary>
    /// Whether <see cref="Dispose"/> has already run on this resolution, so a second call releases
    /// nothing.
    /// </summary>
    private bool isDisposed;

    /// <summary>
    /// Releases <see cref="Key"/> when <see cref="IsKeyOwned"/> is <see langword="true"/>; otherwise a
    /// no-op. Idempotent — safe to call more than once.
    /// </summary>
    public void Dispose()
    {
        if(!isDisposed && IsKeyOwned)
        {
            Key.Dispose();
        }

        isDisposed = true;
    }

    /// <summary>
    /// A key the verification releases once it is done with it — the answer a resolver that mints a key
    /// per call gives.
    /// </summary>
    /// <param name="key">The freshly minted key.</param>
    /// <returns>The owned resolution.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <see langword="null"/>.</exception>
    public static ResolvedStatusListIssuerKey Owned(PublicKeyMemory key)
    {
        ArgumentNullException.ThrowIfNull(key);

        return new ResolvedStatusListIssuerKey { Key = key, IsKeyOwned = true };
    }

    /// <summary>
    /// A key the verification only reads — the answer a resolver that owns the key's lifetime itself
    /// (a key set, a tenant record, the Referenced Token's own issuer key) gives.
    /// </summary>
    /// <param name="key">The key lent for the verification.</param>
    /// <returns>The borrowed resolution.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <see langword="null"/>.</exception>
    public static ResolvedStatusListIssuerKey Borrowed(PublicKeyMemory key)
    {
        ArgumentNullException.ThrowIfNull(key);

        return new ResolvedStatusListIssuerKey { Key = key, IsKeyOwned = false };
    }
}
