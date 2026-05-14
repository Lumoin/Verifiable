using System.Collections.Immutable;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Server;

/// <summary>
/// In-process default backing for <see cref="ResolveServerHmacKeyDelegate"/>.
/// Holds a current key and zero or more retired keys still acceptable for
/// validation. Supports rotation by hot-swap.
/// </summary>
/// <remarks>
/// <para>
/// Construction takes the initial current key + kid. Subsequent rotations
/// happen via <see cref="Rotate"/>, which moves the current key to the
/// retired set and installs the new key + kid as current. The retired set
/// has a configurable maximum size — older entries fall off the end on
/// rotation.
/// </para>
/// <para>
/// Single-instance and small-cluster deployments use this default
/// directly. Multi-instance deployments needing distributed key
/// management (Vault, KMS) wire their own
/// <see cref="ResolveServerHmacKeyDelegate"/> implementation. The
/// contract is the delegate; this is one implementation of it.
/// </para>
/// </remarks>
[DebuggerDisplay("InProcessHmacKeyResolver Current={currentKid,nq} Retired={retiredCount}")]
public sealed class InProcessHmacKeyResolver
{
    private readonly Lock rotateLock = new();
    private readonly int maxRetainedKeys;
    private string currentKid;
    private SymmetricKey currentKey;
    private ImmutableDictionary<string, SymmetricKey> retiredKeys =
        ImmutableDictionary<string, SymmetricKey>.Empty;
    private int retiredCount;


    /// <summary>
    /// Initialises the resolver with an initial current key and an upper
    /// bound on how many previously-rotated keys to retain.
    /// </summary>
    /// <param name="initialKey">The first current key.</param>
    /// <param name="initialKid">The kid identifying <paramref name="initialKey"/>.</param>
    /// <param name="maxRetainedKeys">
    /// Upper bound on retired keys. Once exceeded, the oldest retired
    /// entry falls off on the next rotation. Default is 4.
    /// </param>
    public InProcessHmacKeyResolver(
        SymmetricKey initialKey,
        string initialKid,
        int maxRetainedKeys = 4)
    {
        ArgumentNullException.ThrowIfNull(initialKey);
        ArgumentException.ThrowIfNullOrEmpty(initialKid);
        ArgumentOutOfRangeException.ThrowIfNegative(maxRetainedKeys);

        currentKey = initialKey;
        currentKid = initialKid;
        this.maxRetainedKeys = maxRetainedKeys;
    }


    /// <summary>
    /// Rotates the current key. The previous current key moves to the
    /// retired set (still acceptable for validation) for up to
    /// <c>maxRetainedKeys</c> rotations; the new key becomes current.
    /// </summary>
    public void Rotate(SymmetricKey newKey, string newKid)
    {
        ArgumentNullException.ThrowIfNull(newKey);
        ArgumentException.ThrowIfNullOrEmpty(newKid);

        lock(rotateLock)
        {
            ImmutableDictionary<string, SymmetricKey> updated =
                retiredKeys.SetItem(currentKid, currentKey);
            if(updated.Count > maxRetainedKeys)
            {
                //Oldest entry falls off — this is a tiny set so iteration cost is negligible.
                string oldestKid = updated
                    .OrderBy(p => p.Key, StringComparer.Ordinal)
                    .First()
                    .Key;
                updated = updated.Remove(oldestKid);
            }
            retiredKeys = updated;
            retiredCount = updated.Count;
            currentKey = newKey;
            currentKid = newKid;
        }
    }


    /// <summary>
    /// The library's <see cref="ResolveServerHmacKeyDelegate"/>-shaped entry point.
    /// Wire this method as the delegate value on
    /// <see cref="AuthorizationServerIntegration.ResolveServerHmacKeyAsync"/>.
    /// </summary>
    public ValueTask<HmacKeyResolution?> ResolveAsync(
        string? kid,
        TenantId tenantId,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if(kid is null)
        {
            return ValueTask.FromResult<HmacKeyResolution?>(new HmacKeyResolution
            {
                Key = currentKey,
                Kid = currentKid
            });
        }
        if(string.Equals(kid, currentKid, StringComparison.Ordinal))
        {
            return ValueTask.FromResult<HmacKeyResolution?>(new HmacKeyResolution
            {
                Key = currentKey,
                Kid = currentKid
            });
        }
        if(retiredKeys.TryGetValue(kid, out SymmetricKey? retired))
        {
            return ValueTask.FromResult<HmacKeyResolution?>(new HmacKeyResolution
            {
                Key = retired,
                Kid = kid
            });
        }
        return ValueTask.FromResult<HmacKeyResolution?>(null);
    }
}
