using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.OAuth.Server.Keys;

/// <summary>
/// Mutable in-process holder for a <see cref="KeySet{TKey}"/> plus
/// slot-transition methods. Single-instance deployments wire this directly
/// as the source of truth for their keyset; multi-instance deployments
/// wire their own (KMS/Vault-backed) implementation that returns
/// <see cref="KeySet{TKey}"/> snapshots.
/// </summary>
/// <remarks>
/// All transitions are thread-safe (lock-protected). Snapshots returned by
/// <see cref="Snapshot"/> are immutable; concurrent transitions don't
/// affect a snapshot already in flight. Transitions throw
/// <see cref="InvalidOperationException"/> when the requested kid is not
/// in the source slot — callers must coordinate transitions with their
/// rotation plan rather than discover slot membership via exception.
/// </remarks>
[DebuggerDisplay("InProcessKeySet Incoming={set.Incoming.Count} Current={set.Current.Count} Retiring={set.Retiring.Count} Historical={set.Historical.Count}")]
public sealed class InProcessKeySet<TKey> where TKey : class, IRotatableKey
{
    private readonly Lock transitionLock = new();
    private KeySet<TKey> set;


    /// <summary>
    /// Initialises the holder with an initial snapshot. Pass
    /// <see langword="null"/> for an empty starting state; otherwise the
    /// supplied <paramref name="initial"/> snapshot becomes the starting
    /// state.
    /// </summary>
    public InProcessKeySet(KeySet<TKey>? initial = null)
    {
        set = initial ?? new KeySet<TKey>();
    }


    /// <summary>Returns an immutable snapshot of the current keyset.</summary>
    public KeySet<TKey> Snapshot()
    {
        lock(transitionLock)
        {
            return set;
        }
    }


    /// <summary>Adds a key to the <c>Incoming</c> slot.</summary>
    public void AddIncoming(TKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        lock(transitionLock)
        {
            set = set with { Incoming = set.Incoming.Add(key) };
        }
    }


    /// <summary>Adds a key directly to the <c>Current</c> slot. Used at bootstrap.</summary>
    public void AddCurrent(TKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        lock(transitionLock)
        {
            set = set with { Current = set.Current.Add(key) };
        }
    }


    /// <summary>
    /// Promotes a key from <c>Incoming</c> to <c>Current</c>. The key must
    /// already be in <c>Incoming</c> by kid.
    /// </summary>
    public void PromoteIncomingToCurrent(string kid)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);
        lock(transitionLock)
        {
            TKey? key = FindByKid(set.Incoming, kid);
            if(key is null)
            {
                throw new InvalidOperationException(
                    $"No key with kid '{kid}' in Incoming.");
            }
            set = set with
            {
                Incoming = set.Incoming.Remove(key),
                Current = set.Current.Add(key)
            };
        }
    }


    /// <summary>
    /// Moves a key from <c>Current</c> to <c>Retiring</c>. The key remains
    /// valid for verification but is no longer used for new issuance.
    /// </summary>
    public void RetireCurrent(string kid)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);
        lock(transitionLock)
        {
            TKey? key = FindByKid(set.Current, kid);
            if(key is null)
            {
                throw new InvalidOperationException(
                    $"No key with kid '{kid}' in Current.");
            }
            set = set with
            {
                Current = set.Current.Remove(key),
                Retiring = set.Retiring.Add(key)
            };
        }
    }


    /// <summary>
    /// Archives a key from <c>Retiring</c> to <c>Historical</c>. After this
    /// transition the kid is no longer valid for verification and is no
    /// longer published.
    /// </summary>
    public void ArchiveRetiring(string kid)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);
        lock(transitionLock)
        {
            TKey? key = FindByKid(set.Retiring, kid);
            if(key is null)
            {
                throw new InvalidOperationException(
                    $"No key with kid '{kid}' in Retiring.");
            }
            set = set with
            {
                Retiring = set.Retiring.Remove(key),
                Historical = set.Historical.Add(key)
            };
        }
    }


    /// <summary>
    /// Resolves a kid to a key across all slots, including Historical.
    /// Used by the byte-loading resolver — slot membership doesn't gate
    /// byte loading itself; verifiability gating happens at validation
    /// time via <see cref="KeySet{TKey}.IsKidValidForVerification"/>.
    /// </summary>
    public TKey? ResolveByKid(string kid)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);
        lock(transitionLock)
        {
            return FindByKid(set.Incoming, kid)
                ?? FindByKid(set.Current, kid)
                ?? FindByKid(set.Retiring, kid)
                ?? FindByKid(set.Historical, kid);
        }
    }


    private static TKey? FindByKid(ImmutableList<TKey> list, string kid)
    {
        foreach(TKey k in list)
        {
            if(string.Equals(k.Kid, kid, StringComparison.Ordinal))
            {
                return k;
            }
        }
        return null;
    }
}
