using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Server.Keys;

/// <summary>
/// Mutable in-process holder for a <see cref="KeySet"/> plus an associated
/// material store keyed by <see cref="KeyId"/>. Single-instance HMAC
/// deployments wire this directly as the source of truth for their
/// keyset; multi-instance deployments wire their own (KMS/Vault-backed)
/// implementations returning <see cref="KeySet"/> snapshots and
/// resolving material by kid.
/// </summary>
/// <remarks>
/// <para>
/// The slot tracker is structurally parallel to <see cref="SigningKeySet"/>;
/// the side dictionary of materials is the in-process default's way of
/// holding actual <see cref="SymmetricKey"/> values for kids it knows
/// about. HSM/KMS-backed deployments skip the material dictionary and
/// resolve material directly from the backing store.
/// </para>
/// <para>
/// All transitions are thread-safe (lock-protected). Snapshots returned
/// by <see cref="Snapshot"/> are immutable; concurrent transitions don't
/// affect snapshots already in flight. Material lookup via
/// <see cref="ResolveMaterial"/> is also lock-protected.
/// </para>
/// </remarks>
[DebuggerDisplay("InProcessKeySet Incoming={set.Incoming.Count} Current={set.Current.Count} Retiring={set.Retiring.Count} Historical={set.Historical.Count}")]
public sealed class InProcessKeySet: IDisposable
{
    private readonly Lock transitionLock = new();
    private KeySet set;
    private ImmutableDictionary<KeyId, SymmetricKey> materials =
        ImmutableDictionary<KeyId, SymmetricKey>.Empty;
    private bool disposed;


    /// <summary>
    /// Initialises an empty in-process keyset. Add keys via
    /// <see cref="AddCurrent"/> or <see cref="AddIncoming"/>.
    /// </summary>
    public InProcessKeySet()
    {
        set = new KeySet();
    }


    /// <summary>
    /// Disposes every <see cref="SymmetricKey"/> the keyset has been
    /// holding — including materials whose kids have moved to
    /// <see cref="KeySet.Historical"/>, since the material itself is kept
    /// in the side store across slot transitions. Idempotent.
    /// </summary>
    public void Dispose()
    {
        lock(transitionLock)
        {
            if(disposed) { return; }
            disposed = true;
            foreach(SymmetricKey material in materials.Values)
            {
                material.Dispose();
            }
            materials = ImmutableDictionary<KeyId, SymmetricKey>.Empty;
        }
    }


    /// <summary>Returns an immutable snapshot of the current keyset slots.</summary>
    public KeySet Snapshot()
    {
        lock(transitionLock)
        {
            return set;
        }
    }


    /// <summary>
    /// Adds a key directly to the <c>Current</c> slot with its material.
    /// Used at bootstrap.
    /// </summary>
    public void AddCurrent(KeyId kid, SymmetricKey material)
    {
        ArgumentNullException.ThrowIfNull(material);
        lock(transitionLock)
        {
            materials = materials.SetItem(kid, material);
            set = set with { Current = set.Current.Add(kid) };
        }
    }


    /// <summary>
    /// Adds a key to the <c>Incoming</c> slot with its material.
    /// </summary>
    public void AddIncoming(KeyId kid, SymmetricKey material)
    {
        ArgumentNullException.ThrowIfNull(material);
        lock(transitionLock)
        {
            materials = materials.SetItem(kid, material);
            set = set with { Incoming = set.Incoming.Add(kid) };
        }
    }


    /// <summary>
    /// Promotes a kid from <c>Incoming</c> to <c>Current</c>.
    /// </summary>
    public void PromoteIncomingToCurrent(KeyId kid)
    {
        lock(transitionLock)
        {
            if(!set.Incoming.Contains(kid))
            {
                throw new InvalidOperationException(
                    $"No kid '{kid.Value}' in Incoming.");
            }
            set = set with
            {
                Incoming = set.Incoming.Remove(kid),
                Current = set.Current.Add(kid)
            };
        }
    }


    /// <summary>
    /// Moves a kid from <c>Current</c> to <c>Retiring</c>. The material
    /// remains in the side store and resolvable.
    /// </summary>
    public void RetireCurrent(KeyId kid)
    {
        lock(transitionLock)
        {
            if(!set.Current.Contains(kid))
            {
                throw new InvalidOperationException(
                    $"No kid '{kid.Value}' in Current.");
            }
            set = set with
            {
                Current = set.Current.Remove(kid),
                Retiring = set.Retiring.Add(kid)
            };
        }
    }


    /// <summary>
    /// Archives a kid from <c>Retiring</c> to <c>Historical</c>. The
    /// material remains in the side store and resolvable, but
    /// <see cref="KeySet.IsKidValidForVerification"/> returns
    /// <see langword="false"/> for Historical kids.
    /// </summary>
    public void ArchiveRetiring(KeyId kid)
    {
        lock(transitionLock)
        {
            if(!set.Retiring.Contains(kid))
            {
                throw new InvalidOperationException(
                    $"No kid '{kid.Value}' in Retiring.");
            }
            set = set with
            {
                Retiring = set.Retiring.Remove(kid),
                Historical = set.Historical.Add(kid)
            };
        }
    }


    /// <summary>
    /// Returns the stored material for <paramref name="kid"/>, or
    /// <see langword="null"/> when the kid is unknown. Slot membership
    /// doesn't gate material lookup — verifiability is checked separately
    /// via <see cref="KeySet.IsKidValidForVerification"/>.
    /// </summary>
    public SymmetricKey? ResolveMaterial(KeyId kid)
    {
        lock(transitionLock)
        {
            return materials.TryGetValue(kid, out SymmetricKey? material)
                ? material : null;
        }
    }
}
