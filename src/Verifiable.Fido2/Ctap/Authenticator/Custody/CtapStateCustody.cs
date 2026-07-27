using System;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// A backend-neutral seam bundling the three async delegates a <see cref="Automata.CtapAuthenticatorSimulator"/>
/// needs to survive the death of the process holding it: load a previously persisted snapshot, persist a
/// fresh one, and wipe whatever is persisted.
/// </summary>
/// <remarks>
/// <para>
/// Contract R-3: a plain seam-bundle record of delegates, never a behavioral interface — any store (a
/// file, a database row, an in-memory dictionary, or package C's TPM-backed adapter sealing the snapshot
/// to the in-house simulated TPM) implements this shape by supplying three delegates, with no interface
/// to implement and no base type to derive from.
/// </para>
/// <para>
/// Supplying an instance of this record to <see cref="Automata.CtapAuthenticatorSimulator.CreateWithCustodyAsync"/>
/// is the ONLY way a simulator gains custody behavior; the simulator's ordinary constructor never accepts
/// one, so every existing composition root is unaffected (contract R-3: "Custody absent (null bundle) ⇒
/// today's behavior, byte-identical").
/// </para>
/// </remarks>
/// <param name="TryLoadSnapshotAsync">Attempts to load a previously persisted snapshot.</param>
/// <param name="PersistSnapshotAsync">Persists a fresh snapshot, overwriting whatever was there.</param>
/// <param name="WipeSnapshotAsync">Deletes whatever snapshot is persisted.</param>
/// <exception cref="ArgumentNullException">Any of the three delegates is <see langword="null"/>.</exception>
public sealed record CtapStateCustody(
    TryLoadSnapshotAsyncDelegate TryLoadSnapshotAsync,
    PersistSnapshotAsyncDelegate PersistSnapshotAsync,
    WipeSnapshotAsyncDelegate WipeSnapshotAsync)
{
    /// <summary>Attempts to load a previously persisted snapshot. Never <see langword="null"/>.</summary>
    public TryLoadSnapshotAsyncDelegate TryLoadSnapshotAsync { get; } =
        TryLoadSnapshotAsync ?? throw new ArgumentNullException(nameof(TryLoadSnapshotAsync));

    /// <summary>Persists a fresh snapshot, overwriting whatever was there. Never <see langword="null"/>.</summary>
    public PersistSnapshotAsyncDelegate PersistSnapshotAsync { get; } =
        PersistSnapshotAsync ?? throw new ArgumentNullException(nameof(PersistSnapshotAsync));

    /// <summary>Deletes whatever snapshot is persisted. Never <see langword="null"/>.</summary>
    public WipeSnapshotAsyncDelegate WipeSnapshotAsync { get; } =
        WipeSnapshotAsync ?? throw new ArgumentNullException(nameof(WipeSnapshotAsync));
}
