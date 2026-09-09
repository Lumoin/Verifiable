using System;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The wire kind tag a serialized context blob's leading octet carries — which of
/// <see cref="TpmContextResource"/>'s five sealed shapes <see cref="TpmContextSerializer"/> wrote, so the read
/// side selects the matching arm before it interprets anything past that octet.
/// </summary>
/// <remarks>
/// The numeric values are this model's own vendor-internal wire convention (TPM 2.0 Library Part 1, clause
/// 27.2.1: "The internal structure TPMS_CONTEXT_DATA of the actual context is vendor specific"), not a TCG-
/// assigned constant; they need only be stable within one running simulator, since a blob never crosses a
/// process boundary except through <see cref="Tpm2bContextData"/>'s own opaque octets.
/// </remarks>
public enum TpmContextResourceKind: byte
{
    /// <summary>A <see cref="TransientKeyState"/> — an ordinary or <c>stClear</c> Transient Object.</summary>
    TransientKey = 0,

    /// <summary>A <see cref="KeyedHashObjectState"/> — a sealed data object or an HMAC signing key.</summary>
    KeyedHashObject = 1,

    /// <summary>A <see cref="SequenceObjectState"/> — an open hash, Event, HMAC, signing, or verification sequence.</summary>
    SequenceObject = 2,

    /// <summary>An <see cref="HmacSessionState"/> — a started bound HMAC session.</summary>
    HmacSession = 3,

    /// <summary>A <see cref="PolicySessionState"/> — a started policy (enhanced authorization) session.</summary>
    PolicySession = 4
}

/// <summary>
/// The uniform envelope <c>TPM2_ContextSave()</c> and <c>TPM2_ContextLoad()</c> carry one of the five saveable
/// resource records through: <see cref="TpmContextSerializer"/> writes and reads the wrapped record's fields,
/// and the transition/effect pair that drives each command reads only <see cref="Kind"/> and
/// <see cref="IsSession"/> to decide how to route it, never the wrapped record's own type directly.
/// </summary>
/// <remarks>
/// <para>
/// Ownership follows the direction the resource is travelling. On the SAVE path the wrapped record is BORROWED:
/// it is read out of <see cref="TpmSimulatorState.TransientObjects"/>, <see cref="TpmSimulatorState.LoadedKeyedHashObjects"/>,
/// <see cref="TpmSimulatorState.SequenceObjects"/>, <see cref="TpmSimulatorState.HmacSessions"/> or
/// <see cref="TpmSimulatorState.PolicySessions"/> and stays that dictionary's (or, for a session, the record the
/// save effect is about to remove and dispose itself) — the envelope's own <see cref="Dispose"/> must never be
/// called on a save-path instance, since it does not own what it wraps. On the LOAD path the wrapped record is
/// OWNED: <see cref="TpmContextSerializer.Deserialize"/> rents fresh carriers under the caller's pool and builds
/// a brand-new resource record no dictionary yet references, which the effect that produced it (or a refusal
/// after it) must dispose through this envelope's <see cref="Dispose"/> until the completing transition installs
/// it into the resource's own dictionary — at which point ownership passes to that dictionary exactly as any
/// other loaded resource's does, and this envelope is discarded unwrapped.
/// </para>
/// </remarks>
public abstract record TpmContextResource: IDisposable
{
    /// <summary>Gets the wire kind tag this resource serializes under (<see cref="TpmContextResourceKind"/>).</summary>
    public abstract TpmContextResourceKind Kind { get; }

    /// <summary>
    /// Gets whether this resource is a session (<see cref="TpmContextResourceKind.HmacSession"/> or
    /// <see cref="TpmContextResourceKind.PolicySession"/>) rather than an object or sequence — the split
    /// <c>TPM2_ContextSave()</c>'s feedback and <c>TPM2_ContextLoad()</c>'s install both branch on (TPM 2.0
    /// Library Part 1, clauses 27.4 and 27.5: an object stays loaded and keeps its handle across a save, a
    /// session is removed from RAM and reinstalled at the SAME handle on load).
    /// </summary>
    public bool IsSession => Kind is TpmContextResourceKind.HmacSession or TpmContextResourceKind.PolicySession;

    /// <summary>
    /// Releases the wrapped record's own owned carriers — a no-op envelope over whichever <c>Dispose()</c> the
    /// wrapped <see cref="TransientKeyState"/>, <see cref="KeyedHashObjectState"/>, <see cref="SequenceObjectState"/>,
    /// <see cref="HmacSessionState"/> or <see cref="PolicySessionState"/> already implements, through the
    /// standard dispose pattern's <see cref="Dispose(bool)"/> each sealed kind overrides. Call this only on an
    /// instance this envelope OWNS (see the ownership remarks above) — never on a save-path instance that merely
    /// borrows the record it wraps.
    /// </summary>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the wrapped record's owned carriers when <paramref name="disposing"/> is <see langword="true"/>
    /// — every kind's wrapped state carries only managed pooled memory, so there is no unmanaged-only path.
    /// </summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected abstract void Dispose(bool disposing);
}

/// <summary>
/// Wraps a <see cref="TransientKeyState"/> as a <see cref="TpmContextResource"/> for
/// <c>TPM2_ContextSave()</c>/<c>TPM2_ContextLoad()</c>.
/// </summary>
/// <param name="Key">The wrapped Transient Object state; BORROWED on the save path, OWNED on the load path (see <see cref="TpmContextResource"/>'s remarks).</param>
public sealed record TpmContextTransientKey(TransientKeyState Key): TpmContextResource
{
    /// <inheritdoc/>
    public override TpmContextResourceKind Kind => TpmContextResourceKind.TransientKey;

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            Key.Dispose();
        }
    }
}

/// <summary>
/// Wraps a <see cref="KeyedHashObjectState"/> as a <see cref="TpmContextResource"/> for
/// <c>TPM2_ContextSave()</c>/<c>TPM2_ContextLoad()</c>.
/// </summary>
/// <param name="Object">The wrapped KEYEDHASH object state; BORROWED on the save path, OWNED on the load path (see <see cref="TpmContextResource"/>'s remarks).</param>
public sealed record TpmContextKeyedHashObject(KeyedHashObjectState Object): TpmContextResource
{
    /// <inheritdoc/>
    public override TpmContextResourceKind Kind => TpmContextResourceKind.KeyedHashObject;

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            Object.Dispose();
        }
    }
}

/// <summary>
/// Wraps a <see cref="SequenceObjectState"/> as a <see cref="TpmContextResource"/> for
/// <c>TPM2_ContextSave()</c>/<c>TPM2_ContextLoad()</c>.
/// </summary>
/// <param name="Sequence">The wrapped sequence-context state; BORROWED on the save path, OWNED on the load path (see <see cref="TpmContextResource"/>'s remarks).</param>
public sealed record TpmContextSequenceObject(SequenceObjectState Sequence): TpmContextResource
{
    /// <inheritdoc/>
    public override TpmContextResourceKind Kind => TpmContextResourceKind.SequenceObject;

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            Sequence.Dispose();
        }
    }
}

/// <summary>
/// Wraps an <see cref="HmacSessionState"/> as a <see cref="TpmContextResource"/> for
/// <c>TPM2_ContextSave()</c>/<c>TPM2_ContextLoad()</c>.
/// </summary>
/// <param name="Session">The wrapped HMAC session state; BORROWED on the save path (the live record the save effect is about to remove and dispose itself), OWNED on the load path (see <see cref="TpmContextResource"/>'s remarks).</param>
public sealed record TpmContextHmacSession(HmacSessionState Session): TpmContextResource
{
    /// <inheritdoc/>
    public override TpmContextResourceKind Kind => TpmContextResourceKind.HmacSession;

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            Session.Dispose();
        }
    }
}

/// <summary>
/// Wraps a <see cref="PolicySessionState"/> as a <see cref="TpmContextResource"/> for
/// <c>TPM2_ContextSave()</c>/<c>TPM2_ContextLoad()</c>.
/// </summary>
/// <param name="Session">The wrapped policy session state; BORROWED on the save path (the live record the save effect is about to remove and dispose itself), OWNED on the load path (see <see cref="TpmContextResource"/>'s remarks).</param>
public sealed record TpmContextPolicySession(PolicySessionState Session): TpmContextResource
{
    /// <inheritdoc/>
    public override TpmContextResourceKind Kind => TpmContextResourceKind.PolicySession;

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            Session.Dispose();
        }
    }
}
