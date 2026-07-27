using System;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// A backend-neutral seam bundling the three async delegates a <see cref="Automata.CtapAuthenticatorSimulator"/>
/// needs to custody a credential's signature counter against a rollback-protected external counter primitive,
/// SIBLING to <see cref="CtapStateCustody"/> rather than a widening of it (contract R-9, wavenv): mint a
/// fresh credential's initial count, advance an existing credential's count at assertion time, and retire a
/// removed credential's count.
/// </summary>
/// <remarks>
/// <para>
/// A plain seam-bundle record of delegates, never a behavioral interface — the same house convention
/// <see cref="CtapStateCustody"/> establishes (contract R-3): any counter-backed store (an in-memory
/// dictionary, a database sequence, or package C's TPM-backed adapter over an NV Counter Index) implements
/// this shape by supplying three delegates, with no interface to implement and no base type to derive from.
/// </para>
/// <para>
/// <b>Opt-in, byte-identical when absent.</b> Composing this bundle is entirely independent of
/// <see cref="CtapStateCustody"/>'s own whole-snapshot persistence — with it composed, a credential's
/// per-credential <see cref="Automata.CtapCredentialRecord.SignCount"/> field becomes a last-observed CACHE
/// (the snapshot CBOR format and version are unchanged) and this bundle's <see cref="IncrementCounterAsync"/>
/// becomes the AUTHORITATIVE source of every wire-visible signature counter; a stale or replayed whole-
/// snapshot can then never roll it back. <see cref="Automata.CtapAuthenticatorSimulator.CreateWithCustodyAsync"/>'s
/// own <c>signatureCounterCustody</c> parameter is the ONLY way a simulator gains this behavior, and it
/// defaults to <see langword="null"/> — every existing composition root is unaffected (the same "absent
/// bundle ⇒ today's behavior, byte-identical" discipline the wavect wave established for
/// <see cref="CtapStateCustody"/>).
/// </para>
/// </remarks>
/// <param name="EnsureCounterAsync">Mints (or re-mints, after a retirement) the counter for a freshly registered credential and returns its initial count.</param>
/// <param name="IncrementCounterAsync">Atomically advances an existing credential's counter at assertion time and returns the fresh count.</param>
/// <param name="RetireCounterAsync">Retires a removed credential's counter so a later identity reuse can never roll it back.</param>
/// <exception cref="ArgumentNullException">Any of the three delegates is <see langword="null"/>.</exception>
public sealed record CtapSignatureCounterCustody(
    EnsureCounterAsyncDelegate EnsureCounterAsync,
    IncrementCounterAsyncDelegate IncrementCounterAsync,
    RetireCounterAsyncDelegate RetireCounterAsync)
{
    /// <summary>Mints (or re-mints, after a retirement) the counter for a freshly registered credential and returns its initial count. Never <see langword="null"/>.</summary>
    public EnsureCounterAsyncDelegate EnsureCounterAsync { get; } =
        EnsureCounterAsync ?? throw new ArgumentNullException(nameof(EnsureCounterAsync));

    /// <summary>Atomically advances an existing credential's counter at assertion time and returns the fresh count. Never <see langword="null"/>.</summary>
    public IncrementCounterAsyncDelegate IncrementCounterAsync { get; } =
        IncrementCounterAsync ?? throw new ArgumentNullException(nameof(IncrementCounterAsync));

    /// <summary>Retires a removed credential's counter so a later identity reuse can never roll it back. Never <see langword="null"/>.</summary>
    public RetireCounterAsyncDelegate RetireCounterAsync { get; } =
        RetireCounterAsync ?? throw new ArgumentNullException(nameof(RetireCounterAsync));
}
