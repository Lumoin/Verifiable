using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// Explicit per-call caller state for <see cref="CBAdESDetachedObjectDereferenceDelegate"/> and
/// <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/> — the no-closure-capture seam
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.1</see>'s dereference obligations flow through: the caller builds
/// ONE instance and passes it explicitly at every call this creation flow makes, rather than an implementation
/// lambda capturing an HTTP client, timeout, or credential from its enclosing scope.
/// </summary>
/// <remarks>
/// <para>
/// <strong>No HTTP client ships in this library (contract R-2).</strong> Dereferencing a URI-reference —
/// including <see href="https://www.rfc-editor.org/rfc/rfc3986#section-1.1.3">RFC 3986 §1.1.3</see> locator
/// classification, relative-reference resolution against <see cref="DefaultBaseUri"/> per
/// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-5.1.4">RFC 3986 §5.1.4</see> (CB-5.2.8.2.1-04),
/// HTTP status-code handling (CB-5.2.8.2.1-06), and any non-HTTP scheme's own dereferencing rule
/// (CB-5.2.8.2.1-07/08) — is entirely the <see cref="CBAdESDetachedObjectDereferenceDelegate"/> implementer's
/// obligation. This context carries only what a spec-aware implementer needs across every call of one
/// creation invocation, plus one opaque escape hatch for anything else (an HTTP client instance, a timeout, an
/// authentication header) the implementer's own infrastructure requires.
/// </para>
/// <para>
/// <strong>The one-hop rule (CB-5.2.8-10/11) holds structurally, not by policy.</strong> Nothing in this file
/// re-inspects a dereferenced object's bytes for further references — <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/>
/// only ever calls <see cref="CBAdESDetachedObjectDereferenceDelegate"/> once per entry of the caller-supplied
/// reference list, never recursively over a fetched object's content. Chaining would require this file to
/// parse fetched bytes looking for more references, which it never does.
/// </para>
/// </remarks>
/// <param name="DefaultBaseUri">
/// The default base HTTP-scheme URI a relative URI-reference resolves against (CB-5.2.8.2.1-04), or
/// <see langword="null"/> when every reference this call set carries is already absolute.
/// </param>
/// <param name="State">
/// Opaque implementer infrastructure (an HTTP client instance, a timeout, credentials) passed through
/// unexamined by this library. <see langword="null"/> when the implementer needs none.
/// </param>
[DebuggerDisplay("CBAdESDetachedObjectDereferenceContext: {DefaultBaseUri}")]
public sealed record CBAdESDetachedObjectDereferenceContext(Uri? DefaultBaseUri, object? State);


/// <summary>
/// The outcome of dereferencing one detached-object URI-reference — the fetched bytes, or a failure signal. A
/// DU-ready closed sum: no external type may derive from it.
/// </summary>
public abstract record CBAdESDetachedObjectDereferenceResult
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESDetachedObjectDereferenceResult()
    {
    }
}


/// <summary>
/// A successfully dereferenced detached data object.
/// </summary>
/// <param name="Content">
/// The dereferenced object's bytes, pool-routed. Ownership transfers to whichever caller receives this
/// result — see <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/> for the
/// built-in consumer's disposal contract.
/// </param>
[DebuggerDisplay("CBAdESDetachedObjectDereferenceSuccess: {Content.Length} bytes")]
public sealed record CBAdESDetachedObjectDereferenceSuccess(PooledMemory Content) : CBAdESDetachedObjectDereferenceResult;


/// <summary>
/// A failed dereference attempt (locator unreachable, an HTTP status outside the success range, an unsupported
/// scheme).
/// </summary>
/// <param name="Reason">A human-readable statement of why dereferencing failed.</param>
[DebuggerDisplay("CBAdESDetachedObjectDereferenceFailure: {Reason}")]
public sealed record CBAdESDetachedObjectDereferenceFailure(string Reason) : CBAdESDetachedObjectDereferenceResult;


/// <summary>
/// Dereferences one detached-object URI-reference — the delegate seam
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.1</see> describes and this library never implements directly
/// (contract R-2: no HTTP client ships in this library).
/// </summary>
/// <remarks>
/// Never throws on a failed dereference — a network failure, a 404, or a rejected scheme is a
/// <see cref="CBAdESDetachedObjectDereferenceFailure"/>, not an exception; the caller (typically
/// <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/>) decides how to react.
/// An implementer that genuinely cannot continue (a cancelled operation, a programming error) still throws
/// normally — this convention is about the routine "the object was not retrievable" outcome, not every
/// possible failure mode.
/// </remarks>
/// <param name="uriReference">The URI-reference to dereference (one <c>pars</c> element, CB-5.2.8-17/18).</param>
/// <param name="context">The per-call caller state; see <see cref="CBAdESDetachedObjectDereferenceContext"/>.</param>
/// <param name="pool">Memory pool the fetched content is rented from.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The dereferenced content, or a failure signal.</returns>
public delegate ValueTask<CBAdESDetachedObjectDereferenceResult> CBAdESDetachedObjectDereferenceDelegate(
    string uriReference,
    CBAdESDetachedObjectDereferenceContext context,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);


/// <summary>
/// One <c>sigD.pars</c> entry, before digest computation — the per-call input shape
/// <see cref="CBAdESSignatureCreation"/> accepts for a detached object referenced by URI, mirroring
/// <see cref="CBAdESDetachedObjectEntry"/> minus its <see cref="CBAdESDetachedObjectEntry.Digest"/> member
/// (S3 coordinator ruling (4): creation computes <c>hashV</c> itself under the
/// <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/> mechanism — see
/// <see cref="CBAdESSignatureCreation"/>'s remarks for why this is a NEW type rather than a nullable-digest
/// <see cref="CBAdESDetachedObjectEntry"/>).
/// </summary>
/// <param name="Reference">The URI-reference to the detached data object (one <c>pars</c> element).</param>
/// <param name="ContentType">
/// The content type of the referenced object (the <c>ctys</c> element at the same position), or
/// <see langword="null"/> when absent or implied (CB-5.2.8-23/25).
/// </param>
[DebuggerDisplay("CBAdESDetachedObjectReferenceInput: {Reference}")]
public sealed record CBAdESDetachedObjectReferenceInput(string Reference, string? ContentType);


/// <summary>
/// Retrieves the COSE Payload for a <c>sigD.mId</c> value neither
/// <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/> nor <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/>
/// — the third-party mechanism extension point CB-5.2.6-07 and CB-5.2.8-08 require: "the specification defining
/// that <c>mId</c> value shall specify how to retrieve the COSE Payload."
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope, recorded loudly.</strong> This extension point covers COSE-Payload retrieval only, matching
/// CB-5.2.6-07's literal wording. It does not produce per-entry digests: a third-party mechanism's own
/// <c>hashM</c>/<c>hashV</c> semantics (if it has any) are that mechanism's specification's concern, not
/// something this library can generalize from two built-in examples. <see cref="CBAdESSignatureCreation"/>
/// therefore builds <see cref="CBAdESDetachedObjects"/> for an unknown mechanism with every entry's
/// <see cref="CBAdESDetachedObjectEntry.Digest"/> <see langword="null"/> and no <c>hashM</c> — a caller whose
/// third-party mechanism needs digests is outside what this stage's extension point resolves; flagged for the
/// review wave as a residue, not a defect (the two mechanisms this document itself defines are fully
/// supported without this delegate).
/// </para>
/// <para>
/// <strong>Failure contract (wavecb S3 FX-J).</strong> Routine retrieval failure — the referenced object is
/// unreachable, a locator the implementer's infrastructure rejects, anything an ordinary
/// <see cref="CBAdESDetachedObjectDereferenceDelegate"/> implementer would report as a
/// <see cref="CBAdESDetachedObjectDereferenceFailure"/> — is signalled by throwing
/// <see cref="CBAdESDetachedObjectDereferenceException"/> (the message-only constructor is sufficient; this
/// delegate has no single <c>uriReference</c> the classified constructor could name, since it may resolve
/// several <paramref name="references"/> at once). Anything else — cancellation, a programming error, an
/// implementer-infrastructure fault that is not "the object was not retrievable" — is NON-ROUTINE and
/// propagates unmodified through both <see cref="CBAdESSignatureCreation"/> (which never catches an exception
/// from this delegate at all) and <see cref="CBAdESSignatureValidation"/> (whose own catch, post FX-J, narrows
/// to exactly <see cref="CBAdESDetachedObjectDereferenceException"/> — see that class's remarks).
/// </para>
/// </remarks>
/// <param name="mechanismIdentifier">The unrecognized <c>mId</c> value.</param>
/// <param name="references">The <c>sigD.pars</c> entries, in wire order.</param>
/// <param name="hashAlgorithm">The caller-declared <c>hashM</c>, when the payload input carried one, or <see langword="null"/>.</param>
/// <param name="context">The per-call caller state; see <see cref="CBAdESDetachedObjectDereferenceContext"/>.</param>
/// <param name="pool">Memory pool the returned payload is rented from.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The COSE Payload bytes to sign over, pool-routed. Ownership transfers to the caller.</returns>
public delegate ValueTask<PooledMemory> CBAdESUnknownDetachedObjectMechanismDelegate(
    string mechanismIdentifier,
    IReadOnlyList<CBAdESDetachedObjectReferenceInput> references,
    CBAdESDigestAlgorithmIdentifier? hashAlgorithm,
    CBAdESDetachedObjectDereferenceContext context,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);


/// <summary>
/// Thrown when <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/> cannot
/// complete because a referenced object could not be dereferenced — a creation-time operational failure
/// (network/data unavailability), distinct from the validation-side "malformed wire content never throws"
/// convention (R-5): this is trusted-caller-triggered I/O, mirroring
/// <see cref="TimestampAcquisitionException"/>'s fail-closed creation-side shape rather than a parsed-content
/// conclusion model.
/// </summary>
public sealed class CBAdESDetachedObjectDereferenceException: Exception
{
    /// <summary>
    /// Gets the URI-reference whose dereference failed, or <see langword="null"/> when this instance was
    /// constructed through the standard parameterless/message-only exception constructors.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "A sigD.pars URI-reference (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.1) may be relative " +
            "per RFC 3986 SS4.2, and this repo's own recorded cross-platform trap -- Uri.TryCreate(Absolute) " +
            "accepts a bare '/relative' path as a file:// URI on Unix -- makes a System.Uri property here an " +
            "unreliable carrier for the exact reference string a caller passed to " +
            "CBAdESDetachedObjectDereferenceDelegate. Keeping this string-typed is also consistent with the " +
            "whole string-typed sigD surface (CBAdESDetachedObjectEntry.Reference, " +
            "CBAdESDetachedObjectReferenceInput.Reference) this exception reports against.")]
    public string? UriReference { get; }


    /// <summary>
    /// Initializes a new instance (the standard parameterless exception constructor .NET convention expects;
    /// every throw site in this library uses the classified overload below instead).
    /// </summary>
    public CBAdESDetachedObjectDereferenceException(): base("A detached data object could not be dereferenced.")
    {
    }


    /// <summary>Initializes a new instance with a message.</summary>
    /// <param name="message">The message that describes the error.</param>
    public CBAdESDetachedObjectDereferenceException(string message): base(message)
    {
    }


    /// <summary>Initializes a new instance with a message and an inner exception.</summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of this exception.</param>
    public CBAdESDetachedObjectDereferenceException(string message, Exception innerException): base(message, innerException)
    {
    }


    /// <summary>Initializes a new instance naming the reference that failed and why.</summary>
    /// <param name="uriReference">The URI-reference whose dereference failed.</param>
    /// <param name="reason">The failure reason (see <see cref="CBAdESDetachedObjectDereferenceFailure.Reason"/>).</param>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "A sigD.pars URI-reference (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.1) may be relative " +
            "per RFC 3986 SS4.2, and this repo's own recorded cross-platform trap -- Uri.TryCreate(Absolute) " +
            "accepts a bare '/relative' path as a file:// URI on Unix -- makes a System.Uri parameter here an " +
            "unreliable carrier for the exact reference string the caller passed to " +
            "CBAdESDetachedObjectDereferenceDelegate. Keeping this string-typed is also consistent with the " +
            "whole string-typed sigD surface (CBAdESDetachedObjectEntry.Reference, " +
            "CBAdESDetachedObjectReferenceInput.Reference) this exception reports against.")]
    public CBAdESDetachedObjectDereferenceException(string uriReference, string reason)
        : base($"Failed to dereference '{uriReference}': {reason}")
    {
        UriReference = uriReference;
    }
}


/// <summary>
/// The <c>sigD</c> detached-object dereferencing seam: composes <see cref="CBAdESDetachedObjectDereferenceDelegate"/>
/// calls into the payload-reconstruction algorithm
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.2</see> defines.
/// </summary>
public static class CBAdESDetachedObjectDereferencing
{
    /// <summary>The tag every buffer <see cref="ReconstructObjectIdByURIPayloadAsync"/> mints carries.</summary>
    private static Tag ReconstructedPayloadTag { get; } = Tag.Create(Purpose.Data);


    /// <summary>
    /// Implements the <c>ObjectIdByURI</c> octet-stream algorithm (CB-5.2.8.2.2-05): initializes an empty
    /// octet stream, then for each reference in order, dereferences it (CB-5.2.8.2.1) and concatenates the
    /// resulting octets onto the stream. This is also the CB-5.2.8.2.3-07 reconstruction path — the same
    /// procedure the <c>ObjectIdByURIHash</c> mechanism falls back to whenever the full COSE Payload is needed
    /// for a purpose OTHER than the COSE signature-value computation itself (<c>adoTst</c>/<c>arcTst</c>
    /// message imprints, CB-5.2.6-06); this method is public and composable for exactly that reuse — the S4
    /// timestamp work calls it directly rather than reimplementing the concatenation.
    /// </summary>
    /// <param name="references">
    /// The ordered URI-references to dereference and concatenate, in wire (<c>pars</c>) order — order is
    /// load-bearing (CB-5.2.8.2.2-05: "the COSE Payload byte order").
    /// </param>
    /// <param name="dereference">The dereference delegate; see <see cref="CBAdESDetachedObjectDereferenceDelegate"/>.</param>
    /// <param name="context">The per-call caller state; see <see cref="CBAdESDetachedObjectDereferenceContext"/>.</param>
    /// <param name="pool">Memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The concatenated octet stream, pool-routed. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="references"/>, <paramref name="dereference"/>, <paramref name="context"/>, or
    /// <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException"><paramref name="references"/> is empty (CB-5.2.8-06).</exception>
    /// <exception cref="CBAdESDetachedObjectDereferenceException">
    /// A referenced object could not be dereferenced (<see cref="CBAdESDetachedObjectDereferenceFailure"/>).
    /// </exception>
    public static async ValueTask<PooledMemory> ReconstructObjectIdByURIPayloadAsync(
        IReadOnlyList<string> references,
        CBAdESDetachedObjectDereferenceDelegate dereference,
        CBAdESDetachedObjectDereferenceContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(references);
        ArgumentNullException.ThrowIfNull(dereference);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        if(references.Count == 0)
        {
            throw new ArgumentException(
                "sigD shall reference one or more detached data objects (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1, CB-5.2.8-06).",
                nameof(references));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var fetched = new PooledMemory[references.Count];
        int fetchedCount = 0;
        try
        {
            int totalLength = 0;
            for(int i = 0; i < references.Count; ++i)
            {
                cancellationToken.ThrowIfCancellationRequested();

                CBAdESDetachedObjectDereferenceResult result = await dereference(
                    references[i], context, pool, cancellationToken).ConfigureAwait(false);

                if(result is not CBAdESDetachedObjectDereferenceSuccess success)
                {
                    string reason = result is CBAdESDetachedObjectDereferenceFailure failure
                        ? failure.Reason
                        : "the dereference delegate returned neither a success nor a failure result.";

                    throw new CBAdESDetachedObjectDereferenceException(references[i], reason);
                }

                fetched[i] = success.Content;
                fetchedCount = i + 1;
                totalLength += success.Content.Length;
            }

            //At least one byte is always rented, even for an all-empty reference set, matching
            //PooledMemory.FromBytes's own convention (some MemoryPool<T> implementations reject a
            //zero-length request outright).
            IMemoryOwner<byte> owner = pool.Rent(Math.Max(totalLength, 1));
            int offset = 0;
            for(int i = 0; i < fetched.Length; ++i)
            {
                ReadOnlySpan<byte> content = fetched[i].AsReadOnlySpan();
                content.CopyTo(owner.Memory.Span[offset..]);
                offset += content.Length;
            }

            return new PooledMemory(owner, totalLength, ReconstructedPayloadTag);
        }
        finally
        {
            for(int i = 0; i < fetchedCount; ++i)
            {
                fetched[i]?.Dispose();
            }
        }
    }
}
