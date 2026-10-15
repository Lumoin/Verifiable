using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// Explicit per-call caller state for <see cref="JAdESDetachedObjectDereferenceDelegate"/> and
/// <see cref="JAdESUnknownDetachedObjectMechanismDelegate"/> — the no-closure-capture seam clause 5.2.8.3.1's
/// dereference obligations flow through, mirroring
/// <see cref="CBAdESDetachedObjectDereferenceContext"/> one document removed.
/// </summary>
/// <param name="DefaultBaseUri">
/// The default base HTTP-scheme URI a relative URI-reference resolves against (JA-5.2.8.3.1-05), or
/// <see langword="null"/> when every reference this call set carries is already absolute.
/// </param>
/// <param name="State">
/// Opaque implementer infrastructure (an HTTP client instance, a timeout, credentials) passed through
/// unexamined by this library. <see langword="null"/> when the implementer needs none.
/// </param>
[DebuggerDisplay("JAdESDetachedObjectDereferenceContext: {DefaultBaseUri}")]
public sealed record JAdESDetachedObjectDereferenceContext(Uri? DefaultBaseUri, object? State);


/// <summary>
/// The outcome of dereferencing one detached-object URI-reference under the <c>ObjectIdByURI</c>/
/// <c>ObjectIdByURIHash</c> mechanisms — the fetched bytes, or a failure signal. A DU-ready closed sum: no
/// external type may derive from it.
/// </summary>
public abstract record JAdESDetachedObjectDereferenceResult
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected JAdESDetachedObjectDereferenceResult()
    {
    }
}


/// <summary>A successfully dereferenced detached data object.</summary>
/// <param name="Content">
/// The dereferenced object's raw bytes, pool-routed. Ownership transfers to whichever caller receives this
/// result.
/// </param>
[DebuggerDisplay("JAdESDetachedObjectDereferenceSuccess: {Content.Length} bytes")]
public sealed record JAdESDetachedObjectDereferenceSuccess(PooledMemory Content) : JAdESDetachedObjectDereferenceResult;


/// <summary>A failed dereference attempt (locator unreachable, an HTTP status outside the success range, an unsupported scheme).</summary>
/// <param name="Reason">A human-readable statement of why dereferencing failed.</param>
[DebuggerDisplay("JAdESDetachedObjectDereferenceFailure: {Reason}")]
public sealed record JAdESDetachedObjectDereferenceFailure(string Reason) : JAdESDetachedObjectDereferenceResult;


/// <summary>
/// Dereferences one detached-object URI-reference — the delegate seam clause 5.2.8.3.1 describes and this
/// library never implements directly (no HTTP client ships in this library). Shared by both <c>ObjectIdByURI</c> (JA-5.2.8.3.2-C3) and
/// <c>ObjectIdByURIHash</c> (JA-5.2.8.3.3-04) — the sole two mechanisms this document's dereferencing obligation
/// applies to, since <c>HttpHeaders</c> dereferences nothing.
/// </summary>
/// <remarks>
/// Never throws on a failed dereference — a network failure, a 404, or a rejected scheme is a
/// <see cref="JAdESDetachedObjectDereferenceFailure"/>, not an exception; the caller decides how to react.
/// </remarks>
/// <param name="uriReference">The URI-reference to dereference (one <c>pars</c> element, JA-5.2.8.1-16/-17).</param>
/// <param name="context">The per-call caller state; see <see cref="JAdESDetachedObjectDereferenceContext"/>.</param>
/// <param name="pool">Memory pool the fetched content is rented from.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The dereferenced content, or a failure signal.</returns>
public delegate ValueTask<JAdESDetachedObjectDereferenceResult> JAdESDetachedObjectDereferenceDelegate(
    string uriReference,
    JAdESDetachedObjectDereferenceContext context,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);


/// <summary>
/// One <c>sigD.pars</c> entry, before digest/mechanism resolution — the per-call input shape
/// <see cref="JAdESSignatureCreation"/> accepts for a detached object referenced under <c>ObjectIdByURI</c>,
/// <c>ObjectIdByURIHash</c>, or an unrecognized mechanism, mirroring
/// <see cref="CBAdESDetachedObjectReferenceInput"/> one document removed.
/// </summary>
/// <param name="Reference">The URI-reference to the detached data object (one <c>pars</c> element).</param>
/// <param name="ContentType">The content type of the referenced object (the <c>ctys</c> element at the same position), or <see langword="null"/> when absent or implied (JA-5.2.8.1-26/-29).</param>
[DebuggerDisplay("JAdESDetachedObjectReferenceInput: {Reference}")]
public sealed record JAdESDetachedObjectReferenceInput(string Reference, string? ContentType);


/// <summary>
/// Retrieves the JWS Payload for a <c>sigD.mId</c> value this document does not itself define — the open-arm
/// extension point JA-5.2.8.1-C1 reserves, mirroring <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/>.
/// </summary>
/// <remarks>
/// Scope, recorded here: this extension point covers JWS-Payload retrieval only. It never produces per-entry
/// digests — a third-party mechanism's own <c>hashM</c>/<c>hashV</c> semantics are that mechanism's
/// specification's concern.
/// </remarks>
/// <param name="mechanismIdentifier">The unrecognized <c>mId</c> value.</param>
/// <param name="references">The <c>sigD.pars</c> entries, in wire order.</param>
/// <param name="hashAlgorithm">The caller-declared <c>hashM</c>, when the payload input carried one, or <see langword="null"/>.</param>
/// <param name="context">The per-call caller state; see <see cref="JAdESDetachedObjectDereferenceContext"/>.</param>
/// <param name="pool">Memory pool the returned payload is rented from.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The JWS Payload bytes to sign over, pool-routed. Ownership transfers to the caller.</returns>
public delegate ValueTask<PooledMemory> JAdESUnknownDetachedObjectMechanismDelegate(
    string mechanismIdentifier,
    IReadOnlyList<JAdESDetachedObjectReferenceInput> references,
    string? hashAlgorithm,
    JAdESDetachedObjectDereferenceContext context,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);


/// <summary>
/// Thrown when a <c>sigD</c> payload cannot be resolved because a referenced object could not be dereferenced —
/// a creation-time operational failure, mirroring <see cref="CBAdESDetachedObjectDereferenceException"/>.
/// </summary>
public sealed class JAdESDetachedObjectDereferenceException : Exception
{
    /// <summary>Gets the URI-reference whose dereference failed, or <see langword="null"/> when unset.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "A sigD.pars URI-reference (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.3.1) may be relative " +
            "per RFC 3986 SS4.2; System.Uri normalizes on construction and is an unreliable carrier for the " +
            "exact reference string a caller passed to JAdESDetachedObjectDereferenceDelegate, mirroring " +
            "CBAdESDetachedObjectDereferenceException's identical rationale.")]
    public string? UriReference { get; }


    /// <summary>Initializes a new instance (the standard parameterless exception constructor .NET convention expects).</summary>
    public JAdESDetachedObjectDereferenceException() : base("A detached data object could not be dereferenced.")
    {
    }


    /// <summary>Initializes a new instance with a message.</summary>
    /// <param name="message">The message that describes the error.</param>
    public JAdESDetachedObjectDereferenceException(string message) : base(message)
    {
    }


    /// <summary>Initializes a new instance with a message and an inner exception.</summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of this exception.</param>
    public JAdESDetachedObjectDereferenceException(string message, Exception innerException) : base(message, innerException)
    {
    }


    /// <summary>Initializes a new instance naming the reference that failed and why.</summary>
    /// <param name="uriReference">The URI-reference whose dereference failed.</param>
    /// <param name="reason">The failure reason (see <see cref="JAdESDetachedObjectDereferenceFailure.Reason"/>).</param>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "See UriReference's own suppression justification above.")]
    public JAdESDetachedObjectDereferenceException(string uriReference, string reason)
        : base($"Failed to dereference '{uriReference}': {reason}")
    {
        UriReference = uriReference;
    }
}


/// <summary>
/// Caller-supplied HTTP message facts the <c>HttpHeaders</c> mechanism (clause 5.2.8.2) canonicalizes — pure,
/// in-library canonicalization over facts the signer already holds locally; no dereferencing, no seam.
/// </summary>
/// <param name="RequestTargetValue">
/// The pre-built <c>"(request target)"</c> pseudo-header field VALUE — lowercased method, a space, then the
/// path-absolute (and optional query) of the target URI (JA-5.2.8.2-C1) — or <see langword="null"/> when
/// <see cref="JAdESHttpHeadersReference.HeaderNames"/> never references it.
/// </param>
/// <param name="ResponseStatusValue">
/// The pre-built <c>"(response status)"</c> pseudo-header field VALUE — the status line, no trailing newline
/// (JA-5.2.8.2-C2) — or <see langword="null"/> when never referenced.
/// </param>
/// <param name="HeaderFieldValues">
/// Every ordinary HTTP header field this call may need, keyed by its lowercased name, each entry's values in
/// the order they will appear on the transmitted HTTP message (JA-5.2.8.2-06's multi-instance concatenation
/// input). The <c>"Digest"</c> pseudo-name (JA-5.2.6-07's own header-body-digest processing) is carried like any
/// other entry — this canonicalizer performs no special-casing of it beyond what clause 5.2.8.2 itself states.
/// </param>
[DebuggerDisplay("JAdESHttpHeadersCanonicalizationContext: {HeaderFieldValues.Count} header(s)")]
public sealed record JAdESHttpHeadersCanonicalizationContext(
    string? RequestTargetValue,
    string? ResponseStatusValue,
    IReadOnlyDictionary<string, IReadOnlyList<string>> HeaderFieldValues);


/// <summary>
/// The <c>sigD</c> payload-resolution seams: the <c>HttpHeaders</c> in-library canonicalization (clause 5.2.8.2)
/// and the <c>ObjectIdByURI</c>/<c>ObjectIdByURIHash</c> dereference-and-reconstruct algorithm (clauses 5.2.8.3.1
/// /.2), composed by <see cref="JAdESSignatureCreation"/>.
/// </summary>
public static class JAdESDetachedObjectDereferencing
{
    /// <summary>The wire name of the <c>"(request target)"</c> pseudo-header (JA-5.2.8.2-C1).</summary>
    public const string RequestTargetPseudoHeaderName = "(request target)";

    /// <summary>The wire name of the <c>"(response status)"</c> pseudo-header (JA-5.2.8.2-C2).</summary>
    public const string ResponseStatusPseudoHeaderName = "(response status)";

    /// <summary>The tag every buffer this class mints carries.</summary>
    private static Tag CanonicalizedPayloadTag { get; } = Tag.Create(Purpose.Data);


    /// <summary>
    /// Canonicalizes <paramref name="reference"/>'s <c>pars</c> header names into the JWS Payload bytes, per
    /// JA-5.2.8.2-05/-06 and the C1..C4 conditional steps: each pseudo-header contributes its bare VALUE
    /// (item a/b's own wording — no <c>name: </c> prefix), every ordinary header contributes
    /// <c>"name: value"</c> (item c), multiple instances of one header join with <c>", "</c> (JA-5.2.8.2-06),
    /// and every contribution is newline-joined in <c>pars</c> order (item d).
    /// </summary>
    /// <param name="reference">The <c>HttpHeaders</c> mechanism's own header-name list.</param>
    /// <param name="context">The caller-supplied HTTP message facts to canonicalize.</param>
    /// <param name="pool">Memory pool the returned payload is rented from.</param>
    /// <returns>The canonicalized JWS Payload bytes, pool-routed. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">Any argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="context"/> carries no value for a referenced pseudo-header or ordinary header name.
    /// </exception>
    public static PooledMemory Canonicalize(
        JAdESHttpHeadersReference reference,
        JAdESHttpHeadersCanonicalizationContext context,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(reference);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        var fieldStrings = new string[reference.HeaderNames.Count];
        for(int i = 0; i < reference.HeaderNames.Count; ++i)
        {
            fieldStrings[i] = BuildFieldString(reference.HeaderNames[i], context);
        }

        string joined = string.Join('\n', fieldStrings);

        return PooledMemory.FromBytes(Encoding.UTF8.GetBytes(joined), pool, CanonicalizedPayloadTag);
    }


    /// <summary>Builds one <c>pars</c> position's contribution to the canonicalized stream. See <see cref="Canonicalize"/>.</summary>
    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase",
        Justification = "JA-5.2.8.2-C3 mandates the LOWERCASED header field name on the wire -- this is a " +
            "spec-mandated output shape, not a case-insensitive comparison CA1308 guards against.")]
    private static string BuildFieldString(string name, JAdESHttpHeadersCanonicalizationContext context)
    {
        if(WellKnownJAdESHeaderNames.Equals(name, RequestTargetPseudoHeaderName))
        {
            return context.RequestTargetValue ?? throw new ArgumentException(
                $"sigD references '{RequestTargetPseudoHeaderName}' but the context carries no request-target " +
                "value (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.2).",
                nameof(context));
        }

        if(WellKnownJAdESHeaderNames.Equals(name, ResponseStatusPseudoHeaderName))
        {
            return context.ResponseStatusValue ?? throw new ArgumentException(
                $"sigD references '{ResponseStatusPseudoHeaderName}' but the context carries no response-status " +
                "value (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.2).",
                nameof(context));
        }

        if(!context.HeaderFieldValues.TryGetValue(name, out IReadOnlyList<string>? values) || values.Count == 0)
        {
            throw new ArgumentException(
                $"sigD references HTTP header '{name}' but the context carries no value for it (ETSI TS 119 " +
                "182-1 V1.2.1, clause 5.2.8.2).",
                nameof(context));
        }

        //JA-5.2.8.2-C3 verbatim: "create the header field string by concatenating the LOWERCASED header field
        //name followed with a colon ':', a space character, and the header field value. Any leading and
        //trailing white spaces are removed." The name is lowercased here too (not just relied upon from
        //JA-5.2.8.2-04's own pars-are-lowercase requirement) so this canonicalizer produces the clause-defined
        //bytes even if a caller-constructed JAdESHttpHeadersReference somehow carries a non-lowercase entry;
        //each value instance is trimmed before JA-5.2.8.2-06's own comma-space join.
        string lowercasedName = name.ToLowerInvariant();
        var trimmedValues = new string[values.Count];
        for(int i = 0; i < values.Count; ++i)
        {
            trimmedValues[i] = values[i].Trim();
        }

        return lowercasedName + ": " + string.Join(", ", trimmedValues);
    }


    /// <summary>
    /// Implements the <c>ObjectIdByURI</c> octet-stream algorithm (JA-5.2.8.3.2-C1..C5): initializes an empty
    /// stream, then for each reference in order, dereferences it (clause 5.2.8.3.1) and — when
    /// <paramref name="base64UrlEncodeEachObject"/> (the <c>b64</c> header parameter absent-or-true reading,
    /// JA-5.2.8.3.2-C4) — base64url-re-encodes the retrieved octets before concatenating. This is also the
    /// JA-5.2.8.3.3-06 reconstruction path <c>ObjectIdByURIHash</c> falls back to whenever the JWS Payload is
    /// needed for a purpose other than the JWS Signature Value computation itself.
    /// </summary>
    /// <param name="references">The ordered URI-references to dereference and concatenate, in wire (<c>pars</c>) order.</param>
    /// <param name="base64UrlEncodeEachObject">Whether each retrieved object is base64url-encoded before concatenation (JA-5.2.8.3.2-C4).</param>
    /// <param name="dereference">The dereference delegate; see <see cref="JAdESDetachedObjectDereferenceDelegate"/>.</param>
    /// <param name="context">The per-call caller state; see <see cref="JAdESDetachedObjectDereferenceContext"/>.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding, used only when <paramref name="base64UrlEncodeEachObject"/> is <see langword="true"/>.</param>
    /// <param name="pool">Memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The concatenated octet stream, pool-routed. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">Any required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="references"/> is empty (JA-5.2.8.1-16).</exception>
    /// <exception cref="JAdESDetachedObjectDereferenceException">A referenced object could not be dereferenced.</exception>
    public static async ValueTask<PooledMemory> ReconstructObjectIdByUriPayloadAsync(
        IReadOnlyList<JAdESDetachedObjectReferenceInput> references,
        bool base64UrlEncodeEachObject,
        JAdESDetachedObjectDereferenceDelegate dereference,
        JAdESDetachedObjectDereferenceContext context,
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(references);
        ArgumentNullException.ThrowIfNull(dereference);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);
        if(references.Count == 0)
        {
            throw new ArgumentException(
                "sigD's 'pars' member shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1, " +
                "JA-5.2.8.1-16).",
                nameof(references));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var contributions = new PooledMemory[references.Count];
        int contributedCount = 0;
        try
        {
            int totalLength = 0;
            for(int i = 0; i < references.Count; ++i)
            {
                cancellationToken.ThrowIfCancellationRequested();

                JAdESDetachedObjectDereferenceResult result = await dereference(
                    references[i].Reference, context, pool, cancellationToken).ConfigureAwait(false);

                if(result is not JAdESDetachedObjectDereferenceSuccess success)
                {
                    string reason = result is JAdESDetachedObjectDereferenceFailure failure
                        ? failure.Reason
                        : "the dereference delegate returned neither a success nor a failure result.";

                    throw new JAdESDetachedObjectDereferenceException(references[i].Reference, reason);
                }

                //Per-element base64url re-encoding (JA-5.2.8.3.2-C4) mints a NEW pooled buffer from the encoded
                //text and releases the raw dereferenced one immediately; the unencoded arm keeps the original
                //dereferenced buffer as-is -- either way exactly one PooledMemory per reference survives into
                //`contributions` for the final concatenation pass below.
                if(base64UrlEncodeEachObject)
                {
                    using(success.Content)
                    {
                        contributions[i] = PooledMemory.FromBytes(
                            Encoding.ASCII.GetBytes(base64UrlEncoder(success.Content.AsReadOnlySpan())),
                            pool,
                            CanonicalizedPayloadTag);
                    }
                }
                else
                {
                    contributions[i] = success.Content;
                }

                contributedCount = i + 1;
                totalLength += contributions[i].Length;
            }

            IMemoryOwner<byte> owner = pool.Rent(Math.Max(totalLength, 1));
            int offset = 0;
            for(int i = 0; i < contributions.Length; ++i)
            {
                ReadOnlySpan<byte> content = contributions[i].AsReadOnlySpan();
                content.CopyTo(owner.Memory.Span[offset..]);
                offset += content.Length;
            }

            return new PooledMemory(owner, totalLength, CanonicalizedPayloadTag);
        }
        finally
        {
            for(int i = 0; i < contributedCount; ++i)
            {
                contributions[i]?.Dispose();
            }
        }
    }
}
