using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The B-B structural-and-cryptographic facts a successful <see cref="JAdESSignatureValidation.ValidateAsync"/>
/// call promotes into a <see cref="Verified{T}"/> — the record a relying party consumes once verification has
/// succeeded — JAdES's result surfaces are the family's FIRST promotion-shaped template.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns <see cref="Headers"/> and <see cref="UnsignedHeaders"/> (when
/// present); <see cref="Dispose"/> disposes both.
/// </remarks>
[DebuggerDisplay("JAdESVerifiedSignatureFacts: alg={Headers.Algorithm}")]
public sealed class JAdESVerifiedSignatureFacts: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="JAdESVerifiedSignatureFacts"/>. Ownership of <paramref name="headers"/> and
    /// <paramref name="unsignedHeaders"/> (when supplied) transfers to this instance. Internal — minted only by
    /// <see cref="JAdESSignatureValidation"/>, which alone holds the <see cref="Verified{T}"/> minting access
    /// this type exists to be wrapped by.
    /// </summary>
    /// <param name="headers">See <see cref="Headers"/>.</param>
    /// <param name="payloadIsDetached">See <see cref="PayloadIsDetached"/>.</param>
    /// <param name="unsignedHeaders">See <see cref="UnsignedHeaders"/>.</param>
    /// <param name="level">See <see cref="Level"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="headers"/> is <see langword="null"/>.</exception>
    internal JAdESVerifiedSignatureFacts(
        JAdESProtectedHeaders headers, bool payloadIsDetached, JAdESUnsignedHeaders? unsignedHeaders, AdESBaselineLevel? level = null)
    {
        ArgumentNullException.ThrowIfNull(headers);

        Headers = headers;
        PayloadIsDetached = payloadIsDetached;
        UnsignedHeaders = unsignedHeaders;
        Level = level;
    }


    /// <summary>
    /// Gets the decoded, B-B-conformant signed-header-set aggregate — every clause 5.1/5.2 member the signature
    /// verified over, including <see cref="JAdESProtectedHeaders.SigT"/> when the signature carries the legacy
    /// member (read-tolerated, never creation-emitted) and <see cref="JAdESProtectedHeaders.IssuedAt"/> the
    /// mandatory replacement. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public JAdESProtectedHeaders Headers { get; }

    /// <summary>Gets whether the JWS Payload this signature covers is detached (JA-4-07).</summary>
    public bool PayloadIsDetached { get; }

    /// <summary>
    /// Gets the decoded <c>etsiU</c> unsigned-header set when the signature incorporates one, structurally
    /// decoded (structural scope — the message-imprint algorithms over its byte-exact carriage are the
    /// level-aware validation pass's territory); <see langword="null"/> when no unprotected header (or no <c>etsiU</c> member within it) was
    /// present. Owned by this instance when present; disposed via <see cref="Dispose"/>.
    /// </summary>
    public JAdESUnsignedHeaders? UnsignedHeaders { get; }

    /// <summary>
    /// Gets the <see cref="AdESBaselineLevel"/> this instance was validated against, when produced by one of
    /// <see cref="JAdESSignatureValidation"/>'s level-aware <c>ValidateAsync</c> overloads; <see langword="null"/>
    /// when produced by the B-B-only overloads, which never evaluate a single Table 1 level rule.
    /// </summary>
    public AdESBaselineLevel? Level { get; }


    /// <summary>Disposes <see cref="Headers"/> and <see cref="UnsignedHeaders"/> when present.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Headers.Dispose();
            UnsignedHeaders?.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// The outcome of validating a JAdES signature — a <see cref="Verified{T}"/>-wrapped
/// <see cref="JAdESVerifiedSignatureFacts"/> when <see cref="IsValid"/> is <see langword="true"/>, or a
/// closed-sum failure detail otherwise. Produced by <see cref="JAdESSignatureValidation.ValidateAsync"/>, the
/// JAdES counterpart of <see cref="CBAdESValidationResult"/> — built PROMOTION-SHAPED from the outset.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Mint-only.</strong> The constructor and the <see cref="Success"/>/<see cref="Failed"/> factories are
/// <see langword="internal"/>, so a result with <see cref="IsValid"/> <see langword="true"/> — and therefore a
/// non-null <see cref="Verified"/> — can only originate from <see cref="JAdESSignatureValidation"/>.
/// </para>
/// <para>
/// <strong>Decoded facts survive a post-parse failure, mirroring CB-AdES's validation result.</strong> On
/// every failure arm reached only after the wire bytes and protected header decoded successfully —
/// <see cref="JAdESRuleViolationsFailure"/>, <see cref="JAdESSignatureInvalidFailure"/>,
/// <see cref="JAdESDetachedObjectUnresolvableFailure"/>, <see cref="JAdESDetachedObjectDigestMismatchFailure"/> —
/// <see cref="Headers"/> and <see cref="UnsignedHeaders"/> carry whatever decoded before hitting the failure, so a
/// FAILED/INDETERMINATE conclusion (a later stage's EN 319 102-1 mapping) can cite what it saw. Ownership
/// transfers exactly once: <see cref="Headers"/>/<see cref="UnsignedHeaders"/> are reachable EITHER through this
/// property pair (every failure arm) OR through <see cref="Verified"/>'s wrapped
/// <see cref="JAdESVerifiedSignatureFacts"/> (success) — never both on the same result. Only
/// <see cref="JAdESMalformedEncodingFailure"/> carries no facts: reached before or during parsing, when nothing
/// has decoded yet to hand over.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESValidationResult: IsValid={IsValid}")]
public sealed class JAdESValidationResult: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="JAdESValidationResult"/>. Internal — see the type remarks for the mint-only
    /// rationale.
    /// </summary>
    /// <param name="isValid">See <see cref="IsValid"/>.</param>
    /// <param name="verified">See <see cref="Verified"/>. Ownership transfers to this instance when supplied.</param>
    /// <param name="headers">See <see cref="Headers"/>. Ownership transfers to this instance when supplied.</param>
    /// <param name="unsignedHeaders">See <see cref="UnsignedHeaders"/>. Ownership transfers to this instance when supplied.</param>
    /// <param name="failure">See <see cref="Failure"/>.</param>
    /// <param name="level">See <see cref="Level"/>.</param>
    internal JAdESValidationResult(
        bool isValid,
        Verified<JAdESVerifiedSignatureFacts>? verified,
        JAdESProtectedHeaders? headers,
        JAdESUnsignedHeaders? unsignedHeaders,
        JAdESValidationFailure? failure,
        AdESBaselineLevel? level = null)
    {
        IsValid = isValid;
        Verified = verified;
        Headers = headers;
        UnsignedHeaders = unsignedHeaders;
        Failure = failure;
        Level = level;
    }


    /// <summary>Whether the JAdES signature is structurally conformant and cryptographically valid.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the promoted, verified facts when <see cref="IsValid"/> is <see langword="true"/>; otherwise
    /// <see langword="null"/>. The sole route through which this library hands a relying party a
    /// <see cref="Verified{JAdESVerifiedSignatureFacts}"/> — no other member of this type carries proof of
    /// verification. Owned by this instance when present; disposed via <see cref="Dispose"/>.
    /// </summary>
    public Verified<JAdESVerifiedSignatureFacts>? Verified { get; }

    /// <summary>
    /// Gets the decoded signed-header-set aggregate when validation failed on an arm reached only after the wire
    /// bytes and protected header decoded successfully (see the type remarks); <see langword="null"/> on
    /// <see cref="IsValid"/> <see langword="true"/> (reachable via <see cref="Verified"/> instead) or on
    /// <see cref="JAdESMalformedEncodingFailure"/>. Owned by this instance when non-null; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public JAdESProtectedHeaders? Headers { get; }

    /// <summary>
    /// Gets the decoded <c>etsiU</c> unsigned-header set under the same failure-arm-only availability as
    /// <see cref="Headers"/>; <see langword="null"/> on <see cref="IsValid"/> <see langword="true"/> (reachable
    /// via <see cref="Verified"/> instead), when no <c>etsiU</c> was present, or on
    /// <see cref="JAdESMalformedEncodingFailure"/>. Owned by this instance when non-null; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public JAdESUnsignedHeaders? UnsignedHeaders { get; }

    /// <summary>Gets the failure detail when <see cref="IsValid"/> is <see langword="false"/>; otherwise <see langword="null"/>.</summary>
    public JAdESValidationFailure? Failure { get; }

    /// <summary>
    /// Gets the <see cref="AdESBaselineLevel"/> this result was validated against, when produced by one of
    /// <see cref="JAdESSignatureValidation"/>'s level-aware <c>ValidateAsync</c> overloads — populated on
    /// BOTH a level-aware success (mirrored onto <see cref="Verified"/>'s own wrapped
    /// <see cref="JAdESVerifiedSignatureFacts.Level"/>) and a level-aware failure, so a caller can always tell
    /// which level a validation call checked against without unwrapping <see cref="Verified"/> first.
    /// <see langword="null"/> for the B-B-only overloads, which never evaluate a single Table 1 level
    /// rule.
    /// </summary>
    public AdESBaselineLevel? Level { get; }


    /// <summary>
    /// Mints a successful result, promoting <paramref name="headers"/>/<paramref name="unsignedHeaders"/> into a
    /// <see cref="Verified{JAdESVerifiedSignatureFacts}"/> minted with <paramref name="provenance"/>. Ownership of
    /// both transfers to the returned instance's <see cref="Verified"/> member. Internal so only
    /// <see cref="JAdESSignatureValidation"/> can produce one.
    /// </summary>
    /// <param name="headers">The decoded, B-B-conformant signed-header-set aggregate.</param>
    /// <param name="payloadIsDetached">Whether the JWS Payload this signature covers is detached.</param>
    /// <param name="unsignedHeaders">The decoded <c>etsiU</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="provenance">The verification provenance the minted <see cref="Verified{T}"/> carries.</param>
    /// <param name="level">The level this result was checked against, or <see langword="null"/> for the B-B-only overloads.</param>
    /// <returns>A valid result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "facts wraps headers/unsignedHeaders by reference (no new disposable resource of its " +
            "own) and is immediately wrapped into the Verified<JAdESVerifiedSignatureFacts> this factory " +
            "returns inside the resulting JAdESValidationResult -- ownership transfers to the caller of " +
            "Success, which owns and disposes the returned result (and therefore facts) via JAdESValidationResult.Dispose.")]
    internal static JAdESValidationResult Success(
        JAdESProtectedHeaders headers,
        bool payloadIsDetached,
        JAdESUnsignedHeaders? unsignedHeaders,
        AssertedProvenance provenance,
        AdESBaselineLevel? level = null)
    {
        var facts = new JAdESVerifiedSignatureFacts(headers, payloadIsDetached, unsignedHeaders, level);
        var verified = Verified<JAdESVerifiedSignatureFacts>.CreateAsserted(facts, provenance);

        return new(true, verified, null, null, null, level);
    }


    /// <summary>
    /// Mints a successful, IDENTITY-BOUND result over <paramref name="facts"/> — the certificate-accepting
    /// <see cref="JAdESSignatureValidation.ValidateAsync"/> overload's own terminal step. Unlike
    /// <see cref="Success"/>, this takes the already-constructed <paramref name="facts"/> rather than building
    /// one, because <paramref name="provenance"/> must have been established (<c>BoundProvenance.TryBindByCertificateDigestAsync</c>)
    /// AGAINST that exact instance before this method is called — <see cref="Verified{T}.TryCreateBound"/>'s own
    /// witness check refuses a provenance minted for a different value. Internal so only
    /// <see cref="JAdESSignatureValidation"/> can produce one.
    /// </summary>
    /// <param name="facts">The already-constructed facts <paramref name="provenance"/> was established for. Ownership transfers to the returned instance's <see cref="Verified"/> member on success.</param>
    /// <param name="provenance">The already-minted identity binding for <paramref name="facts"/>.</param>
    /// <returns>A valid, bound result, or <see langword="null"/> when <paramref name="provenance"/> does not witness <paramref name="facts"/> (should not occur when the caller passes the exact instance it bound).</returns>
    /// <exception cref="ArgumentNullException"><paramref name="facts"/> or <paramref name="provenance"/> is <see langword="null"/>.</exception>
    internal static JAdESValidationResult? SuccessBound(JAdESVerifiedSignatureFacts facts, BoundProvenance provenance)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(provenance);

        Verified<JAdESVerifiedSignatureFacts>? verified = Verified<JAdESVerifiedSignatureFacts>.TryCreateBound(facts, provenance);
        if(verified is null)
        {
            return null;
        }

        return new(true, verified, null, null, null, facts.Level);
    }


    /// <summary>
    /// Mints a failed result carrying no decoded facts — <see cref="JAdESMalformedEncodingFailure"/> only, where
    /// nothing decoded before the failure. Internal so only <see cref="JAdESSignatureValidation"/> can produce one.
    /// </summary>
    /// <param name="failure">The failure detail.</param>
    /// <returns>An invalid result.</returns>
    internal static JAdESValidationResult Failed(JAdESValidationFailure failure) =>
        new(false, null, null, null, failure);


    /// <summary>
    /// Mints a failed result that carries the decoded facts known at the point of failure.
    /// Ownership of <paramref name="headers"/> and <paramref name="unsignedHeaders"/> (when supplied) transfers
    /// to the returned instance. Internal so only <see cref="JAdESSignatureValidation"/> can produce one.
    /// </summary>
    /// <param name="failure">The failure detail.</param>
    /// <param name="headers">The decoded signed-header-set aggregate known at the point of failure.</param>
    /// <param name="unsignedHeaders">The decoded <c>etsiU</c> set known at the point of failure, or <see langword="null"/> when absent.</param>
    /// <param name="level">The level this call was checking against, or <see langword="null"/> for the B-B-only overloads.</param>
    /// <returns>An invalid result carrying the decoded facts.</returns>
    internal static JAdESValidationResult Failed(
        JAdESValidationFailure failure,
        JAdESProtectedHeaders headers,
        JAdESUnsignedHeaders? unsignedHeaders,
        AdESBaselineLevel? level = null) =>
        new(false, null, headers, unsignedHeaders, failure, level);


    /// <summary>Disposes <see cref="Verified"/>'s wrapped facts, <see cref="Headers"/>, and <see cref="UnsignedHeaders"/> when present.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Verified?.Value.Dispose();
            Headers?.Dispose();
            UnsignedHeaders?.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// Why a <see cref="JAdESValidationResult"/> failed — a DU-ready closed sum: no external type may derive from it.
/// </summary>
public abstract class JAdESValidationFailure
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected JAdESValidationFailure()
    {
    }


    /// <summary>Gets a human-readable statement of the failure.</summary>
    public abstract string Message { get; }
}


/// <summary>
/// The wire bytes are not a well-formed JAdES message under any of the three JWS serializations, or its
/// protected header does not decode — the parse seam either returned failure or raised one of the fail-closed
/// exception types <see cref="JAdESSignatureValidation"/> catches (parsing of untrusted bytes never throws
/// out of the validation orchestrator).
/// </summary>
/// <remarks>
/// There is no state to tell two of these apart: the whole content of the case is that the bytes did not
/// decode. Equality reflects that, so a caller can compare against the case it expected instead of testing the
/// type by hand.
/// </remarks>
public sealed class JAdESMalformedEncodingFailure: JAdESValidationFailure, IEquatable<JAdESMalformedEncodingFailure>
{
    /// <inheritdoc/>
    public override string Message => "The wire bytes do not decode as a well-formed JAdES signature.";

    /// <inheritdoc/>
    public bool Equals(JAdESMalformedEncodingFailure? other)
    {
        return other is not null;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as JAdESMalformedEncodingFailure);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Message);
    }

    /// <summary>Reports whether two malformed-encoding failures are the same finding (always true for any two instances).</summary>
    public static bool operator ==(JAdESMalformedEncodingFailure? left, JAdESMalformedEncodingFailure? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two malformed-encoding failures are different findings (always false for any two instances).</summary>
    public static bool operator !=(JAdESMalformedEncodingFailure? left, JAdESMalformedEncodingFailure? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The wire bytes decoded successfully, but at least one B-B conformance rule (<see cref="JAdESHeaderRules.Check"/>)
/// is violated.
/// </summary>
[DebuggerDisplay("JAdESRuleViolationsFailure: {Violations.Count} violation(s)")]
public sealed class JAdESRuleViolationsFailure: JAdESValidationFailure
{
    /// <summary>Initializes a new <see cref="JAdESRuleViolationsFailure"/>.</summary>
    /// <param name="violations">Every violation found, in rule-declaration order. Never empty.</param>
    public JAdESRuleViolationsFailure(IReadOnlyList<JAdESRuleViolation> violations)
    {
        Violations = violations;
    }

    /// <summary>Every violation found, in rule-declaration order. Never empty.</summary>
    public IReadOnlyList<JAdESRuleViolation> Violations { get; }

    /// <inheritdoc/>
    public override string Message => $"{Violations.Count} B-B conformance rule violation(s); see {nameof(Violations)}.";
}


/// <summary>
/// Every B-B conformance rule holds and the verification payload resolved successfully, but the JWS signature
/// value does not verify over it (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 §5.2</see>).
/// </summary>
/// <remarks>
/// The case is stateless — a signature either verified or it did not — so every instance of it says exactly
/// the same thing and equality treats them as one.
/// </remarks>
public sealed class JAdESSignatureInvalidFailure: JAdESValidationFailure, IEquatable<JAdESSignatureInvalidFailure>
{
    /// <inheritdoc/>
    public override string Message => "The JWS signature value does not verify over the resolved payload.";

    /// <inheritdoc/>
    public bool Equals(JAdESSignatureInvalidFailure? other)
    {
        return other is not null;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as JAdESSignatureInvalidFailure);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Message);
    }

    /// <summary>Reports whether two signature-invalid failures are the same finding (always true for any two instances).</summary>
    public static bool operator ==(JAdESSignatureInvalidFailure? left, JAdESSignatureInvalidFailure? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two signature-invalid failures are different findings (always false for any two instances).</summary>
    public static bool operator !=(JAdESSignatureInvalidFailure? left, JAdESSignatureInvalidFailure? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The certificate-accepting <see cref="JAdESSignatureValidation.ValidateAsync"/> overload could not establish
/// an identity binding for the supplied signing certificate — either the certificate itself is not one
/// this binding can verify under (not an elliptic curve this library resolves, or not well-formed X.509), or the
/// JWS signature value DID verify but the recomputed digest of the certificate it verified under does not match
/// the protected header's own signing-certificate-identification commitment (<c>x5t#S256</c>/<c>x5t#o</c>/first
/// <c>sigX5ts</c> entry) — the bind-to-X/verify-under-Y hazard — or no such commitment resolves at all. The
/// bare-<see cref="Verifiable.Cryptography.PublicKeyMemory"/> overloads never bind and never report this failure.
/// </summary>
/// <remarks>
/// Beyond being this case, all the failure carries is the stated reason, so equality is that reason compared
/// ordinally — the text is a diagnostic to be matched exactly, not collated.
/// </remarks>
[DebuggerDisplay("JAdESSigningCertificateBindingFailure: {Reason}")]
public sealed class JAdESSigningCertificateBindingFailure: JAdESValidationFailure, IEquatable<JAdESSigningCertificateBindingFailure>
{
    /// <summary>Initializes a new <see cref="JAdESSigningCertificateBindingFailure"/>.</summary>
    /// <param name="reason">What this binding could state about why the identity binding could not be established.</param>
    public JAdESSigningCertificateBindingFailure(string reason)
    {
        Reason = reason;
    }

    /// <summary>What this binding could state about why the identity binding could not be established.</summary>
    public string Reason { get; }

    /// <inheritdoc/>
    public override string Message => Reason;

    /// <inheritdoc/>
    public bool Equals(JAdESSigningCertificateBindingFailure? other)
    {
        return other is not null && string.Equals(Reason, other.Reason, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as JAdESSigningCertificateBindingFailure);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Reason);
    }

    /// <summary>Reports whether two binding failures state the same reason.</summary>
    public static bool operator ==(JAdESSigningCertificateBindingFailure? left, JAdESSigningCertificateBindingFailure? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two binding failures state a different reason.</summary>
    public static bool operator !=(JAdESSigningCertificateBindingFailure? left, JAdESSigningCertificateBindingFailure? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The verification payload could not be resolved — the caller supplied no external payload for a detached,
/// unreferenced JWS Payload; a <c>sigD</c> mechanism's dereference delegate reported failure, or its required
/// context/delegate was not supplied; or <c>sigD</c> named a mechanism this document does not define and either
/// no caller-supplied mechanism handler was provided, or the handler reported failure.
/// </summary>
/// <remarks>
/// The case is identified by the pair it reports — which reference failed, and why — so equality compares both
/// ordinally, an absent <see cref="Reference"/> included: a failure tied to no single reference is a different
/// statement from one that names it.
/// </remarks>
[DebuggerDisplay("JAdESDetachedObjectUnresolvableFailure: {Reference}")]
public sealed class JAdESDetachedObjectUnresolvableFailure: JAdESValidationFailure, IEquatable<JAdESDetachedObjectUnresolvableFailure>
{
    /// <summary>Initializes a new <see cref="JAdESDetachedObjectUnresolvableFailure"/>.</summary>
    /// <param name="reference">
    /// The <c>pars</c> reference whose dereference failed, or <see langword="null"/> when the failure is not tied to
    /// a single reference (an out-of-band detached payload with no caller-supplied bytes; an unknown mechanism with
    /// no handler; a missing dereference context).
    /// </param>
    /// <param name="reason">A human-readable statement of why the payload could not be resolved.</param>
    public JAdESDetachedObjectUnresolvableFailure(string? reference, string reason)
    {
        Reference = reference;
        Reason = reason;
    }

    /// <summary>
    /// The <c>pars</c> reference whose dereference failed, or <see langword="null"/> when the failure is not tied to
    /// a single reference (an out-of-band detached payload with no caller-supplied bytes; an unknown mechanism with
    /// no handler; a missing dereference context).
    /// </summary>
    public string? Reference { get; }

    /// <summary>A human-readable statement of why the payload could not be resolved.</summary>
    public string Reason { get; }

    /// <inheritdoc/>
    public override string Message => Reason;

    /// <inheritdoc/>
    public bool Equals(JAdESDetachedObjectUnresolvableFailure? other)
    {
        return other is not null
            && string.Equals(Reference, other.Reference, StringComparison.Ordinal)
            && string.Equals(Reason, other.Reason, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as JAdESDetachedObjectUnresolvableFailure);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Reference, Reason);
    }

    /// <summary>Reports whether two unresolvable-object failures state the same reference and reason.</summary>
    public static bool operator ==(JAdESDetachedObjectUnresolvableFailure? left, JAdESDetachedObjectUnresolvableFailure? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two unresolvable-object failures state a different reference or reason.</summary>
    public static bool operator !=(JAdESDetachedObjectUnresolvableFailure? left, JAdESDetachedObjectUnresolvableFailure? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// Under the <c>ObjectIdByURIHash</c> mechanism, the dereferenced object's digest (computed via the registered
/// digest delegate over the algorithm identified by <c>hashM</c>) does not match the signed <c>hashV</c> entry
/// at the same position (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.3.3, JA-5.2.8.3.3-04).
/// </summary>
/// <remarks>
/// Which reference mismatched is the whole of what this case adds, so equality is that reference compared
/// ordinally against another's — the <c>pars</c> entry exactly as the signed header spells it.
/// </remarks>
[DebuggerDisplay("JAdESDetachedObjectDigestMismatchFailure: {Reference}")]
public sealed class JAdESDetachedObjectDigestMismatchFailure: JAdESValidationFailure, IEquatable<JAdESDetachedObjectDigestMismatchFailure>
{
    /// <summary>Initializes a new <see cref="JAdESDetachedObjectDigestMismatchFailure"/>.</summary>
    /// <param name="reference">The <c>pars</c> reference whose digest did not match.</param>
    public JAdESDetachedObjectDigestMismatchFailure(string reference)
    {
        Reference = reference;
    }

    /// <summary>The <c>pars</c> reference whose digest did not match.</summary>
    public string Reference { get; }

    /// <inheritdoc/>
    public override string Message =>
        $"The digest of the detached object referenced by '{Reference}' does not match its signed hashV entry " +
        "(ETSI TS 119 182-1 V1.2.1, clause 5.2.8.3.3, JA-5.2.8.3.3-04).";

    /// <inheritdoc/>
    public bool Equals(JAdESDetachedObjectDigestMismatchFailure? other)
    {
        return other is not null && string.Equals(Reference, other.Reference, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as JAdESDetachedObjectDigestMismatchFailure);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Reference);
    }

    /// <summary>Reports whether two digest-mismatch failures name the same reference.</summary>
    public static bool operator ==(JAdESDetachedObjectDigestMismatchFailure? left, JAdESDetachedObjectDigestMismatchFailure? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two digest-mismatch failures name a different reference.</summary>
    public static bool operator !=(JAdESDetachedObjectDigestMismatchFailure? left, JAdESDetachedObjectDigestMismatchFailure? right)
    {
        return !(left == right);
    }
}
