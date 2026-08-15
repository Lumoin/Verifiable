using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The B-B structural-and-cryptographic facts a successful <see cref="CBAdESSignatureValidation.ValidateAsync"/>
/// call promotes into a <see cref="Verified{T}"/> — the record a relying party consumes once verification has
/// succeeded (the CB-AdES transposition of <see cref="JAdESVerifiedSignatureFacts"/>).
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns <see cref="Headers"/> and <see cref="UnsignedHeaders"/> (when
/// present); <see cref="Dispose"/> disposes both.
/// </remarks>
[DebuggerDisplay("CBAdESVerifiedSignatureFacts: alg={Headers.Algorithm}")]
public sealed class CBAdESVerifiedSignatureFacts: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CBAdESVerifiedSignatureFacts"/>. Ownership of <paramref name="headers"/> and
    /// <paramref name="unsignedHeaders"/> (when supplied) transfers to this instance. Internal — minted only by
    /// <see cref="CBAdESSignatureValidation"/>, which alone holds the <see cref="Verified{T}"/> minting access
    /// this type exists to be wrapped by.
    /// </summary>
    /// <param name="headers">See <see cref="Headers"/>.</param>
    /// <param name="payloadIsDetached">See <see cref="PayloadIsDetached"/>.</param>
    /// <param name="unsignedHeaders">See <see cref="UnsignedHeaders"/>.</param>
    /// <param name="level">See <see cref="Level"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="headers"/> is <see langword="null"/>.</exception>
    internal CBAdESVerifiedSignatureFacts(
        CBAdESProtectedHeaders headers, bool payloadIsDetached, CBAdESUnsignedHeaders? unsignedHeaders, AdESBaselineLevel? level = null)
    {
        ArgumentNullException.ThrowIfNull(headers);

        Headers = headers;
        PayloadIsDetached = payloadIsDetached;
        UnsignedHeaders = unsignedHeaders;
        Level = level;
    }


    /// <summary>
    /// Gets the decoded, B-B-conformant signed-header-set aggregate. Owned by this instance; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public CBAdESProtectedHeaders Headers { get; }

    /// <summary>Gets whether the COSE Payload this signature covers is detached (clause 4.5).</summary>
    public bool PayloadIsDetached { get; }

    /// <summary>
    /// Gets the decoded <c>uHeaders</c> unsigned-header set when the signature incorporates one;
    /// <see langword="null"/> when no unprotected header (or no relevant member within it) was present. Owned
    /// by this instance when present; disposed via <see cref="Dispose"/>.
    /// </summary>
    public CBAdESUnsignedHeaders? UnsignedHeaders { get; }

    /// <summary>
    /// Gets the <see cref="AdESBaselineLevel"/> this instance was validated against, when produced by one of
    /// <see cref="CBAdESSignatureValidation"/>'s level-aware <c>ValidateAsync</c> overloads; <see langword="null"/>
    /// when produced by the B-B-only overloads, which never evaluate a single level-scoped rule.
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
/// The outcome of validating a CB-AdES <c>COSE_Sign1</c> structure — the decoded facts when
/// <see cref="IsValid"/> is <see langword="true"/>, or a closed-sum failure detail otherwise. Produced by
/// <see cref="CBAdESSignatureValidation"/>'s <c>ValidateAsync</c> overloads, the CB-AdES counterpart of
/// <see cref="Verifiable.Cbor.CoseVerificationResult"/> (mint-only pattern) and
/// <c>Verifiable.Cryptography.Pki.SignatureValidationOutcome</c> (owns disposable carriers).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Mint-only.</strong> The constructor and the <see cref="Success"/>/<see cref="Failed"/> factories
/// are <see langword="internal"/>, so a result with <see cref="IsValid"/> <see langword="true"/> can only
/// originate from <see cref="CBAdESSignatureValidation"/> — application code cannot fabricate a "valid"
/// result. This mirrors <see cref="Verifiable.Cbor.CoseVerificationResult"/>'s mint-only shape; the
/// difference — a sealed class rather than a readonly record struct — follows from ownership: this result
/// carries <see cref="Headers"/> and <see cref="UnsignedHeaders"/>, both of which own pool-rented carriers
/// (component models such as <see cref="AdESCertificateThumbprint"/>/<see cref="CBAdESDetachedObjects"/>),
/// so the result itself must be <see cref="IDisposable"/> — a value-type record struct cannot express that.
/// </para>
/// <para>
/// <strong>Scope boundary.</strong> This is the structural-conformance-plus-cryptographic-verification
/// verdict — every clause-5 signed/unsigned header rule <see cref="CBAdESHeaderRules"/> enforces, the COSE
/// signature-value check itself, over caller-provided key material, and, on the level-aware
/// <see cref="CBAdESSignatureValidation.ValidateAsync(ReadOnlyMemory{byte}, ParseCBAdESSign1Delegate, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, ReadOnlyMemory{byte}?, CBAdESUnknownDetachedObjectMechanismDelegate?, AdESBaselineLevel, BuildPayloadTimestampMessageImprintInputDelegate, TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate, TryBuildReferencesOnlyTimestampMessageImprintInputDelegate, BaseMemoryPool, CancellationToken)"/>
/// overloads, every B-T/B-LT/B-LTA level-scoped rule <see cref="Verifiable.Cryptography.Pki.CBAdESLevelRules"/>
/// enforces plus the message-imprint binding of every electronic time-stamp token this signature carries. It
/// remains certificate-path-neutral at EVERY level this type's <see cref="IsValid"/> can report: certificate-
/// path trust and revocation are NEVER resolved, chained, or validated, at any level — opening a time-stamp
/// token only checks that token's OWN CMS signature, never a chain to a trust anchor for the Time-Stamping
/// Authority. This is NOT an
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1</see> Indication/SubIndication conclusion at any level — mapping any of this onto the
/// EN 319 102-1 vocabulary is out of scope for this type.
/// </para>
/// <para>
/// <strong>Decoded facts survive a post-parse failure — a
/// FAILURE-ARM-ONLY behavior.</strong> On every failure arm reached only after the wire bytes parsed
/// successfully — <see cref="CBAdESRuleViolationsFailure"/>, <see cref="CBAdESSignatureInvalidFailure"/>,
/// <see cref="CBAdESDetachedObjectUnresolvableFailure"/>, and <see cref="CBAdESDetachedObjectDigestMismatchFailure"/>
/// — <see cref="Headers"/> and <see cref="UnsignedHeaders"/> carry whatever the orchestrator decoded before
/// hitting the failure, so a FAILED/INDETERMINATE EN 319 102-1 conclusion can cite what it saw (Table 6's
/// <c>ReportData</c>, e.g. naming which header or rule failed). Only <see cref="CBAdESMalformedEncodingFailure"/>
/// carries no facts: it is reached before or during parsing, when nothing has decoded yet to hand over.
/// </para>
/// <para>
/// <strong>Ownership — exactly one owner, never both (the JAdES-mirrored promotion shape).</strong> On
/// success, the decoded facts are reachable ONLY through <see cref="Verified"/>'s wrapped
/// <see cref="CBAdESVerifiedSignatureFacts"/> — <see cref="Headers"/>, <see cref="UnsignedHeaders"/>, and
/// <see cref="PayloadIsDetached"/> are all <see langword="null"/>/<see langword="false"/> on this result itself.
/// On failure, they are reachable through this result's own <see cref="Headers"/>/<see cref="UnsignedHeaders"/>
/// properties instead (the failure-arm-only carriage above), and <see cref="Verified"/> is <see langword="null"/>.
/// <see cref="Dispose"/> disposes whichever side actually owns them. The verified payload bytes and the
/// underlying <see cref="CoseSign1Message"/> are NOT carried by this result — the orchestrator disposes its own
/// <see cref="CoseSign1Message"/> before returning, since nothing here
/// asks for the payload bytes to survive the call; a future consumer that needs them composes its own read of the
/// same wire bytes rather than this type growing an unrequested member.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESValidationResult: IsValid={IsValid}")]
public sealed class CBAdESValidationResult: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CBAdESValidationResult"/>. Internal — see the type remarks for the
    /// mint-only rationale.
    /// </summary>
    /// <param name="isValid">See <see cref="IsValid"/>.</param>
    /// <param name="verified">See <see cref="Verified"/>. Ownership transfers to this instance when supplied.</param>
    /// <param name="headers">See <see cref="Headers"/>. Ownership transfers to this instance when supplied.</param>
    /// <param name="payloadIsDetached">See <see cref="PayloadIsDetached"/>.</param>
    /// <param name="unsignedHeaders">See <see cref="UnsignedHeaders"/>. Ownership transfers to this instance when supplied.</param>
    /// <param name="failure">See <see cref="Failure"/>.</param>
    internal CBAdESValidationResult(
        bool isValid,
        Verified<CBAdESVerifiedSignatureFacts>? verified,
        CBAdESProtectedHeaders? headers,
        bool payloadIsDetached,
        CBAdESUnsignedHeaders? unsignedHeaders,
        CBAdESValidationFailure? failure)
    {
        IsValid = isValid;
        Verified = verified;
        Headers = headers;
        PayloadIsDetached = payloadIsDetached;
        UnsignedHeaders = unsignedHeaders;
        Failure = failure;
    }


    /// <summary>Whether the CB-AdES signature is structurally conformant and cryptographically valid.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the promoted, verified facts when <see cref="IsValid"/> is <see langword="true"/>; otherwise
    /// <see langword="null"/>. The sole route through which this library hands a relying party a
    /// <see cref="Verified{CBAdESVerifiedSignatureFacts}"/> — no other member of this type carries proof of
    /// verification. Owned by this instance when present; disposed via <see cref="Dispose"/>.
    /// </summary>
    public Verified<CBAdESVerifiedSignatureFacts>? Verified { get; }

    /// <summary>
    /// Gets the decoded signed-header-set aggregate when validation failed on an arm reached only after the
    /// wire bytes parsed successfully (see the type remarks); <see langword="null"/> on <see cref="IsValid"/>
    /// <see langword="true"/> (reachable via <see cref="Verified"/> instead) or on
    /// <see cref="CBAdESMalformedEncodingFailure"/>, where nothing decoded. Owned by this instance when
    /// non-null; disposed via <see cref="Dispose"/>.
    /// </summary>
    public CBAdESProtectedHeaders? Headers { get; }

    /// <summary>
    /// Gets whether the COSE Payload this signature covers is detached (clause 4.5); always <see langword="false"/>
    /// on this result itself — reachable via <see cref="Verified"/>'s wrapped
    /// <see cref="CBAdESVerifiedSignatureFacts.PayloadIsDetached"/> on success, and carrying no meaning on any
    /// failure arm.
    /// </summary>
    public bool PayloadIsDetached { get; }

    /// <summary>
    /// Gets the decoded <c>uHeaders</c> unsigned-header set under the same failure-arm-only availability as
    /// <see cref="Headers"/>; <see langword="null"/> on <see cref="IsValid"/> <see langword="true"/> (reachable
    /// via <see cref="Verified"/> instead), when no <c>uHeaders</c> was present, or on
    /// <see cref="CBAdESMalformedEncodingFailure"/>. Owned by this instance when non-null; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public CBAdESUnsignedHeaders? UnsignedHeaders { get; }

    /// <summary>
    /// Gets the failure detail when <see cref="IsValid"/> is <see langword="false"/>; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public CBAdESValidationFailure? Failure { get; }


    /// <summary>
    /// Mints a successful result, promoting <paramref name="headers"/>/<paramref name="unsignedHeaders"/> into a
    /// <see cref="Verified{CBAdESVerifiedSignatureFacts}"/> minted with <paramref name="provenance"/>. Ownership
    /// of both transfers to the returned instance's <see cref="Verified"/> member — this result's own
    /// <see cref="Headers"/>/<see cref="UnsignedHeaders"/> are <see langword="null"/>. Internal so only
    /// <see cref="CBAdESSignatureValidation"/> can produce one.
    /// </summary>
    /// <param name="headers">The decoded signed-header-set aggregate.</param>
    /// <param name="payloadIsDetached">Whether the COSE Payload this signature covers is detached.</param>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="provenance">The verification provenance the minted <see cref="Verified{T}"/> carries.</param>
    /// <param name="level">The level this result was checked against, or <see langword="null"/> for the B-B-only overloads.</param>
    /// <returns>A valid result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "facts wraps headers/unsignedHeaders by reference (no new disposable resource of its " +
            "own) and is immediately wrapped into the Verified<CBAdESVerifiedSignatureFacts> this factory " +
            "returns inside the resulting CBAdESValidationResult -- ownership transfers to the caller of " +
            "Success, which owns and disposes the returned result (and therefore facts) via CBAdESValidationResult.Dispose.")]
    internal static CBAdESValidationResult Success(
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        CBAdESUnsignedHeaders? unsignedHeaders,
        AssertedProvenance provenance,
        AdESBaselineLevel? level = null)
    {
        var facts = new CBAdESVerifiedSignatureFacts(headers, payloadIsDetached, unsignedHeaders, level);
        var verified = Verified<CBAdESVerifiedSignatureFacts>.CreateAsserted(facts, provenance);

        return new(true, verified, headers: null, payloadIsDetached: false, unsignedHeaders: null, failure: null);
    }


    /// <summary>
    /// Mints a successful, IDENTITY-BOUND result over <paramref name="facts"/> — the certificate-accepting
    /// <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload's own terminal step. Unlike
    /// <see cref="Success"/>, this takes the already-constructed <paramref name="facts"/> rather than building
    /// one, because <paramref name="provenance"/> must have been established (<c>BoundProvenance.TryBindByCertificateDigestAsync</c>)
    /// AGAINST that exact instance before this method is called — <see cref="Verified{T}.TryCreateBound"/>'s own
    /// witness check refuses a provenance minted for a different value. Internal so only
    /// <see cref="CBAdESSignatureValidation"/> can produce one.
    /// </summary>
    /// <param name="facts">The already-constructed facts <paramref name="provenance"/> was established for. Ownership transfers to the returned instance's <see cref="Verified"/> member on success.</param>
    /// <param name="provenance">The already-minted identity binding for <paramref name="facts"/>.</param>
    /// <returns>A valid, bound result, or <see langword="null"/> when <paramref name="provenance"/> does not witness <paramref name="facts"/> (should not occur when the caller passes the exact instance it bound).</returns>
    /// <exception cref="ArgumentNullException"><paramref name="facts"/> or <paramref name="provenance"/> is <see langword="null"/>.</exception>
    internal static CBAdESValidationResult? SuccessBound(CBAdESVerifiedSignatureFacts facts, BoundProvenance provenance)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(provenance);

        Verified<CBAdESVerifiedSignatureFacts>? verified = Verified<CBAdESVerifiedSignatureFacts>.TryCreateBound(facts, provenance);
        if(verified is null)
        {
            return null;
        }

        return new(true, verified, headers: null, payloadIsDetached: false, unsignedHeaders: null, failure: null);
    }


    /// <summary>
    /// Mints a failed result carrying no decoded facts — <see cref="CBAdESMalformedEncodingFailure"/> only,
    /// where nothing decoded before the failure. Internal so only <see cref="CBAdESSignatureValidation"/> can
    /// produce one.
    /// </summary>
    /// <param name="failure">The failure detail.</param>
    /// <returns>An invalid result.</returns>
    internal static CBAdESValidationResult Failed(CBAdESValidationFailure failure) =>
        new(false, null, null, false, null, failure);


    /// <summary>
    /// Mints a failed result that carries the decoded facts known at the point of failure — every failure
    /// arm reached only after the wire bytes parsed successfully.
    /// Ownership of <paramref name="headers"/> and <paramref name="unsignedHeaders"/> (when supplied) transfers
    /// to the returned instance. Internal so only <see cref="CBAdESSignatureValidation"/> can produce one.
    /// </summary>
    /// <param name="failure">The failure detail.</param>
    /// <param name="headers">The decoded signed-header-set aggregate known at the point of failure.</param>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set known at the point of failure, or <see langword="null"/> when absent.</param>
    /// <returns>An invalid result carrying the decoded facts.</returns>
    internal static CBAdESValidationResult Failed(
        CBAdESValidationFailure failure,
        CBAdESProtectedHeaders headers,
        CBAdESUnsignedHeaders? unsignedHeaders) =>
        new(false, null, headers, false, unsignedHeaders, failure);


    /// <summary>
    /// Disposes <see cref="Verified"/>'s wrapped facts, <see cref="Headers"/>, and <see cref="UnsignedHeaders"/>
    /// when present — exactly one of the two sides is ever populated on a given instance (see the type remarks).
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        Verified?.Value.Dispose();
        Headers?.Dispose();
        UnsignedHeaders?.Dispose();
        disposed = true;
    }
}


/// <summary>
/// Why a <see cref="CBAdESValidationResult"/> failed — a DU-ready closed sum: no external type may derive
/// from it.
/// </summary>
public abstract class CBAdESValidationFailure
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected CBAdESValidationFailure()
    {
    }


    /// <summary>Gets a human-readable statement of the failure.</summary>
    public abstract string Message { get; }
}


/// <summary>
/// The wire bytes are not a well-formed CB-AdES <c>COSE_Sign1</c> structure — the parse seam either returned
/// failure or raised one of the fail-closed exception types <see cref="CBAdESSignatureValidation"/> catches
/// (parsing of untrusted bytes never throws out of the validation orchestrator).
/// </summary>
/// <remarks>
/// The case carries no state — being this case is the whole of what it says — so any two instances state the
/// same failure and compare equal. Equality is by value here so that a caller can compare a returned failure
/// against the case it expected without reaching for a type test.
/// </remarks>
public sealed class CBAdESMalformedEncodingFailure: CBAdESValidationFailure, IEquatable<CBAdESMalformedEncodingFailure>
{
    /// <inheritdoc/>
    public override string Message => "The wire bytes do not decode as a well-formed CB-AdES COSE_Sign1 structure.";

    /// <inheritdoc/>
    public bool Equals(CBAdESMalformedEncodingFailure? other)
    {
        return other is not null;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as CBAdESMalformedEncodingFailure);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Message);
    }

    /// <summary>Reports whether two malformed-encoding failures are the same finding (always true for any two instances).</summary>
    public static bool operator ==(CBAdESMalformedEncodingFailure? left, CBAdESMalformedEncodingFailure? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two malformed-encoding failures are different findings (always false for any two instances).</summary>
    public static bool operator !=(CBAdESMalformedEncodingFailure? left, CBAdESMalformedEncodingFailure? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The wire bytes decoded successfully, but at least one B-B conformance rule
/// (<see cref="CBAdESHeaderRules.Check"/>) is violated.
/// </summary>
[DebuggerDisplay("CBAdESRuleViolationsFailure: {Violations.Count} violation(s)")]
public sealed class CBAdESRuleViolationsFailure: CBAdESValidationFailure
{
    /// <summary>Initializes a new <see cref="CBAdESRuleViolationsFailure"/>.</summary>
    /// <param name="violations">Every violation found, in rule-declaration order. Never empty.</param>
    public CBAdESRuleViolationsFailure(IReadOnlyList<CBAdESRuleViolation> violations)
    {
        Violations = violations;
    }

    /// <summary>Every violation found, in rule-declaration order. Never empty.</summary>
    public IReadOnlyList<CBAdESRuleViolation> Violations { get; }

    /// <inheritdoc/>
    public override string Message => $"{Violations.Count} B-B conformance rule violation(s); see {nameof(Violations)}.";
}


/// <summary>
/// Every B-B conformance rule holds and the verification payload resolved successfully, but the COSE signature
/// value does not verify over it (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.4">IETF RFC
/// 9052 §4.4</see>).
/// </summary>
/// <remarks>
/// Nothing distinguishes one occurrence of this case from another — the signature simply did not verify — so
/// instances of it are interchangeable and equality says so rather than reporting the accident of allocation.
/// </remarks>
public sealed class CBAdESSignatureInvalidFailure: CBAdESValidationFailure, IEquatable<CBAdESSignatureInvalidFailure>
{
    /// <inheritdoc/>
    public override string Message => "The COSE signature value does not verify over the resolved payload.";

    /// <inheritdoc/>
    public bool Equals(CBAdESSignatureInvalidFailure? other)
    {
        return other is not null;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as CBAdESSignatureInvalidFailure);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Message);
    }

    /// <summary>Reports whether two signature-invalid failures are the same finding (always true for any two instances).</summary>
    public static bool operator ==(CBAdESSignatureInvalidFailure? left, CBAdESSignatureInvalidFailure? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two signature-invalid failures are different findings (always false for any two instances).</summary>
    public static bool operator !=(CBAdESSignatureInvalidFailure? left, CBAdESSignatureInvalidFailure? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The certificate-accepting <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload could not establish
/// an identity binding for the supplied signing certificate — either the certificate itself is not one this
/// binding can verify under (not an elliptic curve this library resolves, or not well-formed X.509), or the
/// COSE signature value DID verify but the recomputed digest of the certificate it verified under does not
/// match the protected header's own signing-certificate-identification commitment (<c>x5t</c>/first
/// <c>x5ts</c> entry) — the bind-to-X/verify-under-Y hazard — or no such commitment resolves at all. The
/// bare-<see cref="Verifiable.Cryptography.PublicKeyMemory"/> overloads never bind and never report this
/// failure.
/// </summary>
/// <remarks>
/// The case says one thing beyond being itself — why the binding could not be established — so equality is an
/// ordinal comparison of <see cref="Reason"/>. Two failures reporting the same reason are the same finding.
/// </remarks>
[DebuggerDisplay("CBAdESSigningCertificateBindingFailure: {Reason}")]
public sealed class CBAdESSigningCertificateBindingFailure: CBAdESValidationFailure, IEquatable<CBAdESSigningCertificateBindingFailure>
{
    /// <summary>Initializes a new <see cref="CBAdESSigningCertificateBindingFailure"/>.</summary>
    /// <param name="reason">What this binding could state about why the identity binding could not be established.</param>
    public CBAdESSigningCertificateBindingFailure(string reason)
    {
        Reason = reason;
    }

    /// <summary>What this binding could state about why the identity binding could not be established.</summary>
    public string Reason { get; }

    /// <inheritdoc/>
    public override string Message => Reason;

    /// <inheritdoc/>
    public bool Equals(CBAdESSigningCertificateBindingFailure? other)
    {
        return other is not null && string.Equals(Reason, other.Reason, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as CBAdESSigningCertificateBindingFailure);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Reason);
    }

    /// <summary>Reports whether two binding failures state the same reason.</summary>
    public static bool operator ==(CBAdESSigningCertificateBindingFailure? left, CBAdESSigningCertificateBindingFailure? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two binding failures state a different reason.</summary>
    public static bool operator !=(CBAdESSigningCertificateBindingFailure? left, CBAdESSigningCertificateBindingFailure? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The verification payload could not be resolved — the caller supplied no external payload for a detached,
/// unreferenced COSE Payload; a <c>sigD</c> mechanism's dereference delegate reported failure; or <c>sigD</c>
/// named a mechanism this document does not define (CB-5.2.6-07/CB-5.2.8-08) and either no
/// caller-supplied mechanism handler was provided, or the handler reported failure.
/// </summary>
/// <remarks>
/// What the case reports is which reference could not be resolved and why, so equality is those two strings
/// compared ordinally — including the null <see cref="Reference"/> that marks a failure tied to no single
/// reference, which is itself part of what the case states.
/// </remarks>
[DebuggerDisplay("CBAdESDetachedObjectUnresolvableFailure: {Reference}")]
public sealed class CBAdESDetachedObjectUnresolvableFailure: CBAdESValidationFailure, IEquatable<CBAdESDetachedObjectUnresolvableFailure>
{
    /// <summary>Initializes a new <see cref="CBAdESDetachedObjectUnresolvableFailure"/>.</summary>
    /// <param name="reference">
    /// The <c>pars</c> reference whose dereference failed, or <see langword="null"/> when the failure is not tied
    /// to a single reference (an out-of-band detached payload with no caller-supplied bytes; an unknown
    /// mechanism with no handler).
    /// </param>
    /// <param name="reason">A human-readable statement of why the payload could not be resolved.</param>
    public CBAdESDetachedObjectUnresolvableFailure(string? reference, string reason)
    {
        Reference = reference;
        Reason = reason;
    }

    /// <summary>
    /// The <c>pars</c> reference whose dereference failed, or <see langword="null"/> when the failure is not tied
    /// to a single reference (an out-of-band detached payload with no caller-supplied bytes; an unknown
    /// mechanism with no handler).
    /// </summary>
    public string? Reference { get; }

    /// <summary>A human-readable statement of why the payload could not be resolved.</summary>
    public string Reason { get; }

    /// <inheritdoc/>
    public override string Message => Reason;

    /// <inheritdoc/>
    public bool Equals(CBAdESDetachedObjectUnresolvableFailure? other)
    {
        return other is not null
            && string.Equals(Reference, other.Reference, StringComparison.Ordinal)
            && string.Equals(Reason, other.Reason, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as CBAdESDetachedObjectUnresolvableFailure);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Reference, Reason);
    }

    /// <summary>Reports whether two unresolvable-object failures state the same reference and reason.</summary>
    public static bool operator ==(CBAdESDetachedObjectUnresolvableFailure? left, CBAdESDetachedObjectUnresolvableFailure? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two unresolvable-object failures state a different reference or reason.</summary>
    public static bool operator !=(CBAdESDetachedObjectUnresolvableFailure? left, CBAdESDetachedObjectUnresolvableFailure? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// Under the <c>ObjectIdByURIHash</c> mechanism, the dereferenced object's digest (computed via the registered
/// digest delegate over the algorithm identified by <c>hashM</c>) does not match the signed <c>hashV</c> entry
/// at the same position (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.3</see>, CB-5.2.8.2.3-05).
/// </summary>
/// <remarks>
/// The case names one thing — the reference whose digest did not match — so equality is that reference,
/// compared ordinally as the <c>pars</c> entry the wire carries. Two mismatches over the same reference are
/// one finding.
/// </remarks>
[DebuggerDisplay("CBAdESDetachedObjectDigestMismatchFailure: {Reference}")]
public sealed class CBAdESDetachedObjectDigestMismatchFailure: CBAdESValidationFailure, IEquatable<CBAdESDetachedObjectDigestMismatchFailure>
{
    /// <summary>Initializes a new <see cref="CBAdESDetachedObjectDigestMismatchFailure"/>.</summary>
    /// <param name="reference">The <c>pars</c> reference whose digest did not match.</param>
    public CBAdESDetachedObjectDigestMismatchFailure(string reference)
    {
        Reference = reference;
    }

    /// <summary>The <c>pars</c> reference whose digest did not match.</summary>
    public string Reference { get; }

    /// <inheritdoc/>
    public override string Message =>
        $"The digest of the detached object referenced by '{Reference}' does not match its signed hashV " +
        "entry (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.3, CB-5.2.8.2.3-05).";

    /// <inheritdoc/>
    public bool Equals(CBAdESDetachedObjectDigestMismatchFailure? other)
    {
        return other is not null && string.Equals(Reference, other.Reference, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as CBAdESDetachedObjectDigestMismatchFailure);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Reference);
    }

    /// <summary>Reports whether two digest-mismatch failures name the same reference.</summary>
    public static bool operator ==(CBAdESDetachedObjectDigestMismatchFailure? left, CBAdESDetachedObjectDigestMismatchFailure? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two digest-mismatch failures name a different reference.</summary>
    public static bool operator !=(CBAdESDetachedObjectDigestMismatchFailure? left, CBAdESDetachedObjectDigestMismatchFailure? right)
    {
        return !(left == right);
    }
}
