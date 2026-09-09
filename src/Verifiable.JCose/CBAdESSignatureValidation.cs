using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// Resolves the countersigner's public key for verifying one decoded <see cref="CoseCounterSignature"/>
/// element discovered by <see cref="CBAdESSignatureValidation"/> during a level-aware validation pass,
/// or <see langword="null"/> when the caller does not trust or cannot resolve a key for it.
/// </summary>
/// <remarks>
/// Matches this validation orchestrator's certificate-path-neutral scope (see the class remarks: "the caller
/// supplies the verification key by whatever means it trusts"). When <see langword="null"/> is returned, that
/// element's cryptographic verification is SKIPPED, not treated as a violation — CB-6.3-30's own
/// presence-never-a-violation rule extends to "no key available to check it against." Resolving WHICH key to
/// trust (certificate-chain material completeness, CB-5.3.5.1-02's own larger half) is out of this delegate's
/// contract; it only asks the caller for a key once it already has one to try.
/// </remarks>
/// <param name="counterSignature">
/// The decoded countersignature to resolve a key for. BORROWED for the duration of this call only — the
/// caller retains ownership (a <see cref="CoseCounterSignatureParseResult"/> it disposes once every one of
/// its element's own resolver calls has returned, including once per element when the countersignature is
/// a <see cref="CounterSignatureV2Sequence"/>); an implementation must not dispose it or retain a reference
/// past the call returning.
/// </param>
/// <returns>The verification key, or <see langword="null"/> to skip cryptographic verification for this element.</returns>
public delegate PublicKeyMemory? CBAdESResolveCounterSignaturePublicKeyDelegate(CoseCounterSignature counterSignature);


/// <summary>
/// The strict CB-AdES signature validation orchestrator: parses wire bytes, checks every B-B conformance
/// rule, resolves the verification payload per the signature's attachment/mechanism, verifies the COSE
/// signature value over it, and — on the level-aware overloads — additionally checks every
/// B-T/B-LT/B-LTA level-scoped rule and every electronic time-stamp token's message-imprint binding, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope boundary.</strong> This is
/// structural conformance plus cryptographic verification with caller-provided key material. Certificate-path
/// trust and revocation are never resolved, chained, or validated by this class, at any level — it does not
/// even require a signing certificate. <c>kid</c> (clause 5.1.4, CB-5.1.4-04) is a non-authoritative hint and
/// drives no key selection here; the caller supplies the verification key by whatever means it trusts, exactly
/// like <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>
/// does for plain COSE_Sign1.
/// </para>
/// <para>
/// <strong>Level-aware surface.</strong> The four <c>ValidateAsync</c>
/// overloads that take no <see cref="AdESBaselineLevel"/> are the original B-B-only surface, UNCHANGED —
/// they never evaluate a single level-scoped rule (<see cref="CBAdESLevelRules"/>) or open a single time-stamp
/// token, regardless of what <c>uHeaders</c> actually carries. The two overloads that
/// DO take a <see cref="AdESBaselineLevel"/> run the identical B-B structural-plus-cryptographic core first,
/// then additionally: (a) evaluate <see cref="CBAdESLevelRules.Check"/> and
/// <see cref="CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/> — the shared, one-implementation
/// level-rule surface, WIRED here, never re-implemented; (b) open and CMS-verify every <c>sigTst</c>/<c>adoTst</c>/
/// <c>sigRTst</c>/<c>rfsTst</c>/<c>arcTst</c> electronic time-stamp token
/// (<see cref="TimestampTokenInfo.ReadFromTokenAsync"/>) and check that its message imprint binds the data it
/// is claimed to time-stamp (<see cref="TimestampTokenInfo.VerifyMessageImprintAsync"/>) — <c>arcTst</c>'s own
/// message-imprint algorithm (clause 5.3.5.3's 12-step concatenation, validation variant) is built via
/// <see cref="VerifyArchiveTimestampAsync"/>, prefix-bounded to each instance's own position
/// exactly like <c>sigRTst</c>/<c>rfsTst</c>'s own prefix-bounding; (c) fold the OR of every opened token's
/// <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/> into the CB-6.3-26/h validation-data-for-time-stamps
/// service check, AND check each individual token's own signer-certificate coverage
/// (<see cref="CBAdESLevelRules.IsTimestampTokenSignerCertificateResolvedAsync"/>) from the declared level B-LT
/// onward. Certificate-path neutrality is preserved identically at every level: opening a token only
/// checks ITS OWN CMS signature (never a chain to a trust anchor for the Time-Stamping Authority), and
/// <see cref="CBAdESLevelRuleContext.SigningCertificateDigests"/> (CB-A.1.1-02) is derived only
/// from facts the signature's OWN <c>x5t</c>/<c>x5ts</c> headers already assert, never from a resolved or
/// chained certificate. Mapping any of this onto an
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1</see> Indication/SubIndication conclusion remains out of this class's scope — see
/// <see cref="CBAdESValidationResult"/>'s own remarks.
/// </para>
/// <para>
/// <strong>Never throws on malformed or non-conformant input.</strong> Every failure mode this class can
/// reach from untrusted wire bytes — a parse failure, a B-B or level-scoped rule violation, an unresolvable
/// detached object, a digest mismatch, a bad signature, an unopenable or non-binding time-stamp token — is
/// reported as a <see cref="CBAdESValidationResult"/> with <see cref="CBAdESValidationResult.IsValid"/>
/// <see langword="false"/>, never a thrown exception. <see cref="ArgumentNullException"/> for a missing
/// REQUIRED delegate/key/pool parameter is a caller-contract violation, not a conformance judgment, and remains
/// a thrown exception, matching every other seam in this library.
/// <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/>'s own creation-side
/// contract THROWS <see cref="CBAdESDetachedObjectDereferenceException"/> on a routine dereference failure
/// (trusted-caller-input semantics there); this class is the one place that exception crosses back into
/// fail-closed territory, catching it and reporting <see cref="CBAdESDetachedObjectUnresolvableFailure"/> (for
/// the signature-verification payload) or <see cref="CBAdESTimestampTokenBindingViolation"/> (for the
/// <c>adoTst</c> message-imprint input) instead.
/// </para>
/// <para>
/// <strong>Signature verification uses the wire bytes captured at parse.</strong>
/// <see cref="CBAdESSign1ParseResult"/> carries <see cref="CBAdESSign1ParseResult.RawProtectedHeader"/> — the
/// exact, undecoded <c>body_protected</c> byte string
/// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.4">RFC 9052 §4.4</see>) the parse step read off
/// the wire — and this class builds the Sig_structure from those bytes directly, exactly like
/// <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>/
/// <see cref="Verifiable.Cbor.CoseVerification"/> do for plain COSE_Sign1. The identical rationale extends to
/// <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/>: the <c>sigRTst</c>/
/// <c>rfsTst</c> message-imprint builders consume THOSE raw bytes, never a re-encoding of the decoded
/// <see cref="CBAdESUnsignedHeaders"/> model, for the same read/write-asymmetry reason.
/// </para>
/// <para>
/// <strong>One rule implementation.</strong> This class calls <see cref="CBAdESHeaderRules.Check"/> and <see cref="CBAdESLevelRules.Check"/>/
/// <see cref="CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/> — the exact same rule surfaces the
/// creation path's throw postures call — in collect posture. This class never re-implements or duplicates a
/// single one of those rules. Likewise, the <c>ObjectIdByURI</c> reconstruction algorithm (CB-5.2.8.2.2-05) is
/// never duplicated here: it composes <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/>
/// directly (reuse over reinvention) — the same method the CB-5.2.8.2.3-07 full-reconstruction path, the
/// <c>adoTst</c> message-imprint-input resolution, and the <c>arcTst</c> work all share.
/// </para>
/// <para>
/// <strong>Payload resolution (clause 5.2.8).</strong> Exactly one of four cases applies once the B-B rules
/// hold (they jointly guarantee <c>sigD</c> present implies the payload is detached, and <c>sigD</c> absent
/// with an attached payload is the ordinary case — CB-5.2.8-03/04). "Detached" here is
/// <see cref="CBAdESSign1ParseResult.PayloadIsPresent"/> being <see langword="false"/> — the wire <c>nil</c>
/// sentinel (clause 4.5), not merely an empty payload byte string (an attached, zero-length payload is a
/// distinct, legal wire shape <see cref="CBAdESSign1ParseResult"/> itself already disambiguates):
/// </para>
/// <list type="number">
/// <item><description>Attached payload: the wire payload bytes verify the signature directly.</description></item>
/// <item><description>
/// Detached payload, no <c>sigD</c>: the caller's <c>externalDetachedPayload</c> parameter supplies the
/// out-of-band bytes (clause 5.2.6 closing paragraph, clause 5.3.5.3 NOTE 1); <see langword="null"/> there is
/// <see cref="CBAdESDetachedObjectUnresolvableFailure"/>.
/// </description></item>
/// <item><description>
/// <c>sigD</c> present, <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/>: the payload is the
/// order-preserving concatenation of every dereferenced <c>pars</c> entry (CB-5.2.8.2.2-05); a dereference
/// failure is <see cref="CBAdESDetachedObjectUnresolvableFailure"/>.
/// </description></item>
/// <item><description>
/// <c>sigD</c> present, <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/>: the payload contributes as
/// an EMPTY stream to signature verification (CB-5.2.8.2.3-06), and every <c>hashV</c> entry is independently
/// re-verified against the dereferenced object via the registered digest delegate resolved from <c>hashM</c>
/// (hash-via-registered-digest rule) — any mismatch, unresolvable dereference, or unresolvable digest
/// algorithm fails the whole validation, even though the signature-value check itself never sees these bytes.
/// </description></item>
/// </list>
/// <para>
/// An <c>mId</c> naming neither built-in mechanism dispatches to the caller-supplied
/// <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/> (CB-5.2.6-07/CB-5.2.8-08); absent or failing,
/// that is <see cref="CBAdESDetachedObjectUnresolvableFailure"/> too. "Failing" here means exactly what that
/// delegate's own remarks document: a routine retrieval failure signalled by throwing
/// <see cref="CBAdESDetachedObjectDereferenceException"/> — the only exception type this class's own catch
/// around that call narrows to. Anything else the handler raises (cancellation, a programming error, a
/// non-routine implementer-infrastructure fault) is NOT caught here and propagates unmodified out of
/// <c>ValidateAsync</c>, mirroring the creation side's own contract for the identical delegate exactly (see
/// <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/>'s remarks).
/// </para>
/// </remarks>
public static class CBAdESSignatureValidation
{
    /// <summary>
    /// Validates a CB-AdES <c>COSE_Sign1</c> using a registry-resolved verification function. Resolves
    /// <see cref="VerificationDelegate"/> from <paramref name="publicKey"/>'s tag and forwards to the explicit
    /// overload, mirroring <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>'s
    /// own two-tier structure. B-B ONLY — see the type remarks for the level-aware overloads below.
    /// </summary>
    /// <param name="encodedCoseSign1">The candidate CB-AdES wire bytes.</param>
    /// <param name="parse">The fail-closed CBOR parse seam (implemented in <c>Verifiable.Cbor</c>).</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The verifying public key; its tag selects the verification function.</param>
    /// <param name="dereference">
    /// The <c>sigD</c> URI-reference dereference seam, needed only when the signature's <c>sigD</c> selects
    /// <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/> or <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/>;
    /// <see langword="null"/> otherwise.
    /// </param>
    /// <param name="dereferenceContext">
    /// The per-call context <paramref name="dereference"/> and <paramref name="unknownMechanismHandler"/>
    /// receive; required whenever either delegate is supplied.
    /// </param>
    /// <param name="externalDetachedPayload">
    /// The out-of-band detached COSE Payload bytes, needed only when the payload is detached and <c>sigD</c>
    /// is absent (clause 5.2.6 closing paragraph); <see langword="null"/> otherwise.
    /// </param>
    /// <param name="unknownMechanismHandler">
    /// Resolves the COSE Payload for a <c>sigD.mId</c> this document does not define (CB-5.2.6-07/CB-5.2.8-08);
    /// <see langword="null"/> when the caller supports only the two built-in mechanisms.
    /// </param>
    /// <param name="pool">Memory pool for the transient parse and dereference buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result; see the type remarks for the never-throws-on-untrusted-input contract.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="publicKey"/> is <see langword="null"/>.</exception>
    public static ValueTask<CBAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> encodedCoseSign1,
        ParseCBAdESSign1Delegate parse,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return ValidateAsync(
            encodedCoseSign1,
            parse,
            buildSigStructure,
            publicKey,
            verificationDelegate,
            dereference,
            dereferenceContext,
            externalDetachedPayload,
            unknownMechanismHandler,
            pool,
            cancellationToken);
    }


    /// <summary>
    /// Validates a CB-AdES <c>COSE_Sign1</c> using an explicit verification delegate. B-B ONLY —
    /// see the type remarks for the level-aware overloads below and for the full B-B algorithm.
    /// </summary>
    /// <param name="encodedCoseSign1">The candidate CB-AdES wire bytes.</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The verifying public key.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="dereference">
    /// The <c>sigD</c> URI-reference dereference seam, needed only when the signature's <c>sigD</c> selects
    /// <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/> or <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/>;
    /// <see langword="null"/> otherwise.
    /// </param>
    /// <param name="dereferenceContext">
    /// The per-call context <paramref name="dereference"/> and <paramref name="unknownMechanismHandler"/>
    /// receive; required whenever either delegate is supplied.
    /// </param>
    /// <param name="externalDetachedPayload">
    /// The out-of-band detached COSE Payload bytes, needed only when the payload is detached and <c>sigD</c>
    /// is absent; <see langword="null"/> otherwise.
    /// </param>
    /// <param name="unknownMechanismHandler">
    /// Resolves the COSE Payload for a <c>sigD.mId</c> this document does not define; <see langword="null"/>
    /// when the caller supports only the two built-in mechanisms.
    /// </param>
    /// <param name="pool">Memory pool for the transient parse and dereference buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="parse"/>, <paramref name="buildSigStructure"/>, <paramref name="publicKey"/>,
    /// <paramref name="verificationDelegate"/>, or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    public static async ValueTask<CBAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> encodedCoseSign1,
        ParseCBAdESSign1Delegate parse,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        CBAdESCoreVerificationOutcome outcome = await VerifyStructureAndSignatureAsync(
            encodedCoseSign1,
            parse,
            buildSigStructure,
            publicKey,
            verificationDelegate,
            dereference,
            dereferenceContext,
            externalDetachedPayload,
            unknownMechanismHandler,
            pool,
            cancellationToken).ConfigureAwait(false);

        if(!outcome.Succeeded)
        {
            return ToFailedResult(outcome);
        }

        //A B-B-only caller never consumes the level-aware carriers (the raw COSE signature-value bytes, the raw
        //uHeaders bytes, and the raw body-protected-header bytes) VerifyStructureAndSignatureAsync
        //keeps alive for the level pass, so they are disposed immediately here. This fixes a real leak the earlier
        //shape never accounted for: RawUnsignedHeaders postdates that earlier shape, and the
        //original success path here never disposed it (only Signature/RawProtectedHeader were surgically
        //disposed) -- CBAdESSign1ParseResult.Dispose() covers it on every FAILURE path already, but the success
        //path never called that blanket Dispose. The fix has zero effect on the CBAdESValidationResult returned
        //below.
        outcome.SignatureValue!.Dispose();
        outcome.RawUnsignedHeaders?.Dispose();
        outcome.RawProtectedHeader?.Dispose();

        return CBAdESValidationResult.Success(
            outcome.Headers!, outcome.PayloadIsDetached, outcome.UnsignedHeaders,
            AssertedProvenance.OfLabel(outcome.Headers!.KeyId?.ToKeyId().Value));
    }


    /// <summary>
    /// Validates a CB-AdES <c>COSE_Sign1</c> against a supplied signing CERTIFICATE — the DEFAULT,
    /// RECOMMENDED B-B overload: resolves the verification key from <paramref name="signingCertificate"/>
    /// itself (never a caller-supplied raw key — the algorithm is read from the RESOLVED key via the crypto
    /// registry, never the wire <c>alg</c>), verifies the COSE signature value under it, then BINDS by
    /// recomputing the certificate's own digest and comparing it against the protected header's own
    /// signing-certificate-identification commitment (<c>x5t</c>/<c>x5ts</c>). A successful call
    /// therefore mints an IDENTITY-BOUND <see cref="Verified{T}"/>
    /// (<see cref="Verified{T}.IsIdentityBound"/> <see langword="true"/> on
    /// <see cref="CBAdESValidationResult.Verified"/>), unlike the bare-<see cref="PublicKeyMemory"/> overloads
    /// above, which stay the honest bring-your-own-key primitive (never bound, an <see cref="AssertedProvenance"/>
    /// label only).
    /// </summary>
    /// <remarks>
    /// <strong>The forwarder guardrail.</strong> This overload runs the certificate-under-verify and
    /// the digest recompute itself, entirely inside this assembly's own binding boundary
    /// (<see cref="BoundProvenance.TryBindByCertificateDigestAsync"/> is <see langword="internal"/>) — it never
    /// exposes a public entry point that accepts a caller-authored <see cref="SignatureCryptographicVerification"/>
    /// and binds from it, which would let a caller forge a match by authoring both sides of the recompute.
    /// </remarks>
    /// <param name="encodedCoseSign1">See the bare-key overload.</param>
    /// <param name="parse">See the bare-key overload.</param>
    /// <param name="buildSigStructure">See the bare-key overload.</param>
    /// <param name="signingCertificate">The DER-encoded candidate signing certificate.</param>
    /// <param name="dereference">See the bare-key overload.</param>
    /// <param name="dereferenceContext">See the bare-key overload.</param>
    /// <param name="externalDetachedPayload">See the bare-key overload.</param>
    /// <param name="unknownMechanismHandler">See the bare-key overload.</param>
    /// <param name="pool">Memory pool for the transient parse, dereference, and digest-recompute buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result; see the type remarks for the never-throws-on-untrusted-input contract.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="signingCertificate"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<CBAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> encodedCoseSign1,
        ParseCBAdESSign1Delegate parse,
        BuildSigStructureDelegate buildSigStructure,
        PkiCertificateMemory signingCertificate,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(pool);

        if(!EllipticCurveSigningCertificateResolution.TryResolve(signingCertificate, out CryptoAlgorithm algorithm, out ReadOnlyMemory<byte> publicKeyPoint))
        {
            //This binding verifies only elliptic-curve signing certificates (P-256/P-384/P-521/secp256k1) that
            //parse as well-formed X.509 -- nothing could even be attempted, so this is reported through this
            //overload's own binary valid/invalid vocabulary rather than a thrown exception.
            return CBAdESValidationResult.Failed(new CBAdESSigningCertificateBindingFailure(
                "This binding verifies only elliptic-curve signing certificates (P-256/P-384/P-521/secp256k1) that parse as well-formed X.509."));
        }

        using PublicKeyMemory publicKey = CBAdESSignatureFacts.ToPublicKeyMemory(publicKeyPoint, algorithm, pool);
        CryptoAlgorithm verificationAlgorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(verificationAlgorithm, purpose);

        CBAdESCoreVerificationOutcome outcome = await VerifyStructureAndSignatureAsync(
            encodedCoseSign1,
            parse,
            buildSigStructure,
            publicKey,
            verificationDelegate,
            dereference,
            dereferenceContext,
            externalDetachedPayload,
            unknownMechanismHandler,
            pool,
            cancellationToken).ConfigureAwait(false);

        if(!outcome.Succeeded)
        {
            return ToFailedResult(outcome);
        }

        outcome.SignatureValue!.Dispose();
        outcome.RawUnsignedHeaders?.Dispose();
        outcome.RawProtectedHeader?.Dispose();

        return await BindAndMintAsync(
            outcome.Headers!, outcome.PayloadIsDetached, outcome.UnsignedHeaders, signingCertificate, level: null, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The certificate-accepting overload's shared terminal step: builds the signature's own
    /// signing-certificate-identification references (<see cref="CBAdESSignatureFacts.BuildSigningCertificateReferences"/>),
    /// binds by recomputing <paramref name="signingCertificate"/>'s digest against the signer reference among
    /// them (<see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>), and mints a <see cref="Verified{T}"/>
    /// ONLY when the recompute matches — fails closed (<see cref="CBAdESSigningCertificateBindingFailure"/>)
    /// otherwise, never silently downgrading to an <see cref="AssertedProvenance"/> mint.
    /// </summary>
    /// <param name="headers">The already B-B-checked, cryptographically-verified signed-header-set aggregate. Ownership transfers into the returned result either way.</param>
    /// <param name="payloadIsDetached">Whether the COSE Payload this signature covers is detached.</param>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent. Ownership transfers into the returned result either way.</param>
    /// <param name="signingCertificate">The certificate the COSE signature value verified under.</param>
    /// <param name="level">The level this call was checking against, or <see langword="null"/> for the B-B-only overload.</param>
    /// <param name="pool">The memory pool the transient reference/digest buffers are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A valid, identity-bound result, or a <see cref="CBAdESSigningCertificateBindingFailure"/> result carrying <paramref name="headers"/>/<paramref name="unsignedHeaders"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "facts wraps headers/unsignedHeaders by reference (no new disposable resource of its " +
            "own); ownership transfers onward through every explicit return below -- promoted through " +
            "CBAdESValidationResult.SuccessBound's own Verified<CBAdESVerifiedSignatureFacts> on a bound match, " +
            "or carried directly via Failed's headers/unsignedHeaders parameters on a bind-mismatch failure -- " +
            "and the caller of BindAndMintAsync owns and disposes whichever CBAdESValidationResult " +
            "is returned via its own Dispose.")]
    private static async ValueTask<CBAdESValidationResult> BindAndMintAsync(
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        CBAdESUnsignedHeaders? unsignedHeaders,
        PkiCertificateMemory signingCertificate,
        AdESBaselineLevel? level,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        var facts = new CBAdESVerifiedSignatureFacts(headers, payloadIsDetached, unsignedHeaders, level);
        List<SigningCertificateReference> references = CBAdESSignatureFacts.BuildSigningCertificateReferences(headers, pool);
        try
        {
            var cryptographicVerification = new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.Verified,
                SigningCertificate = signingCertificate
            };

            BoundProvenance? provenance = await BoundProvenance.TryBindByCertificateDigestAsync(
                references, cryptographicVerification, facts, pool, cancellationToken).ConfigureAwait(false);

            CBAdESValidationResult? bound = provenance is null ? null : CBAdESValidationResult.SuccessBound(facts, provenance);
            if(bound is not null)
            {
                return bound;
            }

            //The recompute did not match the protected header's own commitment (or, in the should-not-occur
            //case, the witness check itself refused) -- fail closed rather than silently downgrading to
            //Asserted. facts is a bare by-reference wrapper this method never disposed, so headers/
            //unsignedHeaders still need exactly the failure-arm carriage every other post-decode
            //failure in this class already gives them.
            return CBAdESValidationResult.Failed(
                new CBAdESSigningCertificateBindingFailure(
                    "The supplied signing certificate's recomputed digest does not match the protected header's " +
                    "own signing-certificate-identification commitment (x5t/x5ts), or no such commitment resolves."),
                headers, unsignedHeaders);
        }
        finally
        {
            for(int i = 0; i < references.Count; ++i)
            {
                references[i].CertificateDigest?.Dispose();
            }
        }
    }


    /// <summary>
    /// Validates a CB-AdES <c>COSE_Sign1</c> at a specific <see cref="AdESBaselineLevel"/> using a
    /// registry-resolved verification function. Resolves
    /// <see cref="VerificationDelegate"/> from <paramref name="publicKey"/>'s tag and forwards to the explicit
    /// overload. See the type remarks for the full level-aware algorithm and its certificate-path-neutral
    /// scope boundary.
    /// </summary>
    /// <param name="encodedCoseSign1">The candidate CB-AdES wire bytes.</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The verifying public key; its tag selects the verification function.</param>
    /// <param name="dereference">The <c>sigD</c> URI-reference dereference seam; see the B-B-only overload's remarks.</param>
    /// <param name="dereferenceContext">The per-call context for <paramref name="dereference"/> and <paramref name="unknownMechanismHandler"/>.</param>
    /// <param name="externalDetachedPayload">The out-of-band detached COSE Payload bytes; see the B-B-only overload's remarks.</param>
    /// <param name="unknownMechanismHandler">Resolves the COSE Payload for an undefined <c>sigD.mId</c>; see the B-B-only overload's remarks.</param>
    /// <param name="level">The baseline level to check against — the level a validation caller believes the signature claims (see <see cref="CBAdESLevelRules"/>'s own remarks).</param>
    /// <param name="buildPayloadTimestampImprintInput">
    /// Builds the <c>adoTst</c> message-imprint input (clause 5.2.6). REQUIRED — a core seam implementation
    /// (implemented in <c>Verifiable.Cbor</c>), not an optional caller-provided mechanism extension point.
    /// </param>
    /// <param name="buildSignatureAndReferencesTimestampImprintInput">Builds the <c>sigRTst</c> message-imprint input (Annex A.1.2.1.2). REQUIRED.</param>
    /// <param name="buildReferencesOnlyTimestampImprintInput">Builds the <c>rfsTst</c> message-imprint input (Annex A.1.2.2.2). REQUIRED.</param>
    /// <param name="buildArchiveTimestampImprintInput">Builds the <c>arcTst</c> message-imprint input in validation mode (clause 5.3.5.3). REQUIRED.</param>
    /// <param name="pool">Memory pool for the transient parse, dereference, and token-verification buffers.</param>
    /// <param name="archiveTimestampExternallySuppliedData">
    /// The externally supplied application data every <c>arcTst</c> instance's message-imprint input binds
    /// (clause 5.3.5.3 step 5): the SIGNATURE's own externally-supplied data, one value per signature,
    /// constant across every <c>arcTst</c> renewal (this library reads step 5's "at the
    /// time of generating" qualifier as snapshotting <c>uHeaders</c>, not the application data); empty when
    /// the application supplies none.
    /// </param>
    /// <param name="parseCounterSignatureHeaderValue">
    /// Decodes a <c>uHeaders</c> counter-signature element's raw value bytes (label 11/12) into an RFC 9338
    /// version 2 countersignature. OPTIONAL — <see langword="null"/> (the default)
    /// leaves counter-signature elements structurally accepted (CB-6.3-30: presence is never a violation) but
    /// neither decoded nor verified; supplying it opts into fail-closed decode (a malformed element becomes
    /// <see cref="CBAdESCounterSignatureMalformedViolation"/>) and, when <paramref name="buildCountersignStructure"/>
    /// and <paramref name="resolveCounterSignaturePublicKey"/> are also supplied and resolve a key, cryptographic
    /// verification.
    /// </param>
    /// <param name="decodeCounterSignatureProtectedHeader">
    /// Decodes a full (label 11) counter-signature's OWN protected header for the CB-5.2.8-09 check (<c>sigD</c>
    /// shall never appear on a counter signature). OPTIONAL — <see langword="null"/> (the default) skips that
    /// specific check; consulted only when <paramref name="parseCounterSignatureHeaderValue"/> is also supplied,
    /// since the countersignature must decode structurally first.
    /// </param>
    /// <param name="buildCountersignStructure">
    /// Builds the RFC 9338 §3.3 Countersign_structure ToBeSigned bytes for a decoded countersignature's
    /// cryptographic verification. OPTIONAL — required only together with
    /// <paramref name="resolveCounterSignaturePublicKey"/> for verification to be attempted.
    /// </param>
    /// <param name="resolveCounterSignaturePublicKey">
    /// Resolves the countersigner's public key for a decoded countersignature, or <see langword="null"/> to
    /// skip its cryptographic verification; see <see cref="CBAdESResolveCounterSignaturePublicKeyDelegate"/>.
    /// OPTIONAL.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result; see the type remarks for the never-throws-on-untrusted-input contract.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="publicKey"/>, <paramref name="buildPayloadTimestampImprintInput"/>,
    /// <paramref name="buildSignatureAndReferencesTimestampImprintInput"/>,
    /// <paramref name="buildReferencesOnlyTimestampImprintInput"/>, <paramref name="buildArchiveTimestampImprintInput"/>,
    /// or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    public static ValueTask<CBAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> encodedCoseSign1,
        ParseCBAdESSign1Delegate parse,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        AdESBaselineLevel level,
        BuildPayloadTimestampMessageImprintInputDelegate buildPayloadTimestampImprintInput,
        TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate buildSignatureAndReferencesTimestampImprintInput,
        TryBuildReferencesOnlyTimestampMessageImprintInputDelegate buildReferencesOnlyTimestampImprintInput,
        TryBuildArchiveTimestampValidationMessageImprintInputDelegate buildArchiveTimestampImprintInput,
        BaseMemoryPool pool,
        ReadOnlyMemory<byte> archiveTimestampExternallySuppliedData = default,
        ParseCounterSignatureHeaderValueDelegate? parseCounterSignatureHeaderValue = null,
        DecodeCBAdESProtectedHeaderDelegate? decodeCounterSignatureProtectedHeader = null,
        BuildCountersignStructureDelegate? buildCountersignStructure = null,
        CBAdESResolveCounterSignaturePublicKeyDelegate? resolveCounterSignaturePublicKey = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return ValidateAsync(
            encodedCoseSign1,
            parse,
            buildSigStructure,
            publicKey,
            verificationDelegate,
            dereference,
            dereferenceContext,
            externalDetachedPayload,
            unknownMechanismHandler,
            level,
            buildPayloadTimestampImprintInput,
            buildSignatureAndReferencesTimestampImprintInput,
            buildReferencesOnlyTimestampImprintInput,
            buildArchiveTimestampImprintInput,
            pool,
            archiveTimestampExternallySuppliedData,
            parseCounterSignatureHeaderValue,
            decodeCounterSignatureProtectedHeader,
            buildCountersignStructure,
            resolveCounterSignaturePublicKey,
            cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Validates a CB-AdES <c>COSE_Sign1</c> at a specific <see cref="AdESBaselineLevel"/> against a supplied
    /// signing CERTIFICATE — the level-aware counterpart of the B-B-only certificate-accepting overload
    /// above: resolves the verification key from <paramref name="signingCertificate"/> itself, runs the
    /// identical B-B structural-plus-cryptographic-plus-level pass, then BINDS by recomputing the certificate's
    /// own digest against the protected header's own signing-certificate-identification commitment
    /// (<c>x5t</c>/<c>x5ts</c>) — the same bind-to-X/verify-under-Y guardrail the B-B-only cert overload
    /// enforces applies here too. A successful call mints an IDENTITY-BOUND <see cref="Verified{T}"/>
    /// (<see cref="Verified{T}.IsIdentityBound"/> <see langword="true"/>) carrying the checked
    /// <paramref name="level"/>; a digest mismatch fails closed with a
    /// <see cref="CBAdESSigningCertificateBindingFailure"/> rather than downgrading to an
    /// <see cref="AssertedProvenance"/> mint. The bare-<see cref="PublicKeyMemory"/> level-aware overloads above
    /// stay the honest bring-your-own-key primitive (never bound, an asserted label only).
    /// </summary>
    /// <remarks>
    /// <strong>The forwarder guardrail.</strong> This overload runs the certificate-under-verify and
    /// the digest recompute itself, entirely inside this assembly's own binding boundary — it never exposes a
    /// public entry point that accepts a caller-authored <see cref="SignatureCryptographicVerification"/> and
    /// binds from it, which would let a caller forge a match by authoring both sides of the recompute.
    /// </remarks>
    /// <param name="encodedCoseSign1">The candidate CB-AdES wire bytes.</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="signingCertificate">The DER-encoded candidate signing certificate.</param>
    /// <param name="dereference">The <c>sigD</c> URI-reference dereference seam; see the B-B-only overload's remarks.</param>
    /// <param name="dereferenceContext">The per-call context for <paramref name="dereference"/> and <paramref name="unknownMechanismHandler"/>.</param>
    /// <param name="externalDetachedPayload">The out-of-band detached COSE Payload bytes; see the B-B-only overload's remarks.</param>
    /// <param name="unknownMechanismHandler">Resolves the COSE Payload for an undefined <c>sigD.mId</c>; see the B-B-only overload's remarks.</param>
    /// <param name="level">The baseline level to check against.</param>
    /// <param name="buildPayloadTimestampImprintInput">Builds the <c>adoTst</c> message-imprint input (clause 5.2.6). REQUIRED.</param>
    /// <param name="buildSignatureAndReferencesTimestampImprintInput">Builds the <c>sigRTst</c> message-imprint input (Annex A.1.2.1.2). REQUIRED.</param>
    /// <param name="buildReferencesOnlyTimestampImprintInput">Builds the <c>rfsTst</c> message-imprint input (Annex A.1.2.2.2). REQUIRED.</param>
    /// <param name="buildArchiveTimestampImprintInput">Builds the <c>arcTst</c> message-imprint input in validation mode (clause 5.3.5.3). REQUIRED.</param>
    /// <param name="pool">Memory pool for the transient parse, dereference, digest-recompute, and token-verification buffers.</param>
    /// <param name="archiveTimestampExternallySuppliedData">See the bare-key level-aware overload.</param>
    /// <param name="parseCounterSignatureHeaderValue">See the bare-key level-aware overload.</param>
    /// <param name="decodeCounterSignatureProtectedHeader">See the bare-key level-aware overload.</param>
    /// <param name="buildCountersignStructure">See the bare-key level-aware overload.</param>
    /// <param name="resolveCounterSignaturePublicKey">See the bare-key level-aware overload.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result; see the type remarks for the never-throws-on-untrusted-input contract.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="signingCertificate"/>, <paramref name="buildPayloadTimestampImprintInput"/>,
    /// <paramref name="buildSignatureAndReferencesTimestampImprintInput"/>,
    /// <paramref name="buildReferencesOnlyTimestampImprintInput"/>, <paramref name="buildArchiveTimestampImprintInput"/>,
    /// or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    public static async ValueTask<CBAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> encodedCoseSign1,
        ParseCBAdESSign1Delegate parse,
        BuildSigStructureDelegate buildSigStructure,
        PkiCertificateMemory signingCertificate,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        AdESBaselineLevel level,
        BuildPayloadTimestampMessageImprintInputDelegate buildPayloadTimestampImprintInput,
        TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate buildSignatureAndReferencesTimestampImprintInput,
        TryBuildReferencesOnlyTimestampMessageImprintInputDelegate buildReferencesOnlyTimestampImprintInput,
        TryBuildArchiveTimestampValidationMessageImprintInputDelegate buildArchiveTimestampImprintInput,
        BaseMemoryPool pool,
        ReadOnlyMemory<byte> archiveTimestampExternallySuppliedData = default,
        ParseCounterSignatureHeaderValueDelegate? parseCounterSignatureHeaderValue = null,
        DecodeCBAdESProtectedHeaderDelegate? decodeCounterSignatureProtectedHeader = null,
        BuildCountersignStructureDelegate? buildCountersignStructure = null,
        CBAdESResolveCounterSignaturePublicKeyDelegate? resolveCounterSignaturePublicKey = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(buildPayloadTimestampImprintInput);
        ArgumentNullException.ThrowIfNull(buildSignatureAndReferencesTimestampImprintInput);
        ArgumentNullException.ThrowIfNull(buildReferencesOnlyTimestampImprintInput);
        ArgumentNullException.ThrowIfNull(buildArchiveTimestampImprintInput);
        ArgumentNullException.ThrowIfNull(pool);

        if(!EllipticCurveSigningCertificateResolution.TryResolve(signingCertificate, out CryptoAlgorithm algorithm, out ReadOnlyMemory<byte> publicKeyPoint))
        {
            //This binding verifies only elliptic-curve signing certificates (P-256/P-384/P-521/secp256k1) that
            //parse as well-formed X.509 -- nothing could even be attempted, so this is reported through this
            //overload's own binary valid/invalid vocabulary rather than a thrown exception.
            return CBAdESValidationResult.Failed(new CBAdESSigningCertificateBindingFailure(
                "This binding verifies only elliptic-curve signing certificates (P-256/P-384/P-521/secp256k1) that parse as well-formed X.509."));
        }

        using PublicKeyMemory publicKey = CBAdESSignatureFacts.ToPublicKeyMemory(publicKeyPoint, algorithm, pool);
        CryptoAlgorithm verificationAlgorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(verificationAlgorithm, purpose);

        return await ValidateAsync(
            encodedCoseSign1,
            parse,
            buildSigStructure,
            publicKey,
            verificationDelegate,
            dereference,
            dereferenceContext,
            externalDetachedPayload,
            unknownMechanismHandler,
            level,
            buildPayloadTimestampImprintInput,
            buildSignatureAndReferencesTimestampImprintInput,
            buildReferencesOnlyTimestampImprintInput,
            buildArchiveTimestampImprintInput,
            pool,
            archiveTimestampExternallySuppliedData,
            parseCounterSignatureHeaderValue,
            decodeCounterSignatureProtectedHeader,
            buildCountersignStructure,
            resolveCounterSignaturePublicKey,
            signingCertificate: signingCertificate,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Validates a CB-AdES <c>COSE_Sign1</c> at a specific <see cref="AdESBaselineLevel"/> using an explicit
    /// verification delegate — the level-aware core implementation. See the
    /// type remarks for the full algorithm and its certificate-path-neutral scope boundary.
    /// </summary>
    /// <param name="encodedCoseSign1">The candidate CB-AdES wire bytes.</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The verifying public key.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="dereference">The <c>sigD</c> URI-reference dereference seam; see the B-B-only overload's remarks.</param>
    /// <param name="dereferenceContext">The per-call context for <paramref name="dereference"/> and <paramref name="unknownMechanismHandler"/>.</param>
    /// <param name="externalDetachedPayload">The out-of-band detached COSE Payload bytes; see the B-B-only overload's remarks.</param>
    /// <param name="unknownMechanismHandler">Resolves the COSE Payload for an undefined <c>sigD.mId</c>; see the B-B-only overload's remarks.</param>
    /// <param name="level">The baseline level to check against.</param>
    /// <param name="buildPayloadTimestampImprintInput">Builds the <c>adoTst</c> message-imprint input (clause 5.2.6). REQUIRED.</param>
    /// <param name="buildSignatureAndReferencesTimestampImprintInput">Builds the <c>sigRTst</c> message-imprint input (Annex A.1.2.1.2). REQUIRED.</param>
    /// <param name="buildReferencesOnlyTimestampImprintInput">Builds the <c>rfsTst</c> message-imprint input (Annex A.1.2.2.2). REQUIRED.</param>
    /// <param name="buildArchiveTimestampImprintInput">Builds the <c>arcTst</c> message-imprint input in validation mode (clause 5.3.5.3). REQUIRED.</param>
    /// <param name="pool">Memory pool for the transient parse, dereference, and token-verification buffers.</param>
    /// <param name="archiveTimestampExternallySuppliedData">
    /// The externally supplied application data every <c>arcTst</c> instance's message-imprint input binds
    /// (clause 5.3.5.3 step 5): the SIGNATURE's own externally-supplied data, one value per signature,
    /// constant across every <c>arcTst</c> renewal (this library reads step 5's "at the
    /// time of generating" qualifier as snapshotting <c>uHeaders</c>, not the application data); empty when
    /// the application supplies none.
    /// </param>
    /// <param name="parseCounterSignatureHeaderValue">
    /// Decodes a <c>uHeaders</c> counter-signature element's raw value bytes (label 11/12) into an RFC 9338
    /// version 2 countersignature. OPTIONAL — see the B-B-only... (registry-resolved)
    /// overload's remarks for the full opt-in contract.
    /// </param>
    /// <param name="buildCountersignStructure">
    /// Builds the RFC 9338 §3.3 Countersign_structure ToBeSigned bytes for cryptographic verification.
    /// OPTIONAL.
    /// </param>
    /// <param name="resolveCounterSignaturePublicKey">
    /// Resolves the countersigner's public key for a decoded countersignature; see
    /// <see cref="CBAdESResolveCounterSignaturePublicKeyDelegate"/>. OPTIONAL.
    /// </param>
    /// <param name="signingCertificate">
    /// The signing certificate to identity-bind against when the caller reached this core through the
    /// certificate-accepting overload; <see langword="null"/> for the bring-your-own-key path, which mints an
    /// asserted label only.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="parse"/>, <paramref name="buildSigStructure"/>, <paramref name="publicKey"/>,
    /// <paramref name="verificationDelegate"/>, <paramref name="buildPayloadTimestampImprintInput"/>,
    /// <paramref name="buildSignatureAndReferencesTimestampImprintInput"/>,
    /// <paramref name="buildReferencesOnlyTimestampImprintInput"/>, <paramref name="buildArchiveTimestampImprintInput"/>,
    /// or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    public static async ValueTask<CBAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> encodedCoseSign1,
        ParseCBAdESSign1Delegate parse,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        AdESBaselineLevel level,
        BuildPayloadTimestampMessageImprintInputDelegate buildPayloadTimestampImprintInput,
        TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate buildSignatureAndReferencesTimestampImprintInput,
        TryBuildReferencesOnlyTimestampMessageImprintInputDelegate buildReferencesOnlyTimestampImprintInput,
        TryBuildArchiveTimestampValidationMessageImprintInputDelegate buildArchiveTimestampImprintInput,
        BaseMemoryPool pool,
        ReadOnlyMemory<byte> archiveTimestampExternallySuppliedData = default,
        ParseCounterSignatureHeaderValueDelegate? parseCounterSignatureHeaderValue = null,
        DecodeCBAdESProtectedHeaderDelegate? decodeCounterSignatureProtectedHeader = null,
        BuildCountersignStructureDelegate? buildCountersignStructure = null,
        CBAdESResolveCounterSignaturePublicKeyDelegate? resolveCounterSignaturePublicKey = null,
        PkiCertificateMemory? signingCertificate = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(buildPayloadTimestampImprintInput);
        ArgumentNullException.ThrowIfNull(buildSignatureAndReferencesTimestampImprintInput);
        ArgumentNullException.ThrowIfNull(buildReferencesOnlyTimestampImprintInput);
        ArgumentNullException.ThrowIfNull(buildArchiveTimestampImprintInput);
        ArgumentNullException.ThrowIfNull(pool);

        CBAdESCoreVerificationOutcome outcome = await VerifyStructureAndSignatureAsync(
            encodedCoseSign1,
            parse,
            buildSigStructure,
            publicKey,
            verificationDelegate,
            dereference,
            dereferenceContext,
            externalDetachedPayload,
            unknownMechanismHandler,
            pool,
            cancellationToken).ConfigureAwait(false);

        if(!outcome.Succeeded)
        {
            return ToFailedResult(outcome);
        }

        CBAdESProtectedHeaders headers = outcome.Headers!;
        CBAdESUnsignedHeaders? unsignedHeaders = outcome.UnsignedHeaders;
        using Signature signatureValue = outcome.SignatureValue!;
        using EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders = outcome.RawUnsignedHeaders;
        using EncodedCoseProtectedHeader? rawProtectedHeader = outcome.RawProtectedHeader;

        //The valData certificate candidates every arcTst instance's per-token coverage check (CB-6.3-h)
        //identity-matches against -- collected once, since it is the SAME
        //candidate set regardless of which/how many arcTst instances the loop below visits.
        IReadOnlyList<AdESPkiObject> validationDataCertificates = CBAdESLevelRules.CollectValidationDataCertificateCandidates(unsignedHeaders);

        //arcTst's payload contribution (clause 5.3.5.3 steps 6/7) is resolved AT MOST ONCE, lazily, the first
        //time the loop below encounters an arcTst element -- it is the same resolution adoTst's own payload
        //timestamp uses (ResolvePayloadTimestampImprintSourceAsync), and every arcTst instance in one signature
        //shares the identical body-layer payload, so re-resolving per instance would be redundant work (and,
        //for a sigD-dereferencing caller, a redundant external call).
        bool archiveTimestampPayloadResolutionAttempted = false;
        PooledMemory? archiveTimestampPayloadRented = null;
        CBAdESPayloadTimestampImprintSource? archiveTimestampPayloadSource = null;
        string? archiveTimestampPayloadFailureReason = null;

        try
        {
            try
            {
                var violations = new List<CBAdESRuleViolation>();
                bool anyEmbeddedValidationMaterial = false;

                if(unsignedHeaders is not null)
                {
                    ReadOnlyMemory<byte> signatureValueBytes = signatureValue.AsReadOnlyMemory();

                    for(int i = 0; i < unsignedHeaders.Count; ++i)
                    {
                        switch(unsignedHeaders[i])
                        {
                            case CBAdESUnsignedHeaderElementSignatureTimestamp sigTst:
                                anyEmbeddedValidationMaterial |= await VerifyTimestampContainerAsync(
                                    sigTst.SignatureTimestamp.TimestampContainer,
                                    CBAdESTimestampTokenBindingKind.SignatureTimestamp,
                                    signatureValueBytes,
                                    i,
                                    level,
                                    validationDataCertificates,
                                    violations,
                                    pool,
                                    cancellationToken).ConfigureAwait(false);
                                break;

                            case CBAdESUnsignedHeaderElementArchiveTimestamp arcTst when level == AdESBaselineLevel.BLTA:
                                if(!archiveTimestampPayloadResolutionAttempted)
                                {
                                    archiveTimestampPayloadResolutionAttempted = true;

                                    (bool payloadResolved, archiveTimestampPayloadRented, archiveTimestampPayloadSource, archiveTimestampPayloadFailureReason) =
                                        await ResolvePayloadTimestampImprintSourceAsync(
                                            headers,
                                            outcome.PayloadIsDetached,
                                            outcome.Payload,
                                            dereference,
                                            dereferenceContext,
                                            externalDetachedPayload,
                                            unknownMechanismHandler,
                                            CBAdESTimestampTokenBindingKind.ArchiveTimestamp,
                                            pool,
                                            cancellationToken).ConfigureAwait(false);

                                    if(!payloadResolved)
                                    {
                                        archiveTimestampPayloadSource = null;
                                    }
                                }

                                //This specific arcTst instance's own array position
                                //(i) is the exclusive validation-time prefix bound -- only the uHeaders elements
                                //that precede IT contribute, never a later arcTst instance appended after it
                                //(the repeated-arcTst regression these tests cover).
                                anyEmbeddedValidationMaterial |= await VerifyArchiveTimestampAsync(
                                    arcTst.ArchiveTimestamp.TimestampContainer,
                                    rawProtectedHeader!.AsReadOnlyMemory(),
                                    archiveTimestampExternallySuppliedData,
                                    archiveTimestampPayloadSource,
                                    archiveTimestampPayloadFailureReason,
                                    signatureValueBytes,
                                    rawUnsignedHeaders,
                                    i,
                                    buildArchiveTimestampImprintInput,
                                    level,
                                    validationDataCertificates,
                                    violations,
                                    pool,
                                    cancellationToken).ConfigureAwait(false);
                                break;

                            case CBAdESUnsignedHeaderElementArchiveTimestamp arcTstBelowBlta:
                                //Below the declared B-LTA, arcTst's IMPRINT is not
                                //load-bearing (read-tolerance) -- only token-SHAPE checks run (open +
                                //CMS-verify every token, no expected imprint), restoring c72ebbb1 behavior for
                                //e.g. a detached-payload signature carrying arcTst validated at declared B-B
                                //with no payload context supplied.
                                anyEmbeddedValidationMaterial |= await VerifyTimestampContainerAsync(
                                    arcTstBelowBlta.ArchiveTimestamp.TimestampContainer,
                                    CBAdESTimestampTokenBindingKind.ArchiveTimestamp,
                                    expectedImprintInput: null,
                                    i,
                                    level,
                                    validationDataCertificates,
                                    violations,
                                    pool,
                                    cancellationToken).ConfigureAwait(false);
                                break;

                            case CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp sigRTst:
                                //This specific sigRTst instance's own array
                                //position (i) is the exclusive validation-time prefix bound -- only the uHeaders
                                //elements that precede IT contribute, never a later sigTst instance appended
                                //after it (Table 14 note 7's repeated-sigTst case).
                                anyEmbeddedValidationMaterial |= await VerifySignatureAndReferencesTimestampAsync(
                                    sigRTst.SignatureAndReferencesTimestamp.TimestampContainer,
                                    signatureValueBytes,
                                    rawUnsignedHeaders,
                                    i,
                                    buildSignatureAndReferencesTimestampImprintInput,
                                    level,
                                    validationDataCertificates,
                                    violations,
                                    pool,
                                    cancellationToken).ConfigureAwait(false);
                                break;

                            case CBAdESUnsignedHeaderElementReferencesTimestamp rfsTst:
                                //Same validation-time prefix-bound reading as sigRTst above, over this
                                //specific rfsTst instance's own array position.
                                anyEmbeddedValidationMaterial |= await VerifyReferencesTimestampAsync(
                                    rfsTst.ReferencesTimestamp.TimestampContainer,
                                    rawUnsignedHeaders,
                                    i,
                                    buildReferencesOnlyTimestampImprintInput,
                                    level,
                                    validationDataCertificates,
                                    violations,
                                    pool,
                                    cancellationToken).ConfigureAwait(false);
                                break;

                            case CBAdESUnsignedHeaderElementFullCounterSignature or CBAdESUnsignedHeaderElementAbbreviatedCounterSignature:
                                //CB-6.3-30: presence is NEVER a violation at any level --
                                //this arm decodes and, when the caller opted in, cryptographically verifies the
                                //element's CONTENT, collecting a violation only for malformed content or a
                                //failing signature, never for the element merely existing.
                                await VerifyCounterSignatureAsync(
                                    unsignedHeaders[i],
                                    i,
                                    rawProtectedHeader!.AsReadOnlyMemory(),
                                    outcome.Payload,
                                    signatureValueBytes,
                                    parseCounterSignatureHeaderValue,
                                    decodeCounterSignatureProtectedHeader,
                                    buildCountersignStructure,
                                    resolveCounterSignaturePublicKey,
                                    violations,
                                    pool,
                                    cancellationToken).ConfigureAwait(false);
                                break;
                        }
                    }
                }

                if(headers.PayloadTimestamps is not null)
                {
                    anyEmbeddedValidationMaterial |= await VerifyPayloadTimestampAsync(
                        headers,
                        outcome.PayloadIsDetached,
                        outcome.Payload,
                        dereference,
                        dereferenceContext,
                        externalDetachedPayload,
                        unknownMechanismHandler,
                        buildPayloadTimestampImprintInput,
                        level,
                        validationDataCertificates,
                        violations,
                        pool,
                        cancellationToken).ConfigureAwait(false);
                }

                var levelContext = new CBAdESLevelRuleContext
                {
                    Level = level,
                    UnsignedHeaders = unsignedHeaders,
                    SigningCertificateDigests = CollectSigningCertificateDigests(headers),
                    AnyTimestampTokenCarriesEmbeddedValidationMaterial = anyEmbeddedValidationMaterial,
                    PayloadTimestamps = headers.PayloadTimestamps
                };

                IReadOnlyList<CBAdESRuleViolation> structuralLevelViolations = CBAdESLevelRules.Check(levelContext);
                for(int i = 0; i < structuralLevelViolations.Count; ++i)
                {
                    violations.Add(structuralLevelViolations[i]);
                }

                IReadOnlyList<CBAdESRuleViolation> crossConsistencyViolations = await CBAdESLevelRules
                    .CheckReferencesResolveToValidationDataAsync(unsignedHeaders, pool, cancellationToken)
                    .ConfigureAwait(false);
                for(int i = 0; i < crossConsistencyViolations.Count; ++i)
                {
                    violations.Add(crossConsistencyViolations[i]);
                }

                if(violations.Count > 0)
                {
                    //headers/unsignedHeaders transfer into the
                    //failed result instead of being disposed here -- ownership exactly once, no double-dispose
                    //against CBAdESValidationResult.Dispose()'s own unconditional Headers?.Dispose()/
                    //UnsignedHeaders?.Dispose().
                    return CBAdESValidationResult.Failed(new CBAdESRuleViolationsFailure(violations), headers, unsignedHeaders);
                }

                if(signingCertificate is not null)
                {
                    return await BindAndMintAsync(
                        headers, outcome.PayloadIsDetached, unsignedHeaders, signingCertificate, level, pool, cancellationToken).ConfigureAwait(false);
                }

                return CBAdESValidationResult.Success(
                    headers, outcome.PayloadIsDetached, unsignedHeaders,
                    AssertedProvenance.OfLabel(headers.KeyId?.ToKeyId().Value), level);
            }
            catch
            {
                headers.Dispose();
                unsignedHeaders?.Dispose();
                throw;
            }
        }
        finally
        {
            //archiveTimestampPayloadRented is bound by a tuple deconstruction from
            //ResolvePayloadTimestampImprintSourceAsync inside the loop above (a using declaration accepts only
            //a single simple declaration, never a deconstruction target) and only on the lazy first arcTst
            //visit, so it is disposed manually here rather than at its own declaration point.
            archiveTimestampPayloadRented?.Dispose();
        }
    }


    /// <summary>
    /// Shapes a failed <see cref="CBAdESCoreVerificationOutcome"/> into a <see cref="CBAdESValidationResult"/>
    /// threading <see cref="CBAdESCoreVerificationOutcome.Headers"/>/
    /// <see cref="CBAdESCoreVerificationOutcome.UnsignedHeaders"/> onward when the core decoded them before
    /// failing, rather than discarding them — the shared shaping both <c>ValidateAsync</c> overload pairs (B-B-only
    /// and level-aware) use for the core's own failure arm.
    /// </summary>
    /// <param name="outcome">The failed core outcome. <see cref="CBAdESCoreVerificationOutcome.Succeeded"/> must be <see langword="false"/>.</param>
    /// <returns>The shaped, invalid result.</returns>
    private static CBAdESValidationResult ToFailedResult(CBAdESCoreVerificationOutcome outcome) =>
        outcome.Headers is not null
            ? CBAdESValidationResult.Failed(outcome.Failure!, outcome.Headers, outcome.UnsignedHeaders)
            : CBAdESValidationResult.Failed(outcome.Failure!);


    /// <summary>
    /// The shared structural-plus-cryptographic B-B core, extracted so both the B-B-only
    /// overloads and the level-aware overloads run the IDENTICAL parse/rule/payload-resolution/signature-
    /// verification pipeline (the original B-B behavior preserved EXACTLY) — a level-aware
    /// caller then continues past <see cref="CBAdESCoreVerificationOutcome.Succeeded"/> into the level pass;
    /// a B-B-only caller stops there.
    /// </summary>
    /// <param name="encodedCoseSign1">The candidate CB-AdES wire bytes.</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The verifying public key.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="dereference">The <c>sigD</c> URI-reference dereference seam; see the B-B-only overload's remarks.</param>
    /// <param name="dereferenceContext">The per-call context for <paramref name="dereference"/> and <paramref name="unknownMechanismHandler"/>.</param>
    /// <param name="externalDetachedPayload">The out-of-band detached COSE Payload bytes; see the B-B-only overload's remarks.</param>
    /// <param name="unknownMechanismHandler">Resolves the COSE Payload for an undefined <c>sigD.mId</c>; see the B-B-only overload's remarks.</param>
    /// <param name="pool">Memory pool for the transient parse and dereference buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The core outcome; see <see cref="CBAdESCoreVerificationOutcome"/>.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="parse"/>, <paramref name="buildSigStructure"/>, <paramref name="publicKey"/>,
    /// <paramref name="verificationDelegate"/>, or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "verificationMessage (below) shares parseResult's own RawProtectedHeader/Signature " +
            "carriers verbatim -- the wire body_protected bytes captured at parse -- rather " +
            "than allocating new disposables of its own; both RawProtectedHeader's and Signature's ownership " +
            "transfer onward through the returned CBAdESCoreVerificationOutcome on success (disposed by the " +
            "catch below on any exception instead), whose own caller (either ValidateAsync overload " +
            "pair, above) disposes them explicitly. Roslyn tracks the locally-constructed CoseSign1Message " +
            "itself, not the fact that its constituent IDisposable members are owned and disposed one level up.")]
    private static async ValueTask<CBAdESCoreVerificationOutcome> VerifyStructureAndSignatureAsync(
        ReadOnlyMemory<byte> encodedCoseSign1,
        ParseCBAdESSign1Delegate parse,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        //Step a: parse via the seam; a parse failure (a thrown fail-closed exception, mirroring the
        //Verifiable.Cbor.CoseVerification exemplar, or an unsuccessful CBAdESSign1ParseResult) yields
        //MalformedEncoding.
        CBAdESSign1ParseResult parseResult;
        try
        {
            parseResult = parse(encodedCoseSign1, pool);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            return CBAdESCoreVerificationOutcome.Failed(new CBAdESMalformedEncodingFailure());
        }

        if(!parseResult.IsSuccess || parseResult.ProtectedHeaders is null || parseResult.Signature is null)
        {
            parseResult.Dispose();
            return CBAdESCoreVerificationOutcome.Failed(new CBAdESMalformedEncodingFailure());
        }

        CBAdESProtectedHeaders headers = parseResult.ProtectedHeaders;
        CBAdESUnsignedHeaders? unsignedHeaders = parseResult.UnsignedHeaders;
        bool payloadIsDetached = !parseResult.PayloadIsPresent;

        //Step b: the shared B-B rule surface, collect posture — a single call,
        //never re-implemented here, and never re-checking the unprotected-map single-member rule the parse
        //seam already fail-closed on.
        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESHeaderRules.Check(headers, payloadIsDetached, unsignedHeaders);
        if(violations.Count > 0)
        {
            //headers/unsignedHeaders already decoded successfully --
            //only the OTHER carriers this method never hands onward are released here; headers/unsignedHeaders
            //transfer into the failed outcome instead of being discarded (see the Failed(...) overload below).
            DisposeUnclaimedParseCarriers(parseResult);
            return CBAdESCoreVerificationOutcome.Failed(new CBAdESRuleViolationsFailure(violations), headers, unsignedHeaders);
        }

        //Steps c-e are wrapped in a try/catch: every explicit return below already disposes
        //parseResult on its own way out, but an exception surfacing from either await (a pre-canceled
        //cancellationToken observed inside ResolveVerificationPayloadAsync/Cose.VerifyAsync, or a non-conformant
        //dereference/unknown-mechanism-handler implementation raising something other than the routine failure
        //this method's own catches already convert) would otherwise skip every one of those explicit disposals
        //and leak parseResult's owned carriers. Dispose is idempotent, so the catch below never double-disposes
        //a carrier an explicit return already disposed -- it only fires on a path that never reached a return.
        try
        {
            //Step c: resolve the verification payload per attachment/mechanism.
            (bool resolved, PooledMemory? rentedPayload, ReadOnlyMemory<byte> resolvedPayload, CBAdESValidationFailure? resolutionFailure) =
                await ResolveVerificationPayloadAsync(
                    parseResult.Payload,
                    headers,
                    payloadIsDetached,
                    dereference,
                    dereferenceContext,
                    externalDetachedPayload,
                    unknownMechanismHandler,
                    pool,
                    cancellationToken).ConfigureAwait(false);

            using(rentedPayload)
            {
                if(!resolved)
                {
                    //See the header-rule-violation arm above -- the
                    //same decoded-facts-survive-the-failure treatment.
                    DisposeUnclaimedParseCarriers(parseResult);
                    return CBAdESCoreVerificationOutcome.Failed(resolutionFailure!, headers, unsignedHeaders);
                }

                //Step d: Cose.VerifyAsync over the resolved payload. verificationMessage shares parseResult's OWN
                //RawProtectedHeader/Signature carriers — the wire body_protected bytes captured verbatim at parse
                //never a re-encoding of headers — and neither is disposed by this "using" block;
                //parseResult itself remains the sole owner until the outcome is known below.
                var verificationMessage = new CoseSign1Message(parseResult.RawProtectedHeader!, null, resolvedPayload, parseResult.Signature);

                bool isValid = await Cose.VerifyAsync(
                    verificationMessage,
                    buildSigStructure,
                    publicKey,
                    verificationDelegate,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                if(!isValid)
                {
                    //See the header-rule-violation arm above -- the
                    //same decoded-facts-survive-the-failure treatment.
                    DisposeUnclaimedParseCarriers(parseResult);
                    return CBAdESCoreVerificationOutcome.Failed(new CBAdESSignatureInvalidFailure(), headers, unsignedHeaders);
                }

                //Step e: success — ownership of headers/unsignedHeaders/Signature/RawUnsignedHeaders/
                //RawProtectedHeader all transfers to the outcome; a B-B-only caller disposes RawProtectedHeader
                //immediately (it has no use for it), a level-aware caller keeps it alive through the arcTst
                //message-imprint pass (clause 5.3.5.3 step 3) and disposes it once that pass ends.
                return CBAdESCoreVerificationOutcome.Success(
                    headers,
                    payloadIsDetached,
                    parseResult.Payload,
                    unsignedHeaders,
                    parseResult.Signature,
                    parseResult.RawUnsignedHeaders,
                    parseResult.RawProtectedHeader);
            }
        }
        catch
        {
            parseResult.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Disposes every carrier of <paramref name="parseResult"/> EXCEPT <see cref="CBAdESSign1ParseResult.ProtectedHeaders"/>
    /// and <see cref="CBAdESSign1ParseResult.UnsignedHeaders"/> — used
    /// on a failure arm reached only after the wire bytes parsed successfully, where those two decoded facts
    /// transfer onward into the caller's <see cref="CBAdESCoreVerificationOutcome.Failed(CBAdESValidationFailure, CBAdESProtectedHeaders, CBAdESUnsignedHeaders?)"/>
    /// call instead of being discarded here. <see cref="CBAdESSign1ParseResult.Dispose"/> is never called on
    /// <paramref name="parseResult"/> once this runs: that would dispose <c>ProtectedHeaders</c>/<c>UnsignedHeaders</c>
    /// a second time, breaking custody-exactly-once for the carriers this method deliberately keeps alive.
    /// </summary>
    /// <param name="parseResult">The parse result whose non-facts carriers are released.</param>
    private static void DisposeUnclaimedParseCarriers(CBAdESSign1ParseResult parseResult)
    {
        parseResult.RawProtectedHeader?.Dispose();
        parseResult.Signature?.Dispose();
        parseResult.RawUnsignedHeaders?.Dispose();
    }


    /// <summary>
    /// Resolves the verification payload per clause 5.2.8's four cases (see the type remarks) and, for the
    /// <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/> case, independently re-verifies every
    /// <c>hashV</c> entry.
    /// </summary>
    /// <param name="payload">The wire COSE Payload bytes (empty when detached — the caller's own attachment state).</param>
    /// <param name="headers">The decoded, already B-B-conformant signed-header-set aggregate.</param>
    /// <param name="payloadIsDetached">Whether the COSE Payload is detached (the wire <c>nil</c> sentinel).</param>
    /// <param name="dereference">The <c>sigD</c> dereference seam, or <see langword="null"/>.</param>
    /// <param name="dereferenceContext">The per-call context for <paramref name="dereference"/> and <paramref name="unknownMechanismHandler"/>.</param>
    /// <param name="externalDetachedPayload">The caller-supplied out-of-band detached payload, or <see langword="null"/>.</param>
    /// <param name="unknownMechanismHandler">The unknown-<c>mId</c> handler, or <see langword="null"/>.</param>
    /// <param name="pool">Memory pool for dereferenced/reconstructed byte carriers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A tuple: whether resolution succeeded; a <see cref="PooledMemory"/> the caller must dispose when a
    /// mechanism rented one (<see langword="null"/> otherwise — the attached and empty-stream cases rent
    /// nothing); the resolved payload view (valid only when resolution succeeded); the failure detail (valid
    /// only when resolution failed).
    /// </returns>
    /// <remarks>
    /// Structure-agnostic: takes the wire payload bytes directly rather than a
    /// <see cref="CBAdESSign1ParseResult"/>, so both <see cref="VerifyStructureAndSignatureAsync"/> (<c>COSE_Sign1</c>)
    /// and <see cref="ValidateCoseSignAsync"/> (<c>COSE_Sign</c>, per signer, over the ONE shared body-layer
    /// payload — RFC 9052 §4.1) resolve <c>sigD</c> through the identical mechanism.
    /// </remarks>
    private static async ValueTask<(bool Resolved, PooledMemory? Rented, ReadOnlyMemory<byte> Payload, CBAdESValidationFailure? Failure)> ResolveVerificationPayloadAsync(
        ReadOnlyMemory<byte> payload,
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(!payloadIsDetached)
        {
            return (true, null, payload, null);
        }

        if(headers.DetachedObjects is null)
        {
            //Detached, no sigD: only the caller-supplied out-of-band bytes can stand in for the payload
            //(clause 5.2.6 closing paragraph / clause 5.3.5.3 NOTE 1).
            return externalDetachedPayload.HasValue
                ? (true, null, externalDetachedPayload.Value, null)
                : (false, null, default, new CBAdESDetachedObjectUnresolvableFailure(
                    null,
                    "The COSE Payload is detached and sigD is absent, but no out-of-band detached payload " +
                    "was supplied (ETSI TS 119 152-1 V1.1.1, clause 5.2.6)."));
        }

        CBAdESDetachedObjects sigD = headers.DetachedObjects;

        //dereferenceContext is required by all three onward paths (the two built-in mechanisms AND the
        //unknown-mechanism handler); dereference itself is required only by the two built-in mechanisms — an
        //unknown-mechanism-only caller may legitimately supply a handler without the ordinary dereference seam.
        if(dereferenceContext is null)
        {
            return (false, null, default, new CBAdESDetachedObjectUnresolvableFailure(
                null,
                $"sigD selects '{sigD.MechanismIdentifier}', but no dereference context was supplied (ETSI TS " +
                "119 152-1 V1.1.1, clause 5.2.8.2.1)."));
        }

        if(CBAdESDetachedMechanisms.IsObjectIdByURI(sigD.MechanismIdentifier))
        {
            if(dereference is null)
            {
                return (false, null, default, new CBAdESDetachedObjectUnresolvableFailure(
                    null,
                    "sigD selects ObjectIdByURI, but no dereference delegate was supplied (ETSI TS 119 152-1 " +
                    "V1.1.1, clause 5.2.8.2.1)."));
            }

            try
            {
                PooledMemory rented = await CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync(
                    BuildReferenceList(sigD),
                    dereference,
                    dereferenceContext,
                    pool,
                    cancellationToken).ConfigureAwait(false);

                return (true, rented, rented.AsReadOnlyMemory(), null);
            }
            catch(CBAdESDetachedObjectDereferenceException ex)
            {
                return (false, null, default, new CBAdESDetachedObjectUnresolvableFailure(ex.UriReference, ex.Message));
            }
        }

        if(CBAdESDetachedMechanisms.IsObjectIdByURIHash(sigD.MechanismIdentifier))
        {
            if(dereference is null)
            {
                return (false, null, default, new CBAdESDetachedObjectUnresolvableFailure(
                    null,
                    "sigD selects ObjectIdByURIHash, but no dereference delegate was supplied (ETSI TS 119 " +
                    "152-1 V1.1.1, clause 5.2.8.2.1)."));
            }

            CBAdESValidationFailure? digestFailure = await VerifyObjectIdByURIHashDigestsAsync(
                sigD, dereference, dereferenceContext, pool, cancellationToken).ConfigureAwait(false);

            //CB-5.2.8.2.3-06: the COSE Payload contributes as an empty stream to signature verification,
            //regardless of the digest-verification outcome computed above (the digest check is a separate,
            //independent gate this method folds into the same resolution failure channel).
            return digestFailure is null
                ? (true, null, ReadOnlyMemory<byte>.Empty, null)
                : (false, null, default, digestFailure);
        }

        //An mId this document does not define (CB-5.2.6-07/CB-5.2.8-08).
        if(unknownMechanismHandler is null)
        {
            return (false, null, default, new CBAdESDetachedObjectUnresolvableFailure(
                null,
                $"sigD.mId '{sigD.MechanismIdentifier}' is not one of the two mechanisms this document " +
                "defines, and no unknown-mechanism handler was supplied (ETSI TS 119 152-1 V1.1.1, clause " +
                "5.2.6, CB-5.2.6-07; clause 5.2.8.1, CB-5.2.8-08)."));
        }

        try
        {
            PooledMemory handled = await unknownMechanismHandler(
                sigD.MechanismIdentifier,
                BuildReferenceInputs(sigD),
                sigD.HashAlgorithm,
                dereferenceContext,
                pool,
                cancellationToken).ConfigureAwait(false);

            return (true, handled, handled.AsReadOnlyMemory(), null);
        }
        catch(CBAdESDetachedObjectDereferenceException ex)
        {
            //This is the delegate's own documented routine-failure signal (see
            //CBAdESUnknownDetachedObjectMechanismDelegate's remarks) -- anything else (cancellation, a
            //programming error, a non-routine implementer-infrastructure fault) is NOT caught here and
            //propagates unmodified, matching the creation side's own (uncatching) contract for this delegate.
            string reason = ex.UriReference is not null
                ? $"The unknown-mechanism handler for sigD.mId '{sigD.MechanismIdentifier}' failed to retrieve '{ex.UriReference}': {ex.Message}"
                : $"The unknown-mechanism handler for sigD.mId '{sigD.MechanismIdentifier}' failed: {ex.Message}";

            return (false, null, default, new CBAdESDetachedObjectUnresolvableFailure(ex.UriReference, reason));
        }
    }


    /// <summary>
    /// Independently re-verifies every <c>hashV</c> entry of a <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/>
    /// <c>sigD</c> against the dereferenced object it references, via the registered digest delegate resolved
    /// from <c>hashM</c> (hash-via-registered-digest rule) — CB-5.2.8.2.3-05.
    /// </summary>
    /// <param name="sigD">The decoded <c>sigD</c> component (mechanism already confirmed <c>ObjectIdByURIHash</c>).</param>
    /// <param name="dereference">The dereference seam.</param>
    /// <param name="dereferenceContext">The per-call context.</param>
    /// <param name="pool">Memory pool for the dereferenced byte carriers and the recomputed digest.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="null"/> when every entry verifies; otherwise the failure to report.</returns>
    private static async ValueTask<CBAdESValidationFailure?> VerifyObjectIdByURIHashDigestsAsync(
        CBAdESDetachedObjects sigD,
        CBAdESDetachedObjectDereferenceDelegate dereference,
        CBAdESDetachedObjectDereferenceContext dereferenceContext,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        (Tag Tag, int OutputByteLength)? algorithm =
            sigD.HashAlgorithm is not null ? TryResolveDigestAlgorithm(sigD.HashAlgorithm) : null;

        for(int i = 0; i < sigD.DetachedObjects.Count; ++i)
        {
            CBAdESDetachedObjectEntry entry = sigD.DetachedObjects[i];
            DigestValue? signedDigest = entry.Digest;

            if(algorithm is null || signedDigest is null)
            {
                //A missing hashM (rejected by CBAdESHeaderRules.Check before this method ever runs), an
                //unresolvable hashM identifier, or an entry with no per-position hashV: none of these can be
                //verified, so each is treated as a mismatch rather than silently skipped (fail closed).
                return new CBAdESDetachedObjectDigestMismatchFailure(entry.Reference);
            }

            CBAdESDetachedObjectDereferenceResult dereferenceResult = await dereference(
                entry.Reference, dereferenceContext, pool, cancellationToken).ConfigureAwait(false);

            if(dereferenceResult is not CBAdESDetachedObjectDereferenceSuccess success)
            {
                string reason = dereferenceResult is CBAdESDetachedObjectDereferenceFailure failure
                    ? failure.Reason
                    : "the dereference delegate returned neither a success nor a failure result.";

                return new CBAdESDetachedObjectUnresolvableFailure(entry.Reference, reason);
            }

            using(success.Content)
            {
                using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
                    success.Content.AsReadOnlyMemory(),
                    algorithm.Value.OutputByteLength,
                    algorithm.Value.Tag,
                    pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                if(computed != signedDigest)
                {
                    return new CBAdESDetachedObjectDigestMismatchFailure(entry.Reference);
                }
            }
        }

        return null;
    }


    /// <summary>
    /// Resolves a <see cref="AdESDigestAlgorithmIdentifier"/> to the <see cref="Tag"/> and output byte
    /// length <see cref="CryptographicKeyEvents.ComputeDigestAsync(System.ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, CancellationToken)"/>
    /// needs, recognizing the SHA-256/384/512 identifiers this library's own registries assign — both the
    /// <c>int</c> arm (<see cref="WellKnownCoseAlgorithms"/>) and the <c>tstr</c> arm
    /// (<see cref="WellKnownHashAlgorithms"/>'s multi-spelling recognizers).
    /// </summary>
    /// <param name="identifier">The digest-algorithm identifier from <c>hashM</c>.</param>
    /// <returns>The resolved tag and output length, or <see langword="null"/> when unrecognized.</returns>
    private static (Tag Tag, int OutputByteLength)? TryResolveDigestAlgorithm(AdESDigestAlgorithmIdentifier identifier) => identifier switch
    {
        AdESDigestAlgorithmIntegerIdentifier integer when WellKnownCoseAlgorithms.IsSha256(integer.Value) =>
            (CryptoTags.Sha256Digest, WellKnownHashAlgorithms.Sha256SizeBytes),
        AdESDigestAlgorithmIntegerIdentifier integer when WellKnownCoseAlgorithms.IsSha384(integer.Value) =>
            (CryptoTags.Sha384Digest, WellKnownHashAlgorithms.Sha384SizeBytes),
        AdESDigestAlgorithmIntegerIdentifier integer when WellKnownCoseAlgorithms.IsSha512(integer.Value) =>
            (CryptoTags.Sha512Digest, WellKnownHashAlgorithms.Sha512SizeBytes),
        AdESDigestAlgorithmTextIdentifier text when WellKnownHashAlgorithms.IsSha256(text.Value) =>
            (CryptoTags.Sha256Digest, WellKnownHashAlgorithms.Sha256SizeBytes),
        AdESDigestAlgorithmTextIdentifier text when WellKnownHashAlgorithms.IsSha384(text.Value) =>
            (CryptoTags.Sha384Digest, WellKnownHashAlgorithms.Sha384SizeBytes),
        AdESDigestAlgorithmTextIdentifier text when WellKnownHashAlgorithms.IsSha512(text.Value) =>
            (CryptoTags.Sha512Digest, WellKnownHashAlgorithms.Sha512SizeBytes),
        _ => null
    };


    /// <summary>
    /// Projects <paramref name="detachedObjects"/>'s entries onto their bare reference strings, in wire order —
    /// shared by <see cref="ResolveVerificationPayloadAsync"/>'s <c>ObjectIdByURI</c> arm and
    /// <see cref="ResolvePayloadTimestampImprintSourceAsync"/>'s identical dereference-and-concatenate need
    /// (reuse over reinvention).
    /// </summary>
    /// <param name="detachedObjects">The <c>sigD</c> component to project.</param>
    /// <returns>The <c>pars</c> reference strings, in order.</returns>
    private static string[] BuildReferenceList(CBAdESDetachedObjects detachedObjects)
    {
        var references = new string[detachedObjects.DetachedObjects.Count];
        for(int i = 0; i < references.Length; ++i)
        {
            references[i] = detachedObjects.DetachedObjects[i].Reference;
        }

        return references;
    }


    /// <summary>
    /// Projects <paramref name="detachedObjects"/>'s entries onto <see cref="CBAdESDetachedObjectReferenceInput"/>,
    /// in wire order — shared by <see cref="ResolveVerificationPayloadAsync"/>'s unknown-mechanism arm and
    /// <see cref="ResolvePayloadTimestampImprintSourceAsync"/>'s identical need.
    /// </summary>
    /// <param name="detachedObjects">The <c>sigD</c> component to project.</param>
    /// <returns>The reference/content-type pairs, in order.</returns>
    private static CBAdESDetachedObjectReferenceInput[] BuildReferenceInputs(CBAdESDetachedObjects detachedObjects)
    {
        var inputs = new CBAdESDetachedObjectReferenceInput[detachedObjects.DetachedObjects.Count];
        for(int i = 0; i < inputs.Length; ++i)
        {
            CBAdESDetachedObjectEntry entry = detachedObjects.DetachedObjects[i];
            inputs[i] = new CBAdESDetachedObjectReferenceInput(entry.Reference, entry.ContentType);
        }

        return inputs;
    }


    /// <summary>
    /// Collects the signing-certificate digest facts <see cref="CBAdESLevelRuleContext.SigningCertificateDigests"/>
    /// needs (CB-A.1.1-02) directly from <paramref name="headers"/>'s own <c>x5t</c>/<c>x5ts</c> members —
    /// facts the signature's own protected headers already assert, never a resolved or hashed certificate
    /// (certificate-path neutrality, see the type remarks).
    /// </summary>
    /// <param name="headers">The decoded signed-header-set aggregate.</param>
    /// <returns>
    /// Every digest <see cref="CBAdESProtectedHeaders.X5T"/>/<see cref="CBAdESProtectedHeaders.CertificateDigests"/>
    /// assert, or <see langword="null"/> when neither is present (<see cref="CBAdESProtectedHeaders.X5Chain"/>
    /// carries certificate bytes rather than a digest and is deliberately not hashed here — a documented scope
    /// note, not an oversight: <see cref="CBAdESLevelRuleContext.SigningCertificateDigests"/>'s
    /// own remarks already treat a <see langword="null"/>/empty fact as "skip this check", never a false
    /// positive).
    /// </returns>
    private static List<DigestValue>? CollectSigningCertificateDigests(CBAdESProtectedHeaders headers)
    {
        var digests = new List<DigestValue>();

        if(headers.X5T is not null)
        {
            digests.Add(headers.X5T.Digest);
        }

        if(headers.CertificateDigests is not null)
        {
            for(int i = 0; i < headers.CertificateDigests.Thumbprints.Count; ++i)
            {
                digests.Add(headers.CertificateDigests.Thumbprints[i].Digest);
            }
        }

        return digests.Count > 0 ? digests : null;
    }


    /// <summary>
    /// Opens and CMS-verifies every token of <paramref name="container"/>, appending a
    /// <see cref="CBAdESTimestampTokenBindingViolation"/> for a token that could not be read or whose message
    /// imprint does not match <paramref name="expectedImprintInput"/> (when supplied), and — from the declared
    /// level B-LT onward — a <see cref="CBAdESTimestampSignerCertificateCoverageViolation"/> for a token whose
    /// signer certificate is not resolvable. EVERY token in <paramref name="container"/> is
    /// checked against the SAME <paramref name="expectedImprintInput"/> (one instance may carry
    /// more than one token, e.g. an <c>arcTst</c> instance under additional requirement (j)).
    /// </summary>
    /// <param name="container">The <c>tstContainer</c> to verify.</param>
    /// <param name="kind">Which token kind <paramref name="container"/> belongs to.</param>
    /// <param name="expectedImprintInput">
    /// The expected message-imprint input, or <see langword="null"/> to skip imprint verification entirely and
    /// only check that every token opens and CMS-verifies.
    /// </param>
    /// <param name="instanceOrdinal">
    /// This <c>uHeaders</c> element's own zero-based position, attributing which instance of a repeated kind
    /// <paramref name="container"/> belongs to (Table 14 note 7); <c>0</c> for
    /// <see cref="CBAdESTimestampTokenBindingKind.PayloadTimestamp"/>, since <c>adoTst</c> is a signed header
    /// parameter that never repeats.
    /// </param>
    /// <param name="level">The baseline level checked against — gates the per-token coverage check to B-LT and above.</param>
    /// <param name="validationDataCertificates">The signature's own <c>valData</c> certificate candidates, for the coverage check.</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the token and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see langword="true"/> when at least one successfully-opened token carries
    /// <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.
    /// </returns>
    private static async ValueTask<bool> VerifyTimestampContainerAsync(
        AdESTimestampContainer container,
        CBAdESTimestampTokenBindingKind kind,
        ReadOnlyMemory<byte>? expectedImprintInput,
        int instanceOrdinal,
        AdESBaselineLevel level,
        IReadOnlyList<AdESPkiObject> validationDataCertificates,
        List<CBAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        bool anyEmbedded = false;
        for(int t = 0; t < container.TstTokens.Count; ++t)
        {
            anyEmbedded |= await VerifyOneTimestampTokenAsync(
                container.TstTokens[t], kind, expectedImprintInput, instanceOrdinal, t, level, validationDataCertificates, violations, pool, cancellationToken).ConfigureAwait(false);
        }

        return anyEmbedded;
    }


    /// <summary>
    /// Opens and CMS-verifies one electronic time-stamp token via the single CMS choke point
    /// (<see cref="TimestampTokenInfo.ReadFromTokenAsync"/>), checks — when <paramref name="expectedImprintInput"/>
    /// is supplied — that its message imprint binds it (<see cref="TimestampTokenInfo.VerifyMessageImprintAsync"/>),
    /// and — from the declared <paramref name="level"/> B-LT onward — that its signer certificate is
    /// resolvable (<see cref="CBAdESLevelRules.IsTimestampTokenSignerCertificateResolvedAsync"/>)
    /// while the token is still open (the ONLY point <see cref="TimestampTokenInfo"/>'s facts exist).
    /// </summary>
    /// <param name="token">The token to verify.</param>
    /// <param name="kind">Which token kind <paramref name="token"/> belongs to.</param>
    /// <param name="expectedImprintInput">The expected message-imprint input, or <see langword="null"/> to skip imprint verification.</param>
    /// <param name="instanceOrdinal">The owning <c>uHeaders</c> element's zero-based position, threaded onto every violation this call reports.</param>
    /// <param name="tokenOrdinal">This token's own zero-based position within its instance's <c>tstContainer</c> (an instance may carry more than one token).</param>
    /// <param name="level">The baseline level checked against — gates the per-token coverage check to B-LT and above.</param>
    /// <param name="validationDataCertificates">The signature's own <c>valData</c> certificate candidates, for the coverage check.</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the token and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when the token opened and carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
    private static async ValueTask<bool> VerifyOneTimestampTokenAsync(
        AdESTimestampToken token,
        CBAdESTimestampTokenBindingKind kind,
        ReadOnlyMemory<byte>? expectedImprintInput,
        int instanceOrdinal,
        int tokenOrdinal,
        AdESBaselineLevel level,
        IReadOnlyList<AdESPkiObject> validationDataCertificates,
        List<CBAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using PkiCertificateMemory tokenMemory = RentTimestampTokenMemory(token.Val, pool);
        using TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(tokenMemory, pool, cancellationToken).ConfigureAwait(false);

        if(!tokenInfo.IsRead)
        {
            violations.Add(new CBAdESTimestampTokenBindingViolation(
                kind,
                CBAdESTimestampTokenBindingFailureReason.TokenNotRead,
                $"The token could not be read (status: {tokenInfo.Status}).",
                instanceOrdinal,
                tokenOrdinal));

            return false;
        }

        if(expectedImprintInput is not null)
        {
            bool imprintMatches = await tokenInfo.VerifyMessageImprintAsync(
                expectedImprintInput.Value, pool, cancellationToken).ConfigureAwait(false);

            if(!imprintMatches)
            {
                violations.Add(new CBAdESTimestampTokenBindingViolation(
                    kind,
                    CBAdESTimestampTokenBindingFailureReason.ImprintMismatch,
                    "The token's message imprint does not match the expected input.",
                    instanceOrdinal,
                    tokenOrdinal));
            }
        }

        if(level >= AdESBaselineLevel.BLT)
        {
            bool signerCertificateResolved = await CBAdESLevelRules.IsTimestampTokenSignerCertificateResolvedAsync(
                tokenInfo, validationDataCertificates, pool, cancellationToken).ConfigureAwait(false);

            if(!signerCertificateResolved)
            {
                violations.Add(new CBAdESTimestampSignerCertificateCoverageViolation(kind, DescribeUnresolvedSignerCondition(tokenInfo)));
            }
        }

        return tokenInfo.HasEmbeddedCertificates;

        /// <summary>
        /// Names the actual condition <see cref="CBAdESLevelRules.IsTimestampTokenSignerCertificateResolvedAsync"/>
        /// found unresolvable, so <see cref="CBAdESTimestampSignerCertificateCoverageViolation"/>
        /// never carries a generic message a reader cannot act on.
        /// </summary>
        /// <param name="tokenInfo">The token the coverage check ran against.</param>
        /// <returns>A human-readable statement of why the signer certificate did not resolve.</returns>
        static string DescribeUnresolvedSignerCondition(TimestampTokenInfo tokenInfo) => tokenInfo.EmbeddedMaterialStatus switch
        {
            CmsEmbeddedMaterialStatus.Malformed =>
                "the token's own embedded certificate/CRL material could not be read (status: Malformed), so its signer identity cannot be confirmed.",
            _ =>
                "the token's own signer identity matches neither an embedded certificate nor any valData certificate candidate."
        };
    }


    /// <summary>
    /// Copies <paramref name="tokenValue"/> into pool-rented memory and wraps it as a
    /// <see cref="PkiCertificateMemory"/> tagged <see cref="PkiCertificateTags.TimestampToken"/>, mirroring
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// this library's</see> established copy-into-pooled-carrier idiom for a token this class does not itself
    /// own the backing memory of (<see cref="AdESTimestampToken.Val"/> is a borrowed view).
    /// </summary>
    /// <remarks>
    /// Internal, not private: <see cref="CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/>
    /// reuses this SAME helper to open an <c>arcTst</c> instance's own tokens for the CB-A.1.1-30 candidate-set
    /// widening, rather than re-implementing the identical copy-into-pooled-carrier shape a second time — both
    /// classes live in this same assembly (<c>Verifiable.JCose</c>), so widening to <see langword="internal"/>
    /// is the whole reuse mechanism; no behavior changes for this method's existing callers.
    /// </remarks>
    /// <param name="tokenValue">The token's encoded octets (<see cref="AdESTimestampToken.Val"/>).</param>
    /// <param name="pool">The memory pool to rent from.</param>
    /// <returns>The owned carrier. The caller disposes it.</returns>
    internal static PkiCertificateMemory RentTimestampTokenMemory(ReadOnlyMemory<byte> tokenValue, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(tokenValue.Length, 1));
        try
        {
            tokenValue.Span.CopyTo(owner.Memory.Span);
            return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Builds the <c>sigRTst</c> message-imprint input (Annex A.1.2.1.2) from the raw captured <c>uHeaders</c>
    /// wire bytes and the COSE signature value, then verifies every token of <paramref name="container"/>
    /// against it.
    /// </summary>
    /// <param name="container">The <c>sigRTst</c> element's <c>tstContainer</c>.</param>
    /// <param name="signatureValueBytes">The COSE signature value's raw content bytes (Annex A.1.2.1.2 step 2).</param>
    /// <param name="rawUnsignedHeaders">The raw captured <c>uHeaders</c> wire bytes, or <see langword="null"/> when unexpectedly absent (fail-closed).</param>
    /// <param name="elementIndex">
    /// This <c>sigRTst</c> instance's own zero-based position within <c>uHeaders</c>, threaded as the
    /// exclusive validation-time prefix bound: only the elements strictly before
    /// this position contribute to the expected imprint, so a later sibling <c>sigTst</c> instance appended
    /// after this <c>sigRTst</c> (legal per Table 14 note 7) never changes what this specific instance is
    /// checked against.
    /// </param>
    /// <param name="buildImprintInput">The Annex A.1.2.1.2 message-imprint-input builder seam.</param>
    /// <param name="level">The baseline level checked against — gates the per-token coverage check to B-LT and above.</param>
    /// <param name="validationDataCertificates">The signature's own <c>valData</c> certificate candidates, for the coverage check.</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the imprint-input, token, and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when at least one token carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "input is populated only through TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate's " +
            "own out-parameter contract: false with input left null on failure (nothing allocated, nothing to " +
            "dispose on the early-return path immediately below), true with input non-null on success, which " +
            "this method immediately enters a using(input) block over before returning. Roslyn's CA2000 dataflow " +
            "does not correlate the built/input-is-null short-circuit above with the using scope two statements " +
            "later, so it cannot see that every reachable path already disposes or never allocates input.")]
    private static async ValueTask<bool> VerifySignatureAndReferencesTimestampAsync(
        AdESTimestampContainer container,
        ReadOnlyMemory<byte> signatureValueBytes,
        EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders,
        int elementIndex,
        TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate buildImprintInput,
        AdESBaselineLevel level,
        IReadOnlyList<AdESPkiObject> validationDataCertificates,
        List<CBAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(rawUnsignedHeaders is null)
        {
            violations.Add(new CBAdESTimestampTokenBindingViolation(
                CBAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp,
                CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                "sigRTst is present, but no raw uHeaders wire bytes were captured at parse to build its " +
                "message-imprint input from (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.2).",
                elementIndex,
                TokenOrdinal: -1));

            return false;
        }

        bool built = buildImprintInput(signatureValueBytes, rawUnsignedHeaders.AsReadOnlyMemory(), elementIndex, pool, out PooledMemory? input);
        if(!built || input is null)
        {
            violations.Add(new CBAdESTimestampTokenBindingViolation(
                CBAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp,
                CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                "The sigRTst message-imprint input could not be built from the captured uHeaders wire bytes " +
                "(ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.2).",
                elementIndex,
                TokenOrdinal: -1));

            return false;
        }

        using(input)
        {
            return await VerifyTimestampContainerAsync(
                container,
                CBAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp,
                input.AsReadOnlyMemory(),
                elementIndex,
                level,
                validationDataCertificates,
                violations,
                pool,
                cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Builds the <c>rfsTst</c> message-imprint input (Annex A.1.2.2.2) from the raw captured <c>uHeaders</c>
    /// wire bytes, then verifies every token of <paramref name="container"/> against it.
    /// </summary>
    /// <param name="container">The <c>rfsTst</c> element's <c>tstContainer</c>.</param>
    /// <param name="rawUnsignedHeaders">The raw captured <c>uHeaders</c> wire bytes, or <see langword="null"/> when unexpectedly absent (fail-closed).</param>
    /// <param name="elementIndex">
    /// This <c>rfsTst</c> instance's own zero-based position within <c>uHeaders</c>, threaded as the exclusive
    /// validation-time prefix bound — see
    /// <see cref="VerifySignatureAndReferencesTimestampAsync"/>'s identical parameter remarks.
    /// </param>
    /// <param name="buildImprintInput">The Annex A.1.2.2.2 message-imprint-input builder seam.</param>
    /// <param name="level">The baseline level checked against — gates the per-token coverage check to B-LT and above.</param>
    /// <param name="validationDataCertificates">The signature's own <c>valData</c> certificate candidates, for the coverage check.</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the imprint-input, token, and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when at least one token carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "input is populated only through TryBuildReferencesOnlyTimestampMessageImprintInputDelegate's " +
            "own out-parameter contract: false with input left null on failure (nothing allocated, nothing to " +
            "dispose on the early-return path immediately below), true with input non-null on success, which " +
            "this method immediately enters a using(input) block over before returning. Roslyn's CA2000 dataflow " +
            "does not correlate the built/input-is-null short-circuit above with the using scope two statements " +
            "later, so it cannot see that every reachable path already disposes or never allocates input.")]
    private static async ValueTask<bool> VerifyReferencesTimestampAsync(
        AdESTimestampContainer container,
        EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders,
        int elementIndex,
        TryBuildReferencesOnlyTimestampMessageImprintInputDelegate buildImprintInput,
        AdESBaselineLevel level,
        IReadOnlyList<AdESPkiObject> validationDataCertificates,
        List<CBAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(rawUnsignedHeaders is null)
        {
            violations.Add(new CBAdESTimestampTokenBindingViolation(
                CBAdESTimestampTokenBindingKind.ReferencesTimestamp,
                CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                "rfsTst is present, but no raw uHeaders wire bytes were captured at parse to build its " +
                "message-imprint input from (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.2).",
                elementIndex,
                TokenOrdinal: -1));

            return false;
        }

        bool built = buildImprintInput(rawUnsignedHeaders.AsReadOnlyMemory(), elementIndex, pool, out PooledMemory? input);
        if(!built || input is null)
        {
            violations.Add(new CBAdESTimestampTokenBindingViolation(
                CBAdESTimestampTokenBindingKind.ReferencesTimestamp,
                CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                "The rfsTst message-imprint input could not be built from the captured uHeaders wire bytes " +
                "(ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.2).",
                elementIndex,
                TokenOrdinal: -1));

            return false;
        }

        using(input)
        {
            return await VerifyTimestampContainerAsync(
                container,
                CBAdESTimestampTokenBindingKind.ReferencesTimestamp,
                input.AsReadOnlyMemory(),
                elementIndex,
                level,
                validationDataCertificates,
                violations,
                pool,
                cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Builds the <c>arcTst</c> message-imprint input in validation mode (clause 5.3.5.3) for the specific
    /// <c>arcTst</c> instance at <paramref name="elementIndex"/>, then verifies every token of
    /// <paramref name="container"/> against it (EVERY token in this instance over the SAME
    /// input, whatever its cardinality).
    /// </summary>
    /// <param name="container">The <c>arcTst</c> element's <c>tstContainer</c>.</param>
    /// <param name="bodyProtectedHeaderBytes">The raw captured body-layer protected-header wire bytes (clause 5.3.5.3 step 3).</param>
    /// <param name="externallySuppliedData">The externally supplied application data (clause 5.3.5.3 step 5).</param>
    /// <param name="payloadSource">The resolved payload contribution (steps 6/7), or <see langword="null"/> when resolution failed.</param>
    /// <param name="payloadFailureReason">Why <paramref name="payloadSource"/> is <see langword="null"/>, when it is.</param>
    /// <param name="signatureValueBytes">The COSE signature value's raw content bytes (step 9).</param>
    /// <param name="rawUnsignedHeaders">The raw captured <c>uHeaders</c> wire bytes, or <see langword="null"/> when unexpectedly absent (fail-closed).</param>
    /// <param name="elementIndex">
    /// This <c>arcTst</c> instance's own zero-based position within <c>uHeaders</c>, threaded as the exclusive
    /// validation-time prefix bound (5.3.5.3's own validation variant, "elements that precede... the arcTst
    /// CBOR map that contains the time-stamp token that is being validated"): only the elements strictly
    /// before this position contribute, so a later sibling <c>arcTst</c> instance appended after this one
    /// never changes what THIS instance is checked against.
    /// </param>
    /// <param name="buildImprintInput">The clause 5.3.5.3 validation-mode message-imprint-input builder seam.</param>
    /// <param name="level">The baseline level checked against — gates the per-token coverage check to B-LT and above.</param>
    /// <param name="validationDataCertificates">The signature's own <c>valData</c> certificate candidates, for the coverage check.</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the imprint-input, token, and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when at least one token carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "input is populated only through TryBuildArchiveTimestampValidationMessageImprintInputDelegate's " +
            "own out-parameter contract: false with input left null on failure (nothing allocated, nothing to " +
            "dispose on the early-return path immediately below), true with input non-null on success, which " +
            "this method immediately enters a using(input) block over before returning. Roslyn's CA2000 dataflow " +
            "does not correlate the built/input-is-null short-circuit above with the using scope two statements " +
            "later, so it cannot see that every reachable path already disposes or never allocates input.")]
    private static async ValueTask<bool> VerifyArchiveTimestampAsync(
        AdESTimestampContainer container,
        ReadOnlyMemory<byte> bodyProtectedHeaderBytes,
        ReadOnlyMemory<byte> externallySuppliedData,
        CBAdESPayloadTimestampImprintSource? payloadSource,
        string? payloadFailureReason,
        ReadOnlyMemory<byte> signatureValueBytes,
        EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders,
        int elementIndex,
        TryBuildArchiveTimestampValidationMessageImprintInputDelegate buildImprintInput,
        AdESBaselineLevel level,
        IReadOnlyList<AdESPkiObject> validationDataCertificates,
        List<CBAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(rawUnsignedHeaders is null)
        {
            violations.Add(new CBAdESTimestampTokenBindingViolation(
                CBAdESTimestampTokenBindingKind.ArchiveTimestamp,
                CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                "arcTst is present, but no raw uHeaders wire bytes were captured at parse to build its " +
                "message-imprint input from (ETSI TS 119 152-1 V1.1.1, clause 5.3.5.3).",
                elementIndex,
                TokenOrdinal: -1));

            return false;
        }

        if(payloadSource is null)
        {
            violations.Add(new CBAdESTimestampTokenBindingViolation(
                CBAdESTimestampTokenBindingKind.ArchiveTimestamp,
                CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                payloadFailureReason ?? "The arcTst message-imprint input's payload contribution (clause " +
                    "5.3.5.3 steps 6/7) could not be resolved.",
                elementIndex,
                TokenOrdinal: -1));

            return false;
        }

        bool built = buildImprintInput(
            CBAdESImprintCoseSign1StructureContext.Instance,
            bodyProtectedHeaderBytes,
            signerProtectedHeader: null,
            externallySuppliedData,
            payloadSource,
            countersignatureOtherFields: null,
            signatureValueBytes,
            rawUnsignedHeaders.AsReadOnlyMemory(),
            elementIndex,
            pool,
            out PooledMemory? input);

        if(!built || input is null)
        {
            violations.Add(new CBAdESTimestampTokenBindingViolation(
                CBAdESTimestampTokenBindingKind.ArchiveTimestamp,
                CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                "The arcTst message-imprint input could not be built from the captured uHeaders wire bytes " +
                "(ETSI TS 119 152-1 V1.1.1, clause 5.3.5.3).",
                elementIndex,
                TokenOrdinal: -1));

            return false;
        }

        using(input)
        {
            return await VerifyTimestampContainerAsync(
                container,
                CBAdESTimestampTokenBindingKind.ArchiveTimestamp,
                input.AsReadOnlyMemory(),
                elementIndex,
                level,
                validationDataCertificates,
                violations,
                pool,
                cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Decodes and, when the caller opted in, cryptographically verifies one <c>uHeaders</c> counter-signature
    /// element (label 11 or 12), appending a violation for malformed content or a failing signature — never for
    /// the element's mere presence (CB-6.3-30). Label 11's own value type is
    /// <c>COSE_Countersignature / [+ COSE_Countersignature]</c> (RFC 9338 §2 Table 1): when the element decodes
    /// into a <see cref="CounterSignatureV2Sequence"/> rather than a lone <see cref="CounterSignatureV2"/>, every
    /// countersignature the sequence carries gets the SAME per-countersignature checks below, all reported
    /// against this one <paramref name="elementIndex"/> — RFC 9338 never distinguishes the two shapes'
    /// per-countersignature semantics, only how many are carried together.
    /// </summary>
    /// <param name="element">
    /// The <c>uHeaders</c> element under inspection — must be a <see cref="CBAdESUnsignedHeaderElementFullCounterSignature"/>
    /// or <see cref="CBAdESUnsignedHeaderElementAbbreviatedCounterSignature"/>.
    /// </param>
    /// <param name="elementIndex">The element's own zero-based position within <c>uHeaders</c>.</param>
    /// <param name="bodyProtectedHeaderBytes">
    /// The raw captured body-layer protected-header wire bytes — RFC 9338 §3.3's <c>Countersign_structure</c>
    /// <c>body_protected</c> field for a <c>COSE_Sign1</c> target (this orchestrator's own scope; see the class
    /// remarks).
    /// </param>
    /// <param name="payload">The COSE Payload bytes — the <c>Countersign_structure</c> <c>payload</c> field.</param>
    /// <param name="signatureValueBytes">
    /// The COSE signature value's raw content bytes — the <c>Countersign_structure</c> <c>other_fields</c>
    /// element for a <c>COSE_Sign1</c> target.
    /// </param>
    /// <param name="parseCounterSignatureHeaderValue">
    /// Decodes the element's raw value bytes, or <see langword="null"/> to skip decode/verification entirely
    /// (opt-in seam).
    /// </param>
    /// <param name="decodeProtectedHeader">
    /// Decodes a full counter-signature's OWN protected header (<see cref="CounterSignatureV2.ProtectedHeader"/>)
    /// for the CB-5.2.8-09 <c>sigD</c>-never-on-a-countersignature check, or <see langword="null"/> to skip that
    /// specific check (opt-in, matching this method's own graceful-degradation posture for every other
    /// capability it needs a caller-supplied seam for). Never consulted for an abbreviated (label 12)
    /// countersignature — RFC 9338 §3.2: "no provision for any protected attributes" — so no sigD-placement
    /// question can arise for that arm.
    /// </param>
    /// <param name="buildCountersignStructure">Builds the Countersign_structure ToBeSigned bytes, or <see langword="null"/> to skip verification.</param>
    /// <param name="resolveCounterSignaturePublicKey">Resolves the countersigner's public key, or <see langword="null"/> to skip verification.</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the decode buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private static async ValueTask VerifyCounterSignatureAsync(
        CBAdESUnsignedHeaderElement element,
        int elementIndex,
        ReadOnlyMemory<byte> bodyProtectedHeaderBytes,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signatureValueBytes,
        ParseCounterSignatureHeaderValueDelegate? parseCounterSignatureHeaderValue,
        DecodeCBAdESProtectedHeaderDelegate? decodeProtectedHeader,
        BuildCountersignStructureDelegate? buildCountersignStructure,
        CBAdESResolveCounterSignaturePublicKeyDelegate? resolveCounterSignaturePublicKey,
        List<CBAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(parseCounterSignatureHeaderValue is null)
        {
            //Opt-in seam: a caller that never supplies a decode delegate gets structural acceptance only.
            return;
        }

        (bool isAbbreviated, int label, ReadOnlyMemory<byte> valueBytes) = element switch
        {
            CBAdESUnsignedHeaderElementFullCounterSignature full => (false, CoseHeaderParameters.CounterSignatureVersion2, full.Value),
            CBAdESUnsignedHeaderElementAbbreviatedCounterSignature abbreviated => (true, CoseHeaderParameters.Countersignature0Version2, abbreviated.Value),
            _ => throw new ArgumentOutOfRangeException(nameof(element), element, "Not a counter-signature uHeaders element.")
        };

        using CoseCounterSignatureParseResult parseResult = parseCounterSignatureHeaderValue(label, valueBytes, pool);
        if(!parseResult.IsSuccess || parseResult.CounterSignature is null)
        {
            violations.Add(new CBAdESCounterSignatureMalformedViolation(isAbbreviated, elementIndex));
            return;
        }

        //Label 11's value type is COSE_Countersignature / [+ COSE_Countersignature] (RFC 9338 §2 Table 1) --
        //a lone full countersignature or several carried together; label 12 never carries more than one
        //(Table 1 types it as COSE_Countersignature0 alone). Every element this closed sum can produce gets
        //the SAME loop below, all reported against this one elementIndex.
        IReadOnlyList<CoseCounterSignature> counterSignatures = parseResult.CounterSignature switch
        {
            CounterSignatureV2Sequence sequence => sequence.Countersignatures,
            CounterSignatureV2 single => [single],
            CounterSignature0V2 single => [single],
            _ => throw new UnreachableException(
                "CoseCounterSignature is a closed sum of CounterSignatureV2Sequence, CounterSignatureV2, and CounterSignature0V2.")
        };

        var target = new CoseSign1CountersignTarget(bodyProtectedHeaderBytes, payload, signatureValueBytes);

        foreach(CoseCounterSignature counterSignature in counterSignatures)
        {
            //CB-5.2.8-09: sigD shall never appear on a counter signature -- checked on a full countersignature's
            //OWN protected header, independent of whether the caller opted into cryptographic verification
            //below. The abbreviated (label 12) arm carries no protected header at all (RFC 9338 §3.2), so no
            //check applies -- CounterSignature0V2 never matches the type pattern below.
            if(decodeProtectedHeader is not null && counterSignature is CounterSignatureV2 fullCounterSignature)
            {
                CBAdESProtectedHeaders? counterSignatureHeaders = decodeProtectedHeader(fullCounterSignature.ProtectedHeader.AsReadOnlyMemory(), pool);
                if(counterSignatureHeaders is not null)
                {
                    using(counterSignatureHeaders)
                    {
                        if(counterSignatureHeaders.DetachedObjects is not null)
                        {
                            violations.Add(new CBAdESCounterSignatureDetachedObjectsViolation(elementIndex));
                        }
                    }
                }
            }

            if(buildCountersignStructure is null || resolveCounterSignaturePublicKey is null)
            {
                //Material-completeness (which key to trust) is out of this orchestrator's scope, matching its
                //own certificate-path-neutral posture -- decode-only when the caller has not additionally
                //opted into verification.
                continue;
            }

            PublicKeyMemory? counterSignerKey = resolveCounterSignaturePublicKey(counterSignature);
            if(counterSignerKey is null)
            {
                continue;
            }

            bool isCounterSignatureVerified = await CoseCounterSign.VerifyAsync(
                counterSignature,
                target,
                ReadOnlyMemory<byte>.Empty,
                buildCountersignStructure,
                counterSignerKey,
                cancellationToken).ConfigureAwait(false);

            if(!isCounterSignatureVerified)
            {
                violations.Add(new CBAdESCounterSignatureVerificationFailedViolation(isAbbreviated, elementIndex));
            }
        }
    }


    /// <summary>
    /// Resolves the <c>adoTst</c> message-imprint input (clause 5.2.6) from wire bytes — all three arms — and
    /// verifies every token of <see cref="CBAdESProtectedHeaders.PayloadTimestamps"/> against it.
    /// </summary>
    /// <param name="headers">The decoded signed-header-set aggregate (for <see cref="CBAdESProtectedHeaders.PayloadTimestamps"/>/<see cref="CBAdESProtectedHeaders.DetachedObjects"/>).</param>
    /// <param name="payloadIsDetached">Whether the COSE Payload is detached.</param>
    /// <param name="payload">The wire payload bytes (borrowed, safe past parse-result disposal).</param>
    /// <param name="dereference">The <c>sigD</c> dereference seam, or <see langword="null"/>.</param>
    /// <param name="dereferenceContext">The per-call context for <paramref name="dereference"/> and <paramref name="unknownMechanismHandler"/>.</param>
    /// <param name="externalDetachedPayload">The caller-supplied out-of-band detached payload, or <see langword="null"/>.</param>
    /// <param name="unknownMechanismHandler">The unknown-<c>mId</c> handler, or <see langword="null"/>.</param>
    /// <param name="buildImprintInput">The clause 5.2.6 message-imprint-input builder seam.</param>
    /// <param name="level">The baseline level checked against — gates the per-token coverage check to B-LT and above.</param>
    /// <param name="validationDataCertificates">The signature's own <c>valData</c> certificate candidates, for the coverage check.</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the resolution, imprint-input, token, and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when at least one token carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
    private static async ValueTask<bool> VerifyPayloadTimestampAsync(
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        ReadOnlyMemory<byte> payload,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BuildPayloadTimestampMessageImprintInputDelegate buildImprintInput,
        AdESBaselineLevel level,
        IReadOnlyList<AdESPkiObject> validationDataCertificates,
        List<CBAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        (bool resolved, PooledMemory? rentedSource, CBAdESPayloadTimestampImprintSource? source, string? failureReason) =
            await ResolvePayloadTimestampImprintSourceAsync(
                headers, payloadIsDetached, payload, dereference, dereferenceContext,
                externalDetachedPayload, unknownMechanismHandler, CBAdESTimestampTokenBindingKind.PayloadTimestamp,
                pool, cancellationToken).ConfigureAwait(false);

        using(rentedSource)
        {
            if(!resolved || source is null)
            {
                violations.Add(new CBAdESTimestampTokenBindingViolation(
                    CBAdESTimestampTokenBindingKind.PayloadTimestamp,
                    CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                    failureReason ?? "The adoTst message-imprint input (the COSE Payload) could not be resolved.",
                    InstanceOrdinal: 0,
                    TokenOrdinal: -1));

                return false;
            }

            using PooledMemory imprintInput = buildImprintInput(source, pool);

            return await VerifyTimestampContainerAsync(
                headers.PayloadTimestamps!.TimestampContainer,
                CBAdESTimestampTokenBindingKind.PayloadTimestamp,
                imprintInput.AsReadOnlyMemory(),
                instanceOrdinal: 0,
                level,
                validationDataCertificates,
                violations,
                pool,
                cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Resolves the <c>adoTst</c> message-imprint SOURCE (clause 5.2.6's three-way branch on payload
    /// attachment/<c>sigD</c>) from wire bytes. Unlike <see cref="ResolveVerificationPayloadAsync"/>'s
    /// signature-verification payload resolution, the <c>sigD</c>-present arm here dereferences and
    /// concatenates the referenced objects for BOTH <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/> AND
    /// <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/> (clause 5.2.6's own text never shortcuts to an
    /// empty stream the way CB-5.2.8.2.3-06 does for signature verification — the NOTE beside CB-5.2.6-06
    /// explains why: <c>adoTst</c> still time-stamps the retrieved objects, not their digests, "to protect
    /// against future weaknesses of the digest algorithms used in <c>sigD</c>").
    /// </summary>
    /// <param name="headers">The decoded signed-header-set aggregate.</param>
    /// <param name="payloadIsDetached">Whether the COSE Payload is detached.</param>
    /// <param name="payload">The wire payload bytes (borrowed).</param>
    /// <param name="dereference">The <c>sigD</c> dereference seam, or <see langword="null"/>.</param>
    /// <param name="dereferenceContext">The per-call context.</param>
    /// <param name="externalDetachedPayload">The caller-supplied out-of-band detached payload, or <see langword="null"/>.</param>
    /// <param name="unknownMechanismHandler">The unknown-<c>mId</c> handler, or <see langword="null"/>.</param>
    /// <param name="consumingComponent">
    /// Which component this resolution serves —
    /// <see cref="CBAdESTimestampTokenBindingKind.PayloadTimestamp"/> for <c>adoTst</c> (clause 5.2.6) or
    /// <see cref="CBAdESTimestampTokenBindingKind.ArchiveTimestamp"/> for <c>arcTst</c>'s own payload
    /// contribution (clause 5.3.5.3 steps 6/7) — parameterizes every failure reason below so an
    /// <c>arcTst</c>-triggered resolution failure never reads as an <c>adoTst</c> one and vice versa.
    /// </param>
    /// <param name="pool">Memory pool for the dereferenced byte carriers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A tuple: whether resolution succeeded; a <see cref="PooledMemory"/> the caller must dispose when the
    /// <c>sigD</c> arm rented one (<see langword="null"/> for the attached/detached arms, which rent nothing);
    /// the resolved source (valid only when resolution succeeded); a human-readable failure reason (valid only
    /// when resolution failed).
    /// </returns>
    /// <remarks>
    /// <strong>Internal, not private.</strong> <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/>
    /// reuses this SAME resolver for the generation-time payload contribution (clause 5.3.5.3 steps 6/7, which
    /// branch identically to <c>adoTst</c>'s clause 5.2.6) rather than re-implementing the attached/detached/
    /// <c>sigD</c> three-way branch a second time — both classes live in this same assembly
    /// (<c>Verifiable.JCose</c>), so widening to <see langword="internal"/> is the whole reuse mechanism; no
    /// behavior changes for this method's existing validation-side callers beyond the
    /// <paramref name="consumingComponent"/>-driven reason-string parameterization.
    /// </remarks>
    internal static async ValueTask<(bool Resolved, PooledMemory? Rented, CBAdESPayloadTimestampImprintSource? Source, string? FailureReason)> ResolvePayloadTimestampImprintSourceAsync(
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        ReadOnlyMemory<byte> payload,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        CBAdESTimestampTokenBindingKind consumingComponent,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        (string componentLabel, string clauseCitation) = consumingComponent switch
        {
            CBAdESTimestampTokenBindingKind.ArchiveTimestamp => ("arcTst", "clause 5.3.5.3 steps 6/7"),
            _ => ("adoTst", "clause 5.2.6")
        };

        if(!payloadIsDetached)
        {
            return (true, null, new CBAdESAttachedPayloadTimestampImprintSource(payload), null);
        }

        if(headers.DetachedObjects is null)
        {
            return externalDetachedPayload.HasValue
                ? (true, null, new CBAdESDetachedPayloadTimestampImprintSource(externalDetachedPayload.Value), null)
                : (false, null, null, "The COSE Payload is detached and sigD is absent, but no out-of-band " +
                    $"detached payload was supplied (ETSI TS 119 152-1 V1.1.1, {clauseCitation}).");
        }

        CBAdESDetachedObjects sigD = headers.DetachedObjects;

        if(dereferenceContext is null)
        {
            return (false, null, null, $"{componentLabel} requires the COSE Payload, and sigD selects " +
                $"'{sigD.MechanismIdentifier}', but no dereference context was supplied (ETSI TS 119 152-1 " +
                $"V1.1.1, {clauseCitation}, clause 5.2.8.2.1).");
        }

        if(CBAdESDetachedMechanisms.IsObjectIdByURI(sigD.MechanismIdentifier)
            || CBAdESDetachedMechanisms.IsObjectIdByURIHash(sigD.MechanismIdentifier))
        {
            //Both built-in mechanisms dereference-and-concatenate for this imprint (CB-5.2.6-06's adoTst
            //reading, mirrored by arcTst's own clause 5.3.5.3 steps 6/7) — unlike signature-verification
            //payload resolution, ObjectIdByURIHash gets no empty-stream shortcut here.
            if(dereference is null)
            {
                return (false, null, null, $"{componentLabel} requires the COSE Payload via sigD, but no " +
                    $"dereference delegate was supplied (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.1).");
            }

            try
            {
                PooledMemory rented = await CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync(
                    BuildReferenceList(sigD), dereference, dereferenceContext, pool, cancellationToken).ConfigureAwait(false);

                var source = new CBAdESSigDProcessedPayloadTimestampImprintSource([rented.AsReadOnlyMemory()]);
                return (true, rented, source, null);
            }
            catch(CBAdESDetachedObjectDereferenceException ex)
            {
                string reference = ex.UriReference ?? "(unspecified)";
                return (false, null, null, $"Failed to dereference '{reference}' while resolving the " +
                    $"{componentLabel} message-imprint input: {ex.Message}");
            }
        }

        if(unknownMechanismHandler is null)
        {
            return (false, null, null, $"sigD.mId '{sigD.MechanismIdentifier}' is not one of the two defined " +
                $"mechanisms, and no unknown-mechanism handler was supplied for resolving the {componentLabel} " +
                $"message-imprint input (ETSI TS 119 152-1 V1.1.1, {clauseCitation}).");
        }

        try
        {
            PooledMemory handled = await unknownMechanismHandler(
                sigD.MechanismIdentifier, BuildReferenceInputs(sigD), sigD.HashAlgorithm, dereferenceContext,
                pool, cancellationToken).ConfigureAwait(false);

            var source = new CBAdESSigDProcessedPayloadTimestampImprintSource([handled.AsReadOnlyMemory()]);
            return (true, handled, source, null);
        }
        catch(CBAdESDetachedObjectDereferenceException ex)
        {
            return (false, null, null, $"The unknown-mechanism handler for sigD.mId '{sigD.MechanismIdentifier}' " +
                $"failed while resolving the {componentLabel} message-imprint input: {ex.Message}");
        }
    }


    /// <summary>
    /// Determines whether <paramref name="exception"/> represents malformed or non-conformant untrusted wire
    /// bytes that <see cref="VerifyStructureAndSignatureAsync"/> catches to fail closed, mirroring
    /// <see cref="Verifiable.Cbor.CoseVerification"/>'s own classifier.
    /// </summary>
    /// <remarks>
    /// <see cref="ParseCBAdESSign1Delegate"/>'s own documented contract already promises never to throw for
    /// malformed input (its <see cref="CBAdESSign1ParseResult.IsSuccess"/> <see langword="false"/> arm covers
    /// that case), so this catch is belt-and-suspenders defense against a non-conformant implementation of
    /// that delegate, not a documented necessity. <c>Lumoin.Veritas.Cbor.CborException</c> — the type
    /// <see cref="Verifiable.Cbor.CoseVerification"/>'s own classifier includes — is deliberately absent here:
    /// <c>Verifiable.JCose</c> does not reference the CBOR reader package at all (the reference graph runs
    /// <c>Verifiable.Cbor</c> → <c>Verifiable.JCose</c>, never the other way), so this classifier can only name
    /// exception types this project can actually see.
    /// </remarks>
    /// <param name="exception">The exception to classify.</param>
    /// <returns><see langword="true"/> when the exception should be swallowed and reported as MalformedEncoding.</returns>
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is InvalidOperationException or ArgumentException
            or IndexOutOfRangeException or OverflowException or FormatException;


    /// <summary>
    /// Validates a CB-AdES signature over a <c>COSE_Sign</c> (multi-signer) structure — the multi-signer
    /// counterpart of the <c>COSE_Sign1</c> <c>ValidateAsync</c> overloads
    /// above.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>The B-B/level rule bodies run once, reused, per signer — never forked.</strong> Each signer is
    /// checked through the IDENTICAL <see cref="CBAdESHeaderRules.Check"/> and <see cref="CBAdESLevelRules.Check"/>
    /// calls the <c>COSE_Sign1</c> path above runs once for the whole message, mirroring
    /// <see cref="SignCoseSignAsync"/>'s own creation-side per-signer reuse.
    /// </para>
    /// <para>
    /// <strong><c>sigD</c> is per-signer, over the ONE shared body-layer payload.</strong> RFC
    /// 9052 §4.1 gives <c>COSE_Sign</c> exactly one <c>payload</c> field; when it is detached (nil), EACH
    /// signer's own <c>sigD</c> (a signed, signer-layer header component) independently resolves what bytes
    /// that signer's own Sig_structure covers, through the identical <c>ObjectIdByURI</c>/<c>ObjectIdByURIHash</c>/
    /// unknown-mechanism resolution the <c>COSE_Sign1</c> path above uses — mirrored, never re-implemented.
    /// </para>
    /// <para>
    /// <strong>Ownership, exactly once.</strong> This call never wraps <paramref name="parse"/>'s result in a
    /// blanket <c>using</c>: a signer whose header decodes transfers its <c>uHeaders</c> set onward into the
    /// returned per-signer result (<see cref="CBAdESCoseSignSignerValidationResult.UnsignedHeaders"/>); every
    /// OTHER carrier <paramref name="parse"/>'s result owns (each signer's raw protected header/signature/raw
    /// <c>uHeaders</c> bytes, the body-layer raw protected header, and a signer's <c>uHeaders</c> set when its
    /// header never decoded) is disposed directly in this method's own <c>finally</c> — the same lifetime-
    /// rework pattern <see cref="CBAdESSignatureAugmentation"/>'s <c>DisposeAugmentationArtifacts</c> uses for
    /// <see cref="CBAdESSign1ParseResult.RawProtectedHeader"/>, so nothing is EVER disposed twice and nothing
    /// reaches the caller already disposed.
    /// </para>
    /// <para>
    /// <strong>Body-layer placement (CB-4.4-02/clauses 5.1-5.2).</strong> The body layer's own
    /// raw protected header is decoded too; every signer-layer-only component
    /// (<see cref="CBAdESCoseSignBodyLayerComponentKind"/>) found on it becomes a
    /// <see cref="CBAdESCoseSignBodyLayerPlacementViolation"/> on <see cref="CBAdESCoseSignValidationResult.BodyLayerViolations"/>.
    /// A body layer whose protected header does not decode at all (no <c>alg</c> — the ordinary conformant
    /// empty-body-layer case creation mints) carries no such violation; decoding requires <c>alg</c>, so a body
    /// layer that DOES decode has, by that very fact, already misplaced <c>alg</c> itself.
    /// </para>
    /// <para>
    /// See <see cref="CBAdESCoseSignValidationResult"/>'s own remarks for this overload's recorded scope
    /// boundary (structural/level presence conformance rather than timestamp-token content verification).
    /// </para>
    /// </remarks>
    /// <param name="wireBytes">The candidate CB-AdES <c>COSE_Sign</c> wire bytes.</param>
    /// <param name="parse">The fail-closed <c>COSE_Sign</c> parse seam.</param>
    /// <param name="decodeProtectedHeader">The standalone protected-header decode seam.</param>
    /// <param name="buildSigStructure">Delegate to build the <c>COSE_Signature</c> Sig_structure for verification.</param>
    /// <param name="publicKeys">Every signer's own public key, one per <c>COSE_Signature</c> entry, in wire order.</param>
    /// <param name="level">The Table 14 baseline level to check every signer's own <c>uHeaders</c> against.</param>
    /// <param name="pool">Memory pool every allocation this call performs is rented from.</param>
    /// <param name="dereference">The <c>sigD</c> URI-reference dereference seam, or <see langword="null"/>; see the <c>COSE_Sign1</c> B-B-only overload's remarks.</param>
    /// <param name="dereferenceContext">The per-call context for <paramref name="dereference"/> and <paramref name="unknownMechanismHandler"/>.</param>
    /// <param name="externalDetachedPayload">The out-of-band detached COSE Payload bytes shared by every signer with no <c>sigD</c>, or <see langword="null"/>.</param>
    /// <param name="unknownMechanismHandler">Resolves the COSE Payload for an undefined <c>sigD.mId</c>, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">Any required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="publicKeys"/>'s count does not match the wire message's own signer count.</exception>
    public static async ValueTask<CBAdESCoseSignValidationResult> ValidateCoseSignAsync(
        ReadOnlyMemory<byte> wireBytes,
        ParseCBAdESSignDelegate parse,
        DecodeCBAdESProtectedHeaderDelegate decodeProtectedHeader,
        BuildCoseSignatureSigStructureDelegate buildSigStructure,
        IReadOnlyList<PublicKeyMemory> publicKeys,
        AdESBaselineLevel level,
        BaseMemoryPool pool,
        CBAdESDetachedObjectDereferenceDelegate? dereference = null,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext = null,
        ReadOnlyMemory<byte>? externalDetachedPayload = null,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(decodeProtectedHeader);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKeys);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        CBAdESSignParseResult parseResult;
        try
        {
            parseResult = parse(wireBytes, pool);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            return CBAdESCoseSignValidationResult.Malformed();
        }

        if(!parseResult.IsSuccess || parseResult.Signers is null)
        {
            parseResult.Dispose();
            return CBAdESCoseSignValidationResult.Malformed();
        }

        if(publicKeys.Count != parseResult.Signers.Count)
        {
            parseResult.Dispose();
            throw new ArgumentException(
                "One public key is required per COSE_Signature entry, in the same order.", nameof(publicKeys));
        }

        bool payloadIsDetached = !parseResult.PayloadIsPresent;
        var signerResults = new List<CBAdESCoseSignSignerValidationResult>(parseResult.Signers.Count);
        var unsignedHeadersTransferred = new bool[parseResult.Signers.Count];
        bool completed = false;

        try
        {
            //CB-4.4-02/clauses 5.1-5.2: the body layer's own signed-header-set aggregate,
            //decoded standalone -- null when it carries no alg (the ordinary conformant empty-body-layer case;
            //DecodeCBAdESProtectedHeaderDelegate's own contract fails closed on a missing alg, so a body layer
            //that DOES decode has, by that very fact, already misplaced alg per CB-5.1.2-06).
            List<CBAdESRuleViolation> bodyLayerViolations = [];
            CBAdESProtectedHeaders? bodyHeaders = decodeProtectedHeader(parseResult.RawBodyProtectedHeader!.AsReadOnlyMemory(), pool);
            if(bodyHeaders is not null)
            {
                using(bodyHeaders)
                {
                    CollectBodyLayerPlacementViolations(bodyHeaders, bodyLayerViolations);
                }
            }

            for(int i = 0; i < parseResult.Signers.Count; ++i)
            {
                CBAdESSignerParseResult signer = parseResult.Signers[i];

                CBAdESProtectedHeaders? headers = decodeProtectedHeader(signer.RawProtectedHeader.AsReadOnlyMemory(), pool);
                if(headers is null)
                {
                    signerResults.Add(CBAdESCoseSignSignerValidationResult.MalformedHeader());
                    continue;
                }

                //Ownership of signer.UnsignedHeaders transfers from here on -- every mint below (RuleViolations/
                //SignatureInvalid/Success) takes it; this method's own finally never disposes it once this flag
                //is set (ownership exactly once, no use-after-dispose on the returned result).
                unsignedHeadersTransferred[i] = true;

                //The B-B/level rule bodies, reused verbatim, once per signer -- collect posture, mirroring
                //VerifyStructureAndSignatureAsync's own COSE_Sign1 composition. payloadIsDetached is the
                //message's real attachment state, never hardcoded.
                IReadOnlyList<CBAdESRuleViolation> headerViolations = CBAdESHeaderRules.Check(headers, payloadIsDetached, signer.UnsignedHeaders);
                IReadOnlyList<CBAdESRuleViolation> levelViolations = CBAdESLevelRules.Check(
                    new CBAdESLevelRuleContext { Level = level, UnsignedHeaders = signer.UnsignedHeaders });

                if(headerViolations.Count > 0 || levelViolations.Count > 0)
                {
                    var combined = new List<CBAdESRuleViolation>(headerViolations.Count + levelViolations.Count);
                    combined.AddRange(headerViolations);
                    combined.AddRange(levelViolations);

                    signerResults.Add(CBAdESCoseSignSignerValidationResult.RuleViolations(headers, signer.UnsignedHeaders, combined));
                    continue;
                }

                //Resolve THIS signer's own verification payload -- sigD is a signed, signer-layer
                //component, so each signer independently resolves what its own Sig_structure covers, mirroring
                //the COSE_Sign1 path's ResolveVerificationPayloadAsync exactly (a nil payload with no sigD and
                //no out-of-band agreement fails resolution -- the empty-payload exploit-becomes-regression: it
                //must NOT fall through to verifying against an empty byte span).
                (bool resolved, PooledMemory? rentedPayload, ReadOnlyMemory<byte> resolvedPayload, CBAdESValidationFailure? _) =
                    await ResolveVerificationPayloadAsync(
                        parseResult.Payload,
                        headers,
                        payloadIsDetached,
                        dereference,
                        dereferenceContext,
                        externalDetachedPayload,
                        unknownMechanismHandler,
                        pool,
                        cancellationToken).ConfigureAwait(false);

                using(rentedPayload)
                {
                    if(!resolved)
                    {
                        signerResults.Add(CBAdESCoseSignSignerValidationResult.SignatureInvalid(headers, signer.UnsignedHeaders));
                        continue;
                    }

                    //CA2000: verifies directly over the borrowed carriers -- no throwaway
                    //CoseSignatureComponent/CoseSignMessage wrapper is constructed merely to satisfy a
                    //message-shaped signature (the parts-taking CoseSign.VerifyAsync core).
                    bool isVerified = await CoseSign.VerifyAsync(
                        parseResult.RawBodyProtectedHeader!.AsReadOnlyMemory(),
                        signer.RawProtectedHeader.AsReadOnlyMemory(),
                        resolvedPayload,
                        signer.Signature.AsReadOnlyMemory(),
                        buildSigStructure,
                        publicKeys[i],
                        cancellationToken).ConfigureAwait(false);

                    signerResults.Add(isVerified
                        ? CBAdESCoseSignSignerValidationResult.Success(headers, signer.UnsignedHeaders)
                        : CBAdESCoseSignSignerValidationResult.SignatureInvalid(headers, signer.UnsignedHeaders));
                }
            }

            completed = true;

            return CBAdESCoseSignValidationResult.FromSigners(signerResults, bodyLayerViolations);
        }
        finally
        {
            if(!completed)
            {
                //An exception aborted the loop: every signer result already minted above owns a transferred
                //Headers/UnsignedHeaders pair that will never reach a caller now -- dispose them here, or they
                //leak.
                foreach(CBAdESCoseSignSignerValidationResult partial in signerResults)
                {
                    partial.Dispose();
                }
            }

            for(int i = 0; i < parseResult.Signers.Count; ++i)
            {
                CBAdESSignerParseResult signer = parseResult.Signers[i];
                signer.RawProtectedHeader.Dispose();
                signer.Signature.Dispose();
                signer.RawUnsignedHeaders?.Dispose();
                if(!unsignedHeadersTransferred[i])
                {
                    signer.UnsignedHeaders?.Dispose();
                }
            }

            parseResult.RawBodyProtectedHeader?.Dispose();
        }
    }


    /// <summary>
    /// Appends one <see cref="CBAdESCoseSignBodyLayerPlacementViolation"/> for every signer-layer-only
    /// <see cref="CBAdESProtectedHeaders"/> member found present on <paramref name="bodyHeaders"/> — the
    /// <c>COSE_Sign</c> body layer's own decoded protected header.
    /// </summary>
    /// <param name="bodyHeaders">The body layer's decoded signed-header-set aggregate.</param>
    /// <param name="violations">The violation list to append to.</param>
    private static void CollectBodyLayerPlacementViolations(CBAdESProtectedHeaders bodyHeaders, List<CBAdESRuleViolation> violations)
    {
        //Reaching this point at all means alg decoded (DecodeCBAdESProtectedHeaderDelegate's own mandatory-alg
        //contract), so alg itself is, by construction, already misplaced at the body layer (CB-5.1.2-06).
        violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.Algorithm));

        if(bodyHeaders.ContentType is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.ContentType));
        }

        if(bodyHeaders.KeyId is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.KeyId));
        }

        if(bodyHeaders.X5U is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.X5U));
        }

        if(bodyHeaders.X5T is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.X5T));
        }

        if(bodyHeaders.X5Chain is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.X5Chain));
        }

        if(bodyHeaders.CertificateDigests is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.CertificateDigests));
        }

        if(bodyHeaders.CwtClaims is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.CwtClaims));
        }

        if(bodyHeaders.CriticalLabels is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.CriticalLabels));
        }

        if(bodyHeaders.SignerCommitments is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.SignerCommitments));
        }

        if(bodyHeaders.SignatureProductionPlace is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.SignatureProductionPlace));
        }

        if(bodyHeaders.SignerAttributes is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.SignerAttributes));
        }

        if(bodyHeaders.PayloadTimestamps is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.PayloadTimestamps));
        }

        if(bodyHeaders.SignaturePolicyIdentifier is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.SignaturePolicyIdentifier));
        }

        if(bodyHeaders.DetachedObjects is not null)
        {
            violations.Add(new CBAdESCoseSignBodyLayerPlacementViolation(CBAdESCoseSignBodyLayerComponentKind.DetachedObjects));
        }
    }
}


/// <summary>
/// The outcome of <see cref="CBAdESSignatureValidation"/>'s shared structural-plus-cryptographic B-B core
/// (<c>VerifyStructureAndSignatureAsync</c>) — either every carrier a level-aware caller needs to continue into
/// the level pass, or the failure a B-B-only caller returns immediately. Private to
/// <see cref="CBAdESSignatureValidation"/>: this is an internal composition seam between that class's own
/// methods, never a public result shape (contrast with the mint-only <see cref="CBAdESValidationResult"/>).
/// </summary>
/// <remarks>
/// <strong>Ownership on success.</strong> <see cref="Headers"/> and <see cref="UnsignedHeaders"/> transfer to
/// whichever <see cref="CBAdESValidationResult"/> factory the caller ultimately calls (<see cref="Dispose"/> on
/// the <em>failure</em> arm of that later call, or ownership transfer via <see cref="CBAdESValidationResult.Success"/>).
/// <see cref="SignatureValue"/> and <see cref="RawUnsignedHeaders"/> are NOT carried by
/// <see cref="CBAdESValidationResult"/> at all — the caller (either overload pair) disposes them explicitly
/// once it has used (or, on the B-B-only path, immediately not used) them. <see cref="Payload"/> is a
/// borrowed/GC-owned view, safe to hold past every carrier's disposal (matches <see cref="CoseSign1Message.Payload"/>'s
/// own convention).
/// </remarks>
[DebuggerDisplay("CBAdESCoreVerificationOutcome: Succeeded={Succeeded}")]
internal sealed class CBAdESCoreVerificationOutcome
{
    /// <summary>Gets whether the B-B structural-plus-cryptographic core succeeded.</summary>
    public required bool Succeeded { get; init; }

    /// <summary>Gets the failure detail when <see cref="Succeeded"/> is <see langword="false"/>; otherwise <see langword="null"/>.</summary>
    public CBAdESValidationFailure? Failure { get; init; }

    /// <summary>
    /// Gets the decoded signed-header-set aggregate when <see cref="Succeeded"/> is <see langword="true"/>, or
    /// when the failure was reached only after the wire bytes parsed successfully;
    /// <see langword="null"/> only for a failure reached before or during parsing.
    /// </summary>
    public CBAdESProtectedHeaders? Headers { get; init; }

    /// <summary>Gets whether the COSE Payload is detached, valid only when <see cref="Succeeded"/> is <see langword="true"/>.</summary>
    public bool PayloadIsDetached { get; init; }

    /// <summary>Gets the wire payload bytes (borrowed/GC-owned), valid only when <see cref="Succeeded"/> is <see langword="true"/>.</summary>
    public ReadOnlyMemory<byte> Payload { get; init; }

    /// <summary>
    /// Gets the decoded <c>uHeaders</c> set when present and either <see cref="Succeeded"/> is
    /// <see langword="true"/> or the failure was reached only after the wire bytes parsed successfully;
    /// otherwise <see langword="null"/>.
    /// </summary>
    public CBAdESUnsignedHeaders? UnsignedHeaders { get; init; }

    /// <summary>
    /// Gets the COSE signature-value carrier when <see cref="Succeeded"/> is <see langword="true"/>; otherwise
    /// <see langword="null"/>. Owned by whichever caller consumes this outcome; that caller disposes it.
    /// </summary>
    public Signature? SignatureValue { get; init; }

    /// <summary>
    /// Gets the raw captured <c>uHeaders</c> wire bytes when present and <see cref="Succeeded"/> is
    /// <see langword="true"/>; otherwise <see langword="null"/>. Owned by whichever caller consumes this
    /// outcome; that caller disposes it.
    /// </summary>
    public EncodedCBAdESUnsignedHeaders? RawUnsignedHeaders { get; init; }

    /// <summary>
    /// Gets the raw captured body-layer protected-header wire bytes when <see cref="Succeeded"/> is
    /// <see langword="true"/>; otherwise <see langword="null"/>. Owned by whichever caller consumes this
    /// outcome; that caller disposes it. A B-B-only caller has no use for these bytes past signature
    /// verification; a level-aware caller needs them for the <c>arcTst</c> message-imprint input's step 3
    /// (clause 5.3.5.3).
    /// </summary>
    public EncodedCoseProtectedHeader? RawProtectedHeader { get; init; }


    /// <summary>Mints a successful outcome.</summary>
    /// <param name="headers">See <see cref="Headers"/>.</param>
    /// <param name="payloadIsDetached">See <see cref="PayloadIsDetached"/>.</param>
    /// <param name="payload">See <see cref="Payload"/>.</param>
    /// <param name="unsignedHeaders">See <see cref="UnsignedHeaders"/>.</param>
    /// <param name="signatureValue">See <see cref="SignatureValue"/>.</param>
    /// <param name="rawUnsignedHeaders">See <see cref="RawUnsignedHeaders"/>.</param>
    /// <param name="rawProtectedHeader">See <see cref="RawProtectedHeader"/>.</param>
    /// <returns>A successful outcome.</returns>
    public static CBAdESCoreVerificationOutcome Success(
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        ReadOnlyMemory<byte> payload,
        CBAdESUnsignedHeaders? unsignedHeaders,
        Signature signatureValue,
        EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders,
        EncodedCoseProtectedHeader? rawProtectedHeader) =>
        new()
        {
            Succeeded = true,
            Headers = headers,
            PayloadIsDetached = payloadIsDetached,
            Payload = payload,
            UnsignedHeaders = unsignedHeaders,
            SignatureValue = signatureValue,
            RawUnsignedHeaders = rawUnsignedHeaders,
            RawProtectedHeader = rawProtectedHeader
        };


    /// <summary>Mints a failed outcome carrying no decoded content — a failure reached before or during parsing.</summary>
    /// <param name="failure">The failure detail.</param>
    /// <returns>A failed outcome.</returns>
    public static CBAdESCoreVerificationOutcome Failed(CBAdESValidationFailure failure) =>
        new() { Succeeded = false, Failure = failure };


    /// <summary>
    /// Mints a failed outcome that carries the decoded facts known at the point of failure — every failure
    /// reached only after the wire bytes parsed successfully. Ownership
    /// of <paramref name="headers"/>/<paramref name="unsignedHeaders"/> transfers to the returned outcome.
    /// </summary>
    /// <param name="failure">The failure detail.</param>
    /// <param name="headers">The decoded signed-header-set aggregate known at the point of failure.</param>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set known at the point of failure, or <see langword="null"/> when absent.</param>
    /// <returns>A failed outcome carrying the decoded facts.</returns>
    public static CBAdESCoreVerificationOutcome Failed(
        CBAdESValidationFailure failure, CBAdESProtectedHeaders headers, CBAdESUnsignedHeaders? unsignedHeaders) =>
        new() { Succeeded = false, Failure = failure, Headers = headers, UnsignedHeaders = unsignedHeaders };
}
