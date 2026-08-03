using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The strict CB-AdES signature validation orchestrator: parses wire bytes, checks every B-B conformance
/// rule, resolves the verification payload per the signature's attachment/mechanism, verifies the COSE
/// signature value over it, and — on the level-aware overloads (wavecb S4) — additionally checks every
/// B-T/B-LT/B-LTA level-scoped rule and every electronic time-stamp token's message-imprint binding, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope boundary (S3 coordinator ruling (6), wavecb-contract.md stage list).</strong> This is
/// structural conformance plus cryptographic verification with caller-provided key material. Certificate-path
/// trust and revocation are never resolved, chained, or validated by this class, at any level — it does not
/// even require a signing certificate. <c>kid</c> (clause 5.1.4, CB-5.1.4-04) is a non-authoritative hint and
/// drives no key selection here; the caller supplies the verification key by whatever means it trusts, exactly
/// like <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>
/// does for plain COSE_Sign1.
/// </para>
/// <para>
/// <strong>Level-aware surface (wavecb S4 coordinator ruling (5)).</strong> The four <c>ValidateAsync</c>
/// overloads that take no <see cref="CBAdESBaselineLevel"/> are the original S3 B-B-only surface, UNCHANGED —
/// they never evaluate a single level-scoped rule (<see cref="CBAdESLevelRules"/>) or open a single time-stamp
/// token, regardless of what <c>uHeaders</c> actually carries, exactly as shipped in S3. The two overloads that
/// DO take a <see cref="CBAdESBaselineLevel"/> run the identical B-B structural-plus-cryptographic core first,
/// then additionally: (a) evaluate <see cref="CBAdESLevelRules.Check"/> and
/// <see cref="CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/> — the shared, one-implementation
/// level-rule surface, WIRED here, never re-implemented; (b) open and CMS-verify every <c>sigTst</c>/<c>adoTst</c>/
/// <c>sigRTst</c>/<c>rfsTst</c>/<c>arcTst</c> electronic time-stamp token
/// (<see cref="TimestampTokenInfo.ReadFromTokenAsync"/>) and check that its message imprint binds the data it
/// is claimed to time-stamp (<see cref="TimestampTokenInfo.VerifyMessageImprintAsync"/>) — EXCEPT <c>arcTst</c>,
/// whose message-imprint algorithm (clause 5.3.5.3's 12-step concatenation) is deferred to wavecb S5 once
/// <c>arcTst</c> generation lands (only token openability/CMS-verifiability is checked for it here, matching
/// <see cref="CBAdESLevelRules"/>'s identical CB-A.1.1-30 deferral); (c) fold the OR of every opened token's
/// <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/> into the CB-6.3-26/h validation-data-for-time-stamps
/// service check. Certificate-path neutrality is preserved identically at every level: opening a token only
/// checks ITS OWN CMS signature (never a chain to a trust anchor for the Time-Stamping Authority), and
/// <see cref="CBAdESLevelRuleContext.SigningCertificateDigests"/> (CB-A.1.1-02) is derived only
/// from facts the signature's OWN <c>x5t</c>/<c>x5ts</c> headers already assert, never from a resolved or
/// chained certificate. Mapping any of this onto an
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1</see> Indication/SubIndication conclusion remains wavecb S7's job, not this class's — see
/// <see cref="CBAdESValidationResult"/>'s own remarks.
/// </para>
/// <para>
/// <strong>Never throws on malformed or non-conformant input (R-5).</strong> Every failure mode this class can
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
/// <strong>Signature verification uses the wire bytes captured at parse (wavecb S3 FX-A).</strong>
/// <see cref="CBAdESSign1ParseResult"/> carries <see cref="CBAdESSign1ParseResult.RawProtectedHeader"/> — the
/// exact, undecoded <c>body_protected</c> byte string
/// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.4">RFC 9052 §4.4</see>) the parse step read off
/// the wire — and this class builds the Sig_structure from those bytes directly, exactly like
/// <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>/
/// <see cref="Verifiable.Cbor.CoseVerification"/> do for plain COSE_Sign1. The identical rationale extends to
/// <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/> (wavecb S4 coordinator ruling (3)): the <c>sigRTst</c>/
/// <c>rfsTst</c> message-imprint builders consume THOSE raw bytes, never a re-encoding of the decoded
/// <see cref="CBAdESUnsignedHeaders"/> model, for the same read/write-asymmetry reason.
/// </para>
/// <para>
/// <strong>One rule implementation (S3 coordinator ruling (2), extended level-scoped by S4 coordinator ruling
/// (5)).</strong> This class calls <see cref="CBAdESHeaderRules.Check"/> and <see cref="CBAdESLevelRules.Check"/>/
/// <see cref="CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/> — the exact same rule surfaces the
/// creation path's throw postures call — in collect posture. This class never re-implements or duplicates a
/// single one of those rules. Likewise, the <c>ObjectIdByURI</c> reconstruction algorithm (CB-5.2.8.2.2-05) is
/// never duplicated here: it composes <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/>
/// directly (reuse over reinvention, R-2) — the same method the CB-5.2.8.2.3-07 full-reconstruction path, the
/// <c>adoTst</c> message-imprint-input resolution, and the S5 <c>arcTst</c> work all share.
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
/// delegate's own remarks document (wavecb S3 FX-J): a routine retrieval failure signalled by throwing
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
    /// own two-tier structure. B-B ONLY (wavecb S3) — see the type remarks for the level-aware overloads below.
    /// </summary>
    /// <param name="encodedCoseSign1">The candidate CB-AdES wire bytes.</param>
    /// <param name="parse">The fail-closed CBOR parse seam (implemented in <c>Verifiable.Cbor</c>, stage m4).</param>
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
    /// Validates a CB-AdES <c>COSE_Sign1</c> using an explicit verification delegate. B-B ONLY (wavecb S3) —
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
            return CBAdESValidationResult.Failed(outcome.Failure!);
        }

        //A B-B-only caller never consumes the level-aware carriers (the raw COSE signature-value bytes and the
        //raw uHeaders bytes) VerifyStructureAndSignatureAsync keeps alive for the level pass, so they are
        //disposed immediately here. This fixes a real leak the S3 shape never accounted for: RawUnsignedHeaders
        //(wavecb S4 coordinator ruling (3)) postdates S3, and the original success path here never disposed it
        //(only Signature/RawProtectedHeader were surgically disposed) -- CBAdESSign1ParseResult.Dispose()
        //covers it on every FAILURE path already, but the success path never called that blanket Dispose. The
        //fix has zero effect on the CBAdESValidationResult returned below.
        outcome.SignatureValue!.Dispose();
        outcome.RawUnsignedHeaders?.Dispose();

        return CBAdESValidationResult.Success(outcome.Headers!, outcome.PayloadIsDetached, outcome.UnsignedHeaders);
    }


    /// <summary>
    /// Validates a CB-AdES <c>COSE_Sign1</c> at a specific <see cref="CBAdESBaselineLevel"/> using a
    /// registry-resolved verification function (wavecb S4 coordinator ruling (5)). Resolves
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
    /// <param name="pool">Memory pool for the transient parse, dereference, and token-verification buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result; see the type remarks for the never-throws-on-untrusted-input contract.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="publicKey"/>, <paramref name="buildPayloadTimestampImprintInput"/>,
    /// <paramref name="buildSignatureAndReferencesTimestampImprintInput"/>,
    /// <paramref name="buildReferencesOnlyTimestampImprintInput"/>, or <paramref name="pool"/> is <see langword="null"/>.
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
        CBAdESBaselineLevel level,
        BuildPayloadTimestampMessageImprintInputDelegate buildPayloadTimestampImprintInput,
        TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate buildSignatureAndReferencesTimestampImprintInput,
        TryBuildReferencesOnlyTimestampMessageImprintInputDelegate buildReferencesOnlyTimestampImprintInput,
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
            level,
            buildPayloadTimestampImprintInput,
            buildSignatureAndReferencesTimestampImprintInput,
            buildReferencesOnlyTimestampImprintInput,
            pool,
            cancellationToken);
    }


    /// <summary>
    /// Validates a CB-AdES <c>COSE_Sign1</c> at a specific <see cref="CBAdESBaselineLevel"/> using an explicit
    /// verification delegate (wavecb S4 coordinator ruling (5)) — the level-aware core implementation. See the
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
    /// <param name="pool">Memory pool for the transient parse, dereference, and token-verification buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="parse"/>, <paramref name="buildSigStructure"/>, <paramref name="publicKey"/>,
    /// <paramref name="verificationDelegate"/>, <paramref name="buildPayloadTimestampImprintInput"/>,
    /// <paramref name="buildSignatureAndReferencesTimestampImprintInput"/>,
    /// <paramref name="buildReferencesOnlyTimestampImprintInput"/>, or <paramref name="pool"/> is <see langword="null"/>.
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
        CBAdESBaselineLevel level,
        BuildPayloadTimestampMessageImprintInputDelegate buildPayloadTimestampImprintInput,
        TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate buildSignatureAndReferencesTimestampImprintInput,
        TryBuildReferencesOnlyTimestampMessageImprintInputDelegate buildReferencesOnlyTimestampImprintInput,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(buildPayloadTimestampImprintInput);
        ArgumentNullException.ThrowIfNull(buildSignatureAndReferencesTimestampImprintInput);
        ArgumentNullException.ThrowIfNull(buildReferencesOnlyTimestampImprintInput);
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
            return CBAdESValidationResult.Failed(outcome.Failure!);
        }

        CBAdESProtectedHeaders headers = outcome.Headers!;
        CBAdESUnsignedHeaders? unsignedHeaders = outcome.UnsignedHeaders;
        Signature signatureValue = outcome.SignatureValue!;
        EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders = outcome.RawUnsignedHeaders;

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
                                    violations,
                                    pool,
                                    cancellationToken).ConfigureAwait(false);
                                break;

                            case CBAdESUnsignedHeaderElementArchiveTimestamp arcTst:
                                //Message-imprint binding is deferred to wavecb S5 -- only openability/CMS
                                //verification runs here (expectedImprintInput: null); see the type remarks.
                                anyEmbeddedValidationMaterial |= await VerifyTimestampContainerAsync(
                                    arcTst.ArchiveTimestamp.TimestampContainer,
                                    CBAdESTimestampTokenBindingKind.ArchiveTimestamp,
                                    expectedImprintInput: null,
                                    violations,
                                    pool,
                                    cancellationToken).ConfigureAwait(false);
                                break;

                            case CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp sigRTst:
                                //D15 (wavecb-contract.md R-6): this specific sigRTst instance's own array
                                //position (i) is the exclusive validation-time prefix bound -- only the uHeaders
                                //elements that precede IT contribute, never a later sigTst instance appended
                                //after it (Table 14 note 7's repeated-sigTst case).
                                anyEmbeddedValidationMaterial |= await VerifySignatureAndReferencesTimestampAsync(
                                    sigRTst.SignatureAndReferencesTimestamp.TimestampContainer,
                                    signatureValueBytes,
                                    rawUnsignedHeaders,
                                    i,
                                    buildSignatureAndReferencesTimestampImprintInput,
                                    violations,
                                    pool,
                                    cancellationToken).ConfigureAwait(false);
                                break;

                            case CBAdESUnsignedHeaderElementReferencesTimestamp rfsTst:
                                //D15: same validation-time prefix-bound ruling as sigRTst above, over this
                                //specific rfsTst instance's own array position.
                                anyEmbeddedValidationMaterial |= await VerifyReferencesTimestampAsync(
                                    rfsTst.ReferencesTimestamp.TimestampContainer,
                                    rawUnsignedHeaders,
                                    i,
                                    buildReferencesOnlyTimestampImprintInput,
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
                        violations,
                        pool,
                        cancellationToken).ConfigureAwait(false);
                }

                var levelContext = new CBAdESLevelRuleContext
                {
                    Level = level,
                    UnsignedHeaders = unsignedHeaders,
                    SigningCertificateDigests = CollectSigningCertificateDigests(headers),
                    AnyTimestampTokenCarriesEmbeddedValidationMaterial = anyEmbeddedValidationMaterial
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
                    headers.Dispose();
                    unsignedHeaders?.Dispose();
                    return CBAdESValidationResult.Failed(new CBAdESRuleViolationsFailure(violations));
                }

                return CBAdESValidationResult.Success(headers, outcome.PayloadIsDetached, unsignedHeaders);
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
            signatureValue.Dispose();
            rawUnsignedHeaders?.Dispose();
        }
    }


    /// <summary>
    /// The shared structural-plus-cryptographic B-B core (wavecb S3 steps a-e), extracted so both the B-B-only
    /// overloads and the level-aware overloads run the IDENTICAL parse/rule/payload-resolution/signature-
    /// verification pipeline (S3 behavior preserved EXACTLY, wavecb S4 coordinator ruling (5)) — a level-aware
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
            "carriers verbatim -- the wire body_protected bytes captured at parse (wavecb S3 FX-A) -- rather " +
            "than allocating new disposables of its own; parseResult remains the sole owner of RawProtectedHeader " +
            "throughout (disposed explicitly on success below, and by the wavecb S3 FX-D catch on any exception), " +
            "while Signature's ownership transfers onward through the returned CBAdESCoreVerificationOutcome, " +
            "whose own caller (either ValidateAsync overload pair, above) disposes it explicitly. Roslyn tracks " +
            "the locally-constructed CoseSign1Message itself, not the fact that its constituent IDisposable " +
            "members are owned and disposed one level up.")]
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

        //Step b: the shared B-B rule surface, collect posture (S3 coordinator ruling (2)) — a single call,
        //never re-implemented here, and never re-checking the unprotected-map single-member rule the parse
        //seam already fail-closed on (S3 coordinator ruling (5)).
        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESHeaderRules.Check(headers, payloadIsDetached, unsignedHeaders);
        if(violations.Count > 0)
        {
            parseResult.Dispose();
            return CBAdESCoreVerificationOutcome.Failed(new CBAdESRuleViolationsFailure(violations));
        }

        //Steps c-e are wrapped in a try/catch (wavecb S3 FX-D): every explicit return below already disposes
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
                    parseResult,
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
                    parseResult.Dispose();
                    return CBAdESCoreVerificationOutcome.Failed(resolutionFailure!);
                }

                //Step d: Cose.VerifyAsync over the resolved payload. verificationMessage shares parseResult's OWN
                //RawProtectedHeader/Signature carriers — the wire body_protected bytes captured verbatim at parse
                //(wavecb S3 FX-A), never a re-encoding of headers — and neither is disposed by this "using" block;
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
                    parseResult.Dispose();
                    return CBAdESCoreVerificationOutcome.Failed(new CBAdESSignatureInvalidFailure());
                }

                //Step e: success — ownership of headers/unsignedHeaders/Signature/RawUnsignedHeaders transfers to
                //the outcome; RawProtectedHeader (needed by neither a B-B-only nor a level-aware caller) is
                //disposed here, exactly as the S3 shape always disposed it.
                parseResult.RawProtectedHeader!.Dispose();

                return CBAdESCoreVerificationOutcome.Success(
                    headers,
                    payloadIsDetached,
                    parseResult.Payload,
                    unsignedHeaders,
                    parseResult.Signature,
                    parseResult.RawUnsignedHeaders);
            }
        }
        catch
        {
            parseResult.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Resolves the verification payload per clause 5.2.8's four cases (see the type remarks) and, for the
    /// <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/> case, independently re-verifies every
    /// <c>hashV</c> entry.
    /// </summary>
    /// <param name="parseResult">The successful parse result (for its wire payload and attachment state).</param>
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
    private static async ValueTask<(bool Resolved, PooledMemory? Rented, ReadOnlyMemory<byte> Payload, CBAdESValidationFailure? Failure)> ResolveVerificationPayloadAsync(
        CBAdESSign1ParseResult parseResult,
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
            return (true, null, parseResult.Payload, null);
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
            //wavecb S3 FX-J: this is the delegate's own documented routine-failure signal (see
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
                //verified, so each is treated as a mismatch rather than silently skipped (fail closed, R-5).
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
    /// Resolves a <see cref="CBAdESDigestAlgorithmIdentifier"/> to the <see cref="Tag"/> and output byte
    /// length <see cref="CryptographicKeyEvents.ComputeDigestAsync(System.ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, CancellationToken)"/>
    /// needs, recognizing the SHA-256/384/512 identifiers this library's own registries assign — both the
    /// <c>int</c> arm (<see cref="WellKnownCoseAlgorithms"/>) and the <c>tstr</c> arm
    /// (<see cref="WellKnownHashAlgorithms"/>'s multi-spelling recognizers).
    /// </summary>
    /// <param name="identifier">The digest-algorithm identifier from <c>hashM</c>.</param>
    /// <returns>The resolved tag and output length, or <see langword="null"/> when unrecognized.</returns>
    private static (Tag Tag, int OutputByteLength)? TryResolveDigestAlgorithm(CBAdESDigestAlgorithmIdentifier identifier) => identifier switch
    {
        CBAdESDigestAlgorithmIntegerIdentifier integer when WellKnownCoseAlgorithms.IsSha256(integer.Value) =>
            (CryptoTags.Sha256Digest, WellKnownHashAlgorithms.Sha256SizeBytes),
        CBAdESDigestAlgorithmIntegerIdentifier integer when WellKnownCoseAlgorithms.IsSha384(integer.Value) =>
            (CryptoTags.Sha384Digest, WellKnownHashAlgorithms.Sha384SizeBytes),
        CBAdESDigestAlgorithmIntegerIdentifier integer when WellKnownCoseAlgorithms.IsSha512(integer.Value) =>
            (CryptoTags.Sha512Digest, WellKnownHashAlgorithms.Sha512SizeBytes),
        CBAdESDigestAlgorithmTextIdentifier text when WellKnownHashAlgorithms.IsSha256(text.Value) =>
            (CryptoTags.Sha256Digest, WellKnownHashAlgorithms.Sha256SizeBytes),
        CBAdESDigestAlgorithmTextIdentifier text when WellKnownHashAlgorithms.IsSha384(text.Value) =>
            (CryptoTags.Sha384Digest, WellKnownHashAlgorithms.Sha384SizeBytes),
        CBAdESDigestAlgorithmTextIdentifier text when WellKnownHashAlgorithms.IsSha512(text.Value) =>
            (CryptoTags.Sha512Digest, WellKnownHashAlgorithms.Sha512SizeBytes),
        _ => null
    };


    /// <summary>
    /// Projects <paramref name="detachedObjects"/>'s entries onto their bare reference strings, in wire order —
    /// shared by <see cref="ResolveVerificationPayloadAsync"/>'s <c>ObjectIdByURI</c> arm and
    /// <see cref="ResolvePayloadTimestampImprintSourceAsync"/>'s identical dereference-and-concatenate need
    /// (reuse over reinvention, R-2).
    /// </summary>
    /// <param name="detachedObjects">The <c>sigD</c> component to project.</param>
    /// <returns>The <c>pars</c> reference strings, in order.</returns>
    private static IReadOnlyList<string> BuildReferenceList(CBAdESDetachedObjects detachedObjects)
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
    private static IReadOnlyList<CBAdESDetachedObjectReferenceInput> BuildReferenceInputs(CBAdESDetachedObjects detachedObjects)
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
    private static IReadOnlyList<DigestValue>? CollectSigningCertificateDigests(CBAdESProtectedHeaders headers)
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
    /// imprint does not match <paramref name="expectedImprintInput"/> (when supplied).
    /// </summary>
    /// <param name="container">The <c>tstContainer</c> to verify.</param>
    /// <param name="kind">Which token kind <paramref name="container"/> belongs to.</param>
    /// <param name="expectedImprintInput">
    /// The expected message-imprint input, or <see langword="null"/> to skip imprint verification entirely
    /// (the <c>arcTst</c> deferral to wavecb S5 — see the type remarks) and only check that every token opens
    /// and CMS-verifies.
    /// </param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the token and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see langword="true"/> when at least one successfully-opened token carries
    /// <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.
    /// </returns>
    private static async ValueTask<bool> VerifyTimestampContainerAsync(
        CBAdESTimestampContainer container,
        CBAdESTimestampTokenBindingKind kind,
        ReadOnlyMemory<byte>? expectedImprintInput,
        List<CBAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        bool anyEmbedded = false;
        for(int i = 0; i < container.TstTokens.Count; ++i)
        {
            anyEmbedded |= await VerifyOneTimestampTokenAsync(
                container.TstTokens[i], kind, expectedImprintInput, violations, pool, cancellationToken).ConfigureAwait(false);
        }

        return anyEmbedded;
    }


    /// <summary>
    /// Opens and CMS-verifies one electronic time-stamp token via the single CMS choke point
    /// (<see cref="TimestampTokenInfo.ReadFromTokenAsync"/>) and, when <paramref name="expectedImprintInput"/>
    /// is supplied, checks that its message imprint binds it (<see cref="TimestampTokenInfo.VerifyMessageImprintAsync"/>).
    /// </summary>
    /// <param name="token">The token to verify.</param>
    /// <param name="kind">Which token kind <paramref name="token"/> belongs to.</param>
    /// <param name="expectedImprintInput">The expected message-imprint input, or <see langword="null"/> to skip imprint verification.</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the token and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when the token opened and carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
    private static async ValueTask<bool> VerifyOneTimestampTokenAsync(
        CBAdESTimestampToken token,
        CBAdESTimestampTokenBindingKind kind,
        ReadOnlyMemory<byte>? expectedImprintInput,
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
                $"The token could not be read (status: {tokenInfo.Status})."));

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
                    "The token's message imprint does not match the expected input."));
            }
        }

        return tokenInfo.HasEmbeddedCertificates;
    }


    /// <summary>
    /// Copies <paramref name="tokenValue"/> into pool-rented memory and wraps it as a
    /// <see cref="PkiCertificateMemory"/> tagged <see cref="PkiCertificateTags.TimestampToken"/>, mirroring
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// this library's</see> established copy-into-pooled-carrier idiom for a token this class does not itself
    /// own the backing memory of (<see cref="CBAdESTimestampToken.Val"/> is a borrowed view).
    /// </summary>
    /// <param name="tokenValue">The token's encoded octets (<see cref="CBAdESTimestampToken.Val"/>).</param>
    /// <param name="pool">The memory pool to rent from.</param>
    /// <returns>The owned carrier. The caller disposes it.</returns>
    private static PkiCertificateMemory RentTimestampTokenMemory(ReadOnlyMemory<byte> tokenValue, BaseMemoryPool pool)
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
    /// exclusive validation-time prefix bound (D15, wavecb-contract.md R-6): only the elements strictly before
    /// this position contribute to the expected imprint, so a later sibling <c>sigTst</c> instance appended
    /// after this <c>sigRTst</c> (legal per Table 14 note 7) never changes what this specific instance is
    /// checked against.
    /// </param>
    /// <param name="buildImprintInput">The Annex A.1.2.1.2 message-imprint-input builder seam.</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the imprint-input, token, and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when at least one token carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
    private static async ValueTask<bool> VerifySignatureAndReferencesTimestampAsync(
        CBAdESTimestampContainer container,
        ReadOnlyMemory<byte> signatureValueBytes,
        EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders,
        int elementIndex,
        TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate buildImprintInput,
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
                "message-imprint input from (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.2)."));

            return false;
        }

        bool built = buildImprintInput(signatureValueBytes, rawUnsignedHeaders.AsReadOnlyMemory(), elementIndex, pool, out PooledMemory? input);
        if(!built || input is null)
        {
            violations.Add(new CBAdESTimestampTokenBindingViolation(
                CBAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp,
                CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                "The sigRTst message-imprint input could not be built from the captured uHeaders wire bytes " +
                "(ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.2)."));

            return false;
        }

        using(input)
        {
            return await VerifyTimestampContainerAsync(
                container,
                CBAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp,
                input.AsReadOnlyMemory(),
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
    /// validation-time prefix bound (D15, wavecb-contract.md R-6) — see
    /// <see cref="VerifySignatureAndReferencesTimestampAsync"/>'s identical parameter remarks.
    /// </param>
    /// <param name="buildImprintInput">The Annex A.1.2.2.2 message-imprint-input builder seam.</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the imprint-input, token, and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when at least one token carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
    private static async ValueTask<bool> VerifyReferencesTimestampAsync(
        CBAdESTimestampContainer container,
        EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders,
        int elementIndex,
        TryBuildReferencesOnlyTimestampMessageImprintInputDelegate buildImprintInput,
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
                "message-imprint input from (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.2)."));

            return false;
        }

        bool built = buildImprintInput(rawUnsignedHeaders.AsReadOnlyMemory(), elementIndex, pool, out PooledMemory? input);
        if(!built || input is null)
        {
            violations.Add(new CBAdESTimestampTokenBindingViolation(
                CBAdESTimestampTokenBindingKind.ReferencesTimestamp,
                CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                "The rfsTst message-imprint input could not be built from the captured uHeaders wire bytes " +
                "(ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.2)."));

            return false;
        }

        using(input)
        {
            return await VerifyTimestampContainerAsync(
                container,
                CBAdESTimestampTokenBindingKind.ReferencesTimestamp,
                input.AsReadOnlyMemory(),
                violations,
                pool,
                cancellationToken).ConfigureAwait(false);
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
        List<CBAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        (bool resolved, PooledMemory? rentedSource, CBAdESPayloadTimestampImprintSource? source, string? failureReason) =
            await ResolvePayloadTimestampImprintSourceAsync(
                headers, payloadIsDetached, payload, dereference, dereferenceContext,
                externalDetachedPayload, unknownMechanismHandler, pool, cancellationToken).ConfigureAwait(false);

        using(rentedSource)
        {
            if(!resolved || source is null)
            {
                violations.Add(new CBAdESTimestampTokenBindingViolation(
                    CBAdESTimestampTokenBindingKind.PayloadTimestamp,
                    CBAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                    failureReason ?? "The adoTst message-imprint input (the COSE Payload) could not be resolved."));

                return false;
            }

            using PooledMemory imprintInput = buildImprintInput(source, pool);

            return await VerifyTimestampContainerAsync(
                headers.PayloadTimestamps!.TimestampContainer,
                CBAdESTimestampTokenBindingKind.PayloadTimestamp,
                imprintInput.AsReadOnlyMemory(),
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
    /// <param name="pool">Memory pool for the dereferenced byte carriers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A tuple: whether resolution succeeded; a <see cref="PooledMemory"/> the caller must dispose when the
    /// <c>sigD</c> arm rented one (<see langword="null"/> for the attached/detached arms, which rent nothing);
    /// the resolved source (valid only when resolution succeeded); a human-readable failure reason (valid only
    /// when resolution failed).
    /// </returns>
    private static async ValueTask<(bool Resolved, PooledMemory? Rented, CBAdESPayloadTimestampImprintSource? Source, string? FailureReason)> ResolvePayloadTimestampImprintSourceAsync(
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        ReadOnlyMemory<byte> payload,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(!payloadIsDetached)
        {
            return (true, null, new CBAdESAttachedPayloadTimestampImprintSource(payload), null);
        }

        if(headers.DetachedObjects is null)
        {
            return externalDetachedPayload.HasValue
                ? (true, null, new CBAdESDetachedPayloadTimestampImprintSource(externalDetachedPayload.Value), null)
                : (false, null, null, "The COSE Payload is detached and sigD is absent, but no out-of-band " +
                    "detached payload was supplied (ETSI TS 119 152-1 V1.1.1, clause 5.2.6).");
        }

        CBAdESDetachedObjects sigD = headers.DetachedObjects;

        if(dereferenceContext is null)
        {
            return (false, null, null, $"adoTst requires the COSE Payload, and sigD selects " +
                $"'{sigD.MechanismIdentifier}', but no dereference context was supplied (ETSI TS 119 152-1 " +
                "V1.1.1, clause 5.2.6, clause 5.2.8.2.1).");
        }

        if(CBAdESDetachedMechanisms.IsObjectIdByURI(sigD.MechanismIdentifier)
            || CBAdESDetachedMechanisms.IsObjectIdByURIHash(sigD.MechanismIdentifier))
        {
            //Both built-in mechanisms dereference-and-concatenate for the adoTst imprint (CB-5.2.6-06) — unlike
            //signature-verification payload resolution, ObjectIdByURIHash gets no empty-stream shortcut here.
            if(dereference is null)
            {
                return (false, null, null, "adoTst requires the COSE Payload via sigD, but no dereference " +
                    "delegate was supplied (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.1).");
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
                return (false, null, null, $"Failed to dereference '{reference}' while resolving the adoTst " +
                    $"message-imprint input: {ex.Message}");
            }
        }

        if(unknownMechanismHandler is null)
        {
            return (false, null, null, $"sigD.mId '{sigD.MechanismIdentifier}' is not one of the two defined " +
                "mechanisms, and no unknown-mechanism handler was supplied (ETSI TS 119 152-1 V1.1.1, clause " +
                "5.2.6, CB-5.2.6-07).");
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
                $"failed while resolving the adoTst message-imprint input: {ex.Message}");
        }
    }


    /// <summary>
    /// Determines whether <paramref name="exception"/> represents malformed or non-conformant untrusted wire
    /// bytes that <see cref="VerifyStructureAndSignatureAsync"/> catches to fail closed (R-5), mirroring
    /// <see cref="Verifiable.Cbor.CoseVerification"/>'s own classifier.
    /// </summary>
    /// <remarks>
    /// <see cref="ParseCBAdESSign1Delegate"/>'s own documented contract already promises never to throw for
    /// malformed input (its <see cref="CBAdESSign1ParseResult.IsSuccess"/> <see langword="false"/> arm covers
    /// that case), so this catch is belt-and-suspenders defense against a non-conformant implementation of
    /// that delegate, not a documented necessity. <c>System.Formats.Cbor.CborContentException</c> — the type
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
internal sealed record CBAdESCoreVerificationOutcome
{
    /// <summary>Gets whether the B-B structural-plus-cryptographic core succeeded.</summary>
    public required bool Succeeded { get; init; }

    /// <summary>Gets the failure detail when <see cref="Succeeded"/> is <see langword="false"/>; otherwise <see langword="null"/>.</summary>
    public CBAdESValidationFailure? Failure { get; init; }

    /// <summary>Gets the decoded signed-header-set aggregate when <see cref="Succeeded"/> is <see langword="true"/>; otherwise <see langword="null"/>.</summary>
    public CBAdESProtectedHeaders? Headers { get; init; }

    /// <summary>Gets whether the COSE Payload is detached, valid only when <see cref="Succeeded"/> is <see langword="true"/>.</summary>
    public bool PayloadIsDetached { get; init; }

    /// <summary>Gets the wire payload bytes (borrowed/GC-owned), valid only when <see cref="Succeeded"/> is <see langword="true"/>.</summary>
    public ReadOnlyMemory<byte> Payload { get; init; }

    /// <summary>Gets the decoded <c>uHeaders</c> set when present and <see cref="Succeeded"/> is <see langword="true"/>; otherwise <see langword="null"/>.</summary>
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


    /// <summary>Mints a successful outcome.</summary>
    /// <param name="headers">See <see cref="Headers"/>.</param>
    /// <param name="payloadIsDetached">See <see cref="PayloadIsDetached"/>.</param>
    /// <param name="payload">See <see cref="Payload"/>.</param>
    /// <param name="unsignedHeaders">See <see cref="UnsignedHeaders"/>.</param>
    /// <param name="signatureValue">See <see cref="SignatureValue"/>.</param>
    /// <param name="rawUnsignedHeaders">See <see cref="RawUnsignedHeaders"/>.</param>
    /// <returns>A successful outcome.</returns>
    public static CBAdESCoreVerificationOutcome Success(
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        ReadOnlyMemory<byte> payload,
        CBAdESUnsignedHeaders? unsignedHeaders,
        Signature signatureValue,
        EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders) =>
        new()
        {
            Succeeded = true,
            Headers = headers,
            PayloadIsDetached = payloadIsDetached,
            Payload = payload,
            UnsignedHeaders = unsignedHeaders,
            SignatureValue = signatureValue,
            RawUnsignedHeaders = rawUnsignedHeaders
        };


    /// <summary>Mints a failed outcome carrying no decoded content.</summary>
    /// <param name="failure">The failure detail.</param>
    /// <returns>A failed outcome.</returns>
    public static CBAdESCoreVerificationOutcome Failed(CBAdESValidationFailure failure) =>
        new() { Succeeded = false, Failure = failure };
}
