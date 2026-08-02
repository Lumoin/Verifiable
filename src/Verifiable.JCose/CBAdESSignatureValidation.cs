using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The strict B-B (baseline) CB-AdES signature validation orchestrator: parses wire bytes, checks every B-B
/// conformance rule, resolves the verification payload per the signature's attachment/mechanism, and verifies
/// the COSE signature value over it, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope boundary (S3 coordinator ruling (6), wavecb-contract.md stage list).</strong> This is
/// structural conformance plus cryptographic verification with caller-provided key material. Certificate-path
/// trust, revocation, and time-stamp validation are later stages (S4/S7): this class does not resolve, chain,
/// or validate the signing certificate at all — it does not even require one. <c>kid</c> (clause 5.1.4,
/// CB-5.1.4-04) is a non-authoritative hint and drives no key selection here; the caller supplies the
/// verification key by whatever means it trusts, exactly like <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>
/// does for plain COSE_Sign1.
/// </para>
/// <para>
/// <strong>Never throws on malformed or non-conformant input (R-5).</strong> Every failure mode this class can
/// reach from untrusted wire bytes — a parse failure, a B-B rule violation, an unresolvable detached object, a
/// digest mismatch, a bad signature — is reported as a <see cref="CBAdESValidationResult"/> with
/// <see cref="CBAdESValidationResult.IsValid"/> <see langword="false"/>, never a thrown exception.
/// <see cref="ArgumentNullException"/> for a missing REQUIRED delegate/key/pool parameter is a caller-contract
/// violation, not a conformance judgment, and remains a thrown exception, matching every other seam in this
/// library. <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/>'s own
/// creation-side contract THROWS <see cref="CBAdESDetachedObjectDereferenceException"/> on a routine
/// dereference failure (trusted-caller-input semantics there); this class is the one place that exception
/// crosses back into fail-closed territory, catching it and reporting
/// <see cref="CBAdESDetachedObjectUnresolvableFailure"/> instead, per this task's explicit instruction
/// ("delegate failure -&gt; DetachedObjectUnresolvable").
/// </para>
/// <para>
/// <strong>Signature verification uses the wire bytes captured at parse (wavecb S3 FX-A).</strong>
/// <see cref="CBAdESSign1ParseResult"/> carries <see cref="CBAdESSign1ParseResult.RawProtectedHeader"/> — the
/// exact, undecoded <c>body_protected</c> byte string
/// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.4">RFC 9052 §4.4</see>) the parse step read off
/// the wire — and this class builds the Sig_structure from those bytes directly, exactly like
/// <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>/
/// <see cref="Verifiable.Cbor.CoseVerification"/> do for plain COSE_Sign1. An earlier revision of this class
/// instead called back into a protected-header ENCODER to reconstruct <c>body_protected</c> from the decoded
/// <see cref="CBAdESProtectedHeaders"/> aggregate, reasoning that CB-4.7-02's canonical-encoding mandate makes
/// that round trip lossless. That reasoning does not hold: canonical encoding governs a chosen CDDL union arm's
/// SHORTEST form, never the choice BETWEEN union arms — RFC 8392 §2's <c>NumericDate</c> (<c>int / float</c>,
/// the CWT-Claims <c>iat</c> value this document's protected header always carries) has no canonical arm to
/// prefer, so a re-encoder cannot recover which arm the wire bytes actually used, and a genuinely conformant
/// float-form <c>iat</c> signature would fail re-verification even though nothing about it is non-conformant.
/// Carrying the raw wire bytes instead of re-encoding eliminates this whole class of read/write asymmetry.
/// </para>
/// <para>
/// <strong>One rule implementation (S3 coordinator ruling (2)).</strong> This class calls
/// <see cref="CBAdESHeaderRules.Check"/> — the exact same rule surface the creation path's
/// <see cref="CBAdESHeaderRules.EnsureConformant"/> calls in throw posture — in collect posture. This class
/// never re-implements or duplicates a single one of those rules, including the unprotected-map
/// single-member rule (CB-4.4-01), which is <see cref="ParseCBAdESSign1Delegate"/>'s own fail-closed job (S3
/// coordinator ruling (5)) and therefore never re-checked here. Likewise, the <c>ObjectIdByURI</c>
/// reconstruction algorithm (CB-5.2.8.2.2-05) is never duplicated here: it composes
/// <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/> directly (reuse over
/// reinvention, R-2) — the same method the CB-5.2.8.2.3-07 full-reconstruction path and the S4 timestamp work
/// share.
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
    /// own two-tier structure.
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
    /// Validates a CB-AdES <c>COSE_Sign1</c> using an explicit verification delegate. The core implementation —
    /// see the type remarks for the full algorithm and the never-throws-on-untrusted-input contract.
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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "verificationMessage (below) shares parseResult's own RawProtectedHeader/Signature " +
            "carriers verbatim -- the wire body_protected bytes captured at parse (wavecb S3 FX-A) -- rather " +
            "than allocating new disposables of its own; parseResult remains the sole owner of both throughout, " +
            "disposed explicitly on every success/failure return below and by the wavecb S3 FX-D catch on any " +
            "exception. Roslyn tracks the locally-constructed CoseSign1Message itself, not the fact that its " +
            "constituent IDisposable members are owned and disposed one level up through parseResult.")]
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
            return CBAdESValidationResult.Failed(new CBAdESMalformedEncodingFailure());
        }

        if(!parseResult.IsSuccess || parseResult.ProtectedHeaders is null || parseResult.Signature is null)
        {
            parseResult.Dispose();
            return CBAdESValidationResult.Failed(new CBAdESMalformedEncodingFailure());
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
            return CBAdESValidationResult.Failed(new CBAdESRuleViolationsFailure(violations));
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
                    return CBAdESValidationResult.Failed(resolutionFailure!);
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
                    return CBAdESValidationResult.Failed(new CBAdESSignatureInvalidFailure());
                }

                //Step e: success — ownership of headers/unsignedHeaders transfers to the result; the Signature and
                //RawProtectedHeader carriers (neither returned to the caller) are disposed here.
                parseResult.Signature.Dispose();
                parseResult.RawProtectedHeader!.Dispose();
                return CBAdESValidationResult.Success(headers, payloadIsDetached, unsignedHeaders);
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

        /// <summary>Projects <paramref name="detachedObjects"/>'s entries onto their bare reference strings, in wire order.</summary>
        /// <param name="detachedObjects">The <c>sigD</c> component to project.</param>
        /// <returns>The <c>pars</c> reference strings, in order.</returns>
        static IReadOnlyList<string> BuildReferenceList(CBAdESDetachedObjects detachedObjects)
        {
            var references = new string[detachedObjects.DetachedObjects.Count];
            for(int i = 0; i < references.Length; ++i)
            {
                references[i] = detachedObjects.DetachedObjects[i].Reference;
            }

            return references;
        }


        /// <summary>Projects <paramref name="detachedObjects"/>'s entries onto <see cref="CBAdESDetachedObjectReferenceInput"/>, in wire order.</summary>
        /// <param name="detachedObjects">The <c>sigD</c> component to project.</param>
        /// <returns>The reference/content-type pairs, in order.</returns>
        static IReadOnlyList<CBAdESDetachedObjectReferenceInput> BuildReferenceInputs(CBAdESDetachedObjects detachedObjects)
        {
            var inputs = new CBAdESDetachedObjectReferenceInput[detachedObjects.DetachedObjects.Count];
            for(int i = 0; i < inputs.Length; ++i)
            {
                CBAdESDetachedObjectEntry entry = detachedObjects.DetachedObjects[i];
                inputs[i] = new CBAdESDetachedObjectReferenceInput(entry.Reference, entry.ContentType);
            }

            return inputs;
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
    /// Determines whether <paramref name="exception"/> represents malformed or non-conformant untrusted wire
    /// bytes that <see cref="ValidateAsync(ReadOnlyMemory{byte}, ParseCBAdESSign1Delegate, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, ReadOnlyMemory{byte}?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
    /// catches to fail closed (R-5), mirroring <see cref="Verifiable.Cbor.CoseVerification"/>'s own classifier.
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
