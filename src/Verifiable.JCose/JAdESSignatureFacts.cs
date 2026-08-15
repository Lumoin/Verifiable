using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The JAdES binding of <c>Verifiable.Cryptography.Pki</c>'s format-facts seam: it reads a JAdES JWS message and
/// presents it as the format-neutral <see cref="SignatureFacts"/> the building blocks of clause 5.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> validate, and performs the cryptographic checks of clause 5.2.7.4 over the JWS
/// encoding — the THIRD EN 319 102-1 binding this library ships, after
/// <see cref="CAdESSignatureFacts"/> and <see cref="CBAdESSignatureFacts"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Placement, mirroring <see cref="CBAdESSignatureFacts"/>'s own reasoning.</strong> No JSON decoder
/// lives in <c>Verifiable.Cryptography</c> — the project bans <c>System.Text.Json</c> in every assembly except
/// <c>Verifiable.Json</c>/<c>Verifiable</c>/tests (<c>Directory.Build.props</c>, <c>BannedSymbols.Serialization.txt</c>),
/// an STJ-ban parity this file's placement is deliberately built to maintain. The JAdES decode/validate machinery
/// (<see cref="JAdESProtectedHeaders"/>, <see cref="JAdESHeaderRules"/>, <see cref="Jws"/>) already lives in THIS
/// assembly, one layer below the JSON codec (<c>Verifiable.Json</c>, which cannot be referenced downward either).
/// <see cref="CreateSeam"/> is therefore a FACTORY, not a fixed <c>Seam</c> property, closing over the concrete
/// <c>Verifiable.Json</c> delegates the composition root supplies — never reaching into <c>Verifiable.Json</c> by
/// name, the identical delegate-injection discipline <see cref="JAdESSignatureValidation"/> itself already uses.
/// </para>
/// <para>
/// <strong>Never re-implementing decode or verification.</strong> Structural decode is entirely the
/// injected parse/decode delegates' job; B-B conformance is the shared, already-shipped
/// <see cref="JAdESHeaderRules.Check"/>; cryptographic verification is the shared, already-shipped
/// <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, bool, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>.
/// This binding's own code is limited to (a) mapping the already-decoded <see cref="JAdESProtectedHeaders"/>/
/// <see cref="JAdESUnsignedHeaders"/> model onto <see cref="SignatureFacts"/>' shape, copying bytes into carriers
/// this binding's own <see cref="SignatureFacts"/> owns, and (b) resolving the signing certificate's raw
/// elliptic-curve public-key point via <see cref="EllipticCurveSigningCertificateResolution"/> — the SAME
/// CBOR/JSON-free seam <see cref="CBAdESSignatureFacts"/> already uses, reused here rather than duplicated.
/// </para>
/// <para>
/// <strong>THE MAPPING DISCIPLINE (per-class table) — Table 1's own two-way split, mirroring this library's
/// CB-AdES mapping, transposed.</strong> Class 1 — a JWS structural decode failure (the wire bytes do not parse as
/// one of the three JWS serializations, carry more than one signature, or the JWS Protected Header does not
/// decode as a well-formed <see cref="JAdESProtectedHeaders"/>) prevents the cryptographic verification building
/// block from processing the signature at all, so it maps to <see cref="SignatureFactsStatus.FormatFailure"/> —
/// clause 5.2.2's own scoping ("to the extent that the cryptographic verification building block is unable to
/// process it"). Class 2 — a <see cref="JAdESHeaderRules.Check"/> B-B conformance violation — never prevents that
/// processing: every violation it reports operates on an already-decoded, already-present protected header set.
/// Extraction therefore always proceeds to <see cref="BuildFacts"/>, which downgrades the violated header's
/// <see cref="SignatureAttributeFacts.IsWellFormed"/> to <see langword="false"/> instead
/// (<see cref="DowngradeViolatedAttributes"/>) — reachable by <see cref="SignatureAcceptanceValidation"/>'s
/// existing <c>SIG_CONSTRAINTS_FAILURE</c>/<c>INDETERMINATE</c> arm when a Driving Application's
/// <see cref="SignatureElementsConstraints"/> names the header, never a second, JAdES-private constraint engine.
/// </para>
/// <para>
/// <strong>Scope narrower than <see cref="CAdESSignatureFacts"/> (documented, not silent).</strong> This binding
/// does not resolve a <c>sigD</c>-referenced payload — <c>HttpHeaders</c> canonicalization and the two
/// <c>ObjectId</c> dereferencing mechanisms are creation/validation-orchestrator territory
/// (<see cref="JAdESSignatureValidation"/>'s own no-HTTP-in-library seam), not this binding's. A signature whose
/// protected header carries <see cref="JAdESProtectedHeaders.SigD"/> is cannot-process at cryptographic
/// verification (<see cref="SignatureCryptographicOutcome.NotVerified"/>), never a crypto FAILURE. This binding
/// does not decode the <c>refs</c> family's own digest-reference cross-checks (<c>xRefs</c>/<c>rRefs</c>/
/// <c>axRefs</c>/<c>arRefs</c>), attribute-certificate material (<c>axVals</c>/<c>arVals</c>), <c>sigPSt</c>, or
/// <c>cSig</c> countersignature content — the direct JAdES analogue of <see cref="CBAdESSignatureFacts"/>'s own
/// disclosed <c>x5chain</c>/<c>refs</c>/<c>sigPSt</c>/countersignature residue. Table 1's "Signing Certificate"
/// input is expected to be supplied directly by the Driving Application
/// (<see cref="SignatureValidationInputs.SigningCertificate"/>) — <see cref="SignatureFacts.SigningCertificateReferences"/>
/// stays empty; the signed <c>x5t#S256</c>/<c>x5t#o</c>/<c>sigX5ts</c>/<c>x5c</c> occurrences that would populate
/// it are not decoded into references here. In <see cref="CreateSeam"/>'s cryptographic-verification delegate: a
/// payload that cannot be obtained (detached with no Signer's Document supplied, or a present <c>sigD</c>, or wire
/// bytes that fail to re-parse) maps to <see cref="SignatureCryptographicOutcome.SignedDataNotFound"/> — the
/// direct analogue of <c>JAdESDetachedObjectUnresolvableFailure</c>; a signature value that WAS checked and does
/// not verify maps to <see cref="SignatureCryptographicOutcome.SignatureValueFailure"/> — the direct analogue of
/// <c>JAdESSignatureInvalidFailure</c>. <see cref="SignatureCryptographicOutcome.HashFailure"/> has NO reachable
/// arm from this binding, mirroring <see cref="CBAdESSignatureFacts"/>'s identical gap (JAdES has no hash-only
/// signed-data-item check independent of the JWS signature value itself) — recorded here as a deliberate gap,
/// not a silent one.
/// </para>
/// <para>
/// <strong>An unsupported/unparseable signing certificate is cannot-process, not a failed check (this library's
/// CB-AdES treatment, transposed).</strong> When <see cref="EllipticCurveSigningCertificateResolution.TryResolve"/> cannot
/// resolve <see cref="SignatureCryptographicVerificationContext.SigningCertificate"/> at all (an RSA certificate,
/// or one that does not parse as well-formed X.509), no verification could even be ATTEMPTED — the outcome is
/// <see cref="SignatureCryptographicOutcome.NotVerified"/>, which <see cref="CryptographicVerification"/>'s own
/// default arm maps to Table 15's <c>INDETERMINATE</c>/<c>CUSTOM</c>, mirroring both sibling bindings'
/// <see cref="SignatureCryptographicOutcome.SignedDataNotFound"/> precedent of reporting "nothing was checked" as
/// indeterminate rather than failed. <see cref="SignatureCryptographicOutcome.SignatureValueFailure"/> stays
/// reserved for the one case Table 15's <c>SIG_CRYPTO_FAILURE</c> actually names: a signature value that WAS
/// checked, under a resolved key, and did not verify.
/// </para>
/// </remarks>
public static class JAdESSignatureFacts
{
    /// <summary>
    /// Builds the <see cref="SignatureFormatSeam"/> bundle for JAdES, closing over the concrete
    /// <c>Verifiable.Json</c> delegates the composition root supplies (see the type remarks for why this is a
    /// factory rather than a fixed property).
    /// </summary>
    /// <param name="parse">The fail-closed JAdES wire-bytes parse seam (implemented in <c>Verifiable.Json</c>).</param>
    /// <param name="decodeProtectedHeader">The JAdES-typed JWS Protected Header decode seam.</param>
    /// <param name="detectX5tPresence">The JA-5.1.6-01 wire-detection seam.</param>
    /// <param name="parseEtsiU">The <c>etsiU</c> unsigned-header decode seam.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url-decoding.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding (the Signing Input's payload segment).</param>
    /// <returns>The seam, tagged <see cref="SignatureFormatIdentifier.JAdES"/>.</returns>
    /// <exception cref="ArgumentNullException">Any parameter is <see langword="null"/>.</exception>
    public static SignatureFormatSeam CreateSeam(
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        DetectJAdESX5tPresenceDelegate detectX5tPresence,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(decodeProtectedHeader);
        ArgumentNullException.ThrowIfNull(detectX5tPresence);
        ArgumentNullException.ThrowIfNull(parseEtsiU);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        return new SignatureFormatSeam
        {
            Format = SignatureFormatIdentifier.JAdES,
            ExtractFacts = (context, pool, cancellationToken) =>
                ExtractAsync(context, parse, decodeProtectedHeader, detectX5tPresence, parseEtsiU, base64UrlDecoder, pool, cancellationToken),
            VerifyCryptography = (context, pool, cancellationToken) =>
                VerifyCryptographyAsync(context, parse, decodeProtectedHeader, base64UrlDecoder, base64UrlEncoder, pool, cancellationToken)
        };
    }


    /// <summary>Extracts the facts of a JAdES signature — the <see cref="ExtractSignatureFactsAsyncDelegate"/> half of <see cref="CreateSeam"/>'s bundle.</summary>
    /// <param name="context">The Signed Data Object (the JAdES JWS wire bytes) and any caller-supplied Signer's Documents.</param>
    /// <param name="parse">The injected JAdES message parse seam.</param>
    /// <param name="decodeProtectedHeader">The injected JAdES protected-header decode seam.</param>
    /// <param name="detectX5tPresence">The injected JA-5.1.6-01 wire-detection seam.</param>
    /// <param name="parseEtsiU">The injected <c>etsiU</c> decode seam.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url-decoding.</param>
    /// <param name="pool">The memory pool every carrier the returned facts own is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The extracted facts, or a <see cref="SignatureFactsStatus.FormatFailure"/>. The caller disposes them.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Three flagged sites, each traced false-positive. 'out message'/'out unsignedHeaders' " +
            "(TryParseJAdESMessageDelegate/TryParseJAdESEtsiUDelegate) are, per both delegates' own documented " +
            "contracts, 'never throws for malformed input; returns false instead' -- a conforming implementer " +
            "sets the out parameter only immediately before its own 'return true', so the guarding " +
            "try/catch(IsFailClosedParseException) can never observe a non-null out value alongside a " +
            "propagating exception; every successful assignment is owned exactly once, by this method's own " +
            "nested 'using(message)'/'using(unsignedHeaders)' below -- the identical residual-risk acceptance " +
            "JAdESSignatureValidation.VerifyStructureAndSignatureAsync's own suppression already makes for the " +
            "identical out-parameter shape. BuildFacts' returned SignatureFacts transfers into the ValueTask " +
            "this method returns, which the caller disposes; Roslyn's CA2000 analysis cannot see across the " +
            "ValueTask.FromResult boundary into that transfer -- the identical " +
            "CBAdESSignatureFacts.ExtractAsync justification for the identical shape.")]
    private static ValueTask<SignatureFacts> ExtractAsync(
        SignatureFactsExtractionContext context,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        DetectJAdESX5tPresenceDelegate detectX5tPresence,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        bool parsed;
        UnverifiedJAdESMessage? message;
        try
        {
            parsed = parse(context.SignedDataObject.AsReadOnlyMemory().Span, base64UrlDecoder, pool, out message, out _);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            return ValueTask.FromResult(FormatFailure($"The wire bytes do not decode as a well-formed JAdES JWS message: {ex.Message}"));
        }

        if(!parsed || message is null)
        {
            return ValueTask.FromResult(FormatFailure("The wire bytes do not decode as a well-formed JAdES JWS message."));
        }

        using(message)
        {
            UnverifiedJwsSignature signature = message.Wire.Signatures[0];

            IMemoryOwner<byte> protectedJsonBytes;
            try
            {
                protectedJsonBytes = base64UrlDecoder(signature.Protected, pool);
            }
            catch(Exception ex) when(IsFailClosedParseException(ex))
            {
                return ValueTask.FromResult(FormatFailure($"The JWS Protected Header segment did not base64url-decode: {ex.Message}"));
            }

            JAdESProtectedHeaders? headers;
            bool x5tWasPresentOnWire;
            using(protectedJsonBytes)
            {
                headers = decodeProtectedHeader(protectedJsonBytes.Memory.Span, base64UrlDecoder, pool);
                if(headers is null)
                {
                    return ValueTask.FromResult(FormatFailure("The JWS Protected Header does not decode as a well-formed JAdES protected-header set."));
                }

                x5tWasPresentOnWire = detectX5tPresence(protectedJsonBytes.Memory.Span);
            }

            using(headers)
            {
                bool payloadIsDetached = message.Wire.IsDetachedPayload;
                PooledMemory? etsiURawBytes = message.EtsiURawBytes;

                JAdESUnsignedHeaders? unsignedHeaders = null;
                if(etsiURawBytes is not null
                    && (!parseEtsiU(etsiURawBytes.AsReadOnlySpan(), base64UrlDecoder, pool, out unsignedHeaders) || unsignedHeaders is null))
                {
                    return ValueTask.FromResult(FormatFailure("The etsiU unprotected header parameter does not decode as a well-formed unsigned-component array."));
                }

                using(unsignedHeaders)
                {
                    //THE MAPPING DISCIPLINE (see type remarks): every violation JAdESHeaderRules.Check can report
                    //here operates on an already-decoded, already-present protected header set -- a Table 1 B-B
                    //conformance rule, never a decode blocker, so none of them gate extraction to FormatFailure.
                    //They flow into BuildFacts instead, which downgrades the affected header's
                    //SignatureAttributeFacts entry to IsWellFormed=false.
                    IReadOnlyList<JAdESRuleViolation> violations = JAdESHeaderRules.Check(headers, payloadIsDetached, x5tWasPresentOnWire: x5tWasPresentOnWire);

                    return ValueTask.FromResult(BuildFacts(context, message, headers, unsignedHeaders, payloadIsDetached, violations, pool));
                }
            }
        }
    }


    /// <summary>Mints a <see cref="SignatureFactsStatus.FormatFailure"/> tagged <see cref="SignatureFormatIdentifier.JAdES"/>.</summary>
    /// <param name="reason">What this binding could state about the failure.</param>
    /// <returns>The failed facts.</returns>
    private static SignatureFacts FormatFailure(string reason) => SignatureFacts.FormatFailure(SignatureFormatIdentifier.JAdES, reason);


    /// <summary>
    /// Maps an already-decoded, already B-B-checked JAdES message onto <see cref="SignatureFacts"/>, copying
    /// every carrier's bytes into fresh, this-instance-owned pool memory (never aliasing a carrier
    /// <paramref name="message"/>/<paramref name="headers"/>/<paramref name="unsignedHeaders"/> also own and will
    /// dispose).
    /// </summary>
    /// <param name="context">The extraction context (for the caller-supplied Signer's Documents, and the original Signed Data Object).</param>
    /// <param name="message">The parsed JWS structure (still open; not disposed by this method).</param>
    /// <param name="headers">The decoded protected header set (B-B conformance may still be violated — see <see cref="ExtractAsync"/>'s remarks).</param>
    /// <param name="unsignedHeaders">The decoded <c>etsiU</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="payloadIsDetached">Whether the JWS Payload is detached.</param>
    /// <param name="violations">Every B-B conformance violation <see cref="JAdESHeaderRules.Check"/> found, applied to <see cref="SignatureAttributeFacts.IsWellFormed"/> per <see cref="DowngradeViolatedAttributes"/>.</param>
    /// <param name="pool">The memory pool every copied carrier is rented from.</param>
    /// <returns>The extracted facts.</returns>
    private static SignatureFacts BuildFacts(
        SignatureFactsExtractionContext context,
        UnverifiedJAdESMessage message,
        JAdESProtectedHeaders headers,
        JAdESUnsignedHeaders? unsignedHeaders,
        bool payloadIsDetached,
        IReadOnlyList<JAdESRuleViolation> violations,
        BaseMemoryPool pool)
    {
        List<PkiCertificateMemory> certificates = [];
        List<PkiCertificateMemory> revocationLists = [];
        List<PkiCertificateMemory> ocspResponses = [];
        List<EmbeddedTimestamp> timestamps = [];

        if(headers.PayloadTimestamps is not null)
        {
            //adoTst (clause 5.2.6) is the ONE clause-5.1/5.2 signed header that carries a proof-of-existence
            //style time-stamp -- clause 4.2.5.8's "applied before signature production" is exactly
            //SignatureTimestampClass.ContentTimestamp's own definition.
            CopyTimestamps(headers.PayloadTimestamps, SignatureTimestampClass.ContentTimestamp, "adoTst", timestamps, pool);
        }

        if(unsignedHeaders is not null)
        {
            for(int i = 0; i < unsignedHeaders.Count; ++i)
            {
                switch(unsignedHeaders[i])
                {
                    case JAdESUnsignedHeaderElementSignatureTimestamp sigTst:
                        CopyTimestamps(GetDecodedValue(sigTst.Carriage), SignatureTimestampClass.SignatureTimestamp, "sigTst", timestamps, pool);
                        break;

                    case JAdESUnsignedHeaderElementArchiveTimestamp arcTst:
                        CopyTimestamps(GetDecodedValue(arcTst.Carriage), SignatureTimestampClass.ArchiveTimestamp, "arcTst", timestamps, pool);
                        break;

                    case JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp sigRTst:
                        CopyTimestamps(GetDecodedValue(sigRTst.Carriage), SignatureTimestampClass.ValidationDataTimestamp, "sigRTst", timestamps, pool);
                        break;

                    case JAdESUnsignedHeaderElementReferencesTimestamp rfsTst:
                        CopyTimestamps(GetDecodedValue(rfsTst.Carriage), SignatureTimestampClass.ValidationDataTimestamp, "rfsTst", timestamps, pool);
                        break;

                    case JAdESUnsignedHeaderElementCertificateValues xVals:
                        CopyCertificateValues(GetDecodedValue(xVals.Carriage), certificates, pool);
                        break;

                    case JAdESUnsignedHeaderElementRevocationValues rVals:
                        CopyRevocationValues(GetDecodedValue(rVals.Carriage), revocationLists, ocspResponses, pool);
                        break;

                    case JAdESUnsignedHeaderElementAnyValidationData anyValData:
                        CopyValidationData(GetDecodedValue(anyValData.Carriage), certificates, revocationLists, ocspResponses, pool);
                        break;

                    case JAdESUnsignedHeaderElementTimestampValidationData tstVD:
                        CopyValidationData(GetDecodedValue(tstVD.Carriage), certificates, revocationLists, ocspResponses, pool);
                        break;

                    //axVals/arVals (attribute-certificate material), xRefs/rRefs/axRefs/arRefs (digest-only
                    //references), sigPSt, and cSig are the disclosed residue named in the type remarks -- not
                    //decoded into these facts.
                }
            }
        }

        SignedContentMemory? signedContent = null;
        SignedContentPlacement placement = SignedContentPlacement.NotPresent;
        if(!payloadIsDetached)
        {
            signedContent = SignedContentMemory.FromBytes(message.Wire.Payload.Span, pool);
            placement = SignedContentPlacement.Encapsulated;
        }
        else if(context.SignerDocuments.Count > 0 && context.SignerDocuments[0].Content is SignedContentMemory suppliedDocument)
        {
            signedContent = SignedContentMemory.FromBytes(suppliedDocument.AsReadOnlySpan(), pool);
            placement = SignedContentPlacement.Detached;
        }

        UnverifiedJwsSignature signature = message.Wire.Signatures[0];
        SignedContentMemory signatureValue = SignedContentMemory.FromBytes(signature.SignatureBytes.Memory.Span, pool);

        List<AlgorithmUse> algorithmUses = [new AlgorithmUse(
            new AlgorithmIdentifier(headers.Algorithm) { Name = headers.Algorithm },
            KeySizeBits: null,
            SignatureMaterialIdentifiers.SignatureValue)];

        List<SignatureAttributeFacts> attributes = CollectAttributes(headers);
        DowngradeViolatedAttributes(attributes, violations);

        return new SignatureFacts
        {
            Status = SignatureFactsStatus.Extracted,
            Format = SignatureFormatIdentifier.JAdES,
            SignedDataObject = context.SignedDataObject,
            SignedContent = signedContent,
            SignedContentPlacement = placement,
            SignatureValue = signatureValue,
            Attributes = attributes,
            SigningCertificateReferences = BuildSigningCertificateReferences(headers, pool),
            SigningCertificate = null,
            EmbeddedCertificates = certificates,
            EmbeddedCertificateRevocationLists = revocationLists,
            EmbeddedOcspResponses = ocspResponses,
            Timestamps = timestamps,
            ClaimedSigningTime = headers.IssuedAt?.Value ?? headers.SigT?.Value,
            SignaturePolicyIdentifier = headers.SignaturePolicyIdentifier?.Id.Id,
            AlgorithmUses = algorithmUses
        };
    }


    /// <summary>
    /// Builds every <see cref="SigningCertificateReference"/> the signed header set's own signing-certificate-
    /// identification parameters carry (JA-5.1.7-04's four disjunctive mechanisms) — <see cref="JAdESProtectedHeaders.X5tHashS256"/>
    /// and <see cref="JAdESProtectedHeaders.X5tHashO"/> each name the signer's own certificate directly, and
    /// <see cref="JAdESProtectedHeaders.SigX5ts"/>'s own first entry does too (JA-5.2.2.3-03), the rest naming the
    /// remaining certification path in order. <see cref="JAdESProtectedHeaders.X5Chain"/> carries full DER
    /// certificates, not digests, so it contributes no reference here (mirrors JA-A.1.1-02's own
    /// <c>CollectSigningCertificateDigests</c> exclusion in <see cref="JAdESSignatureValidation"/>). Closes the
    /// trivial-PASS hole <see cref="SigningCertificateIdentification"/> otherwise takes when
    /// <see cref="SignatureFacts.SigningCertificateReferences"/> is left empty (clause 5.2.3.4's last paragraph)
    /// even though the signature itself carries a checkable commitment.
    /// </summary>
    /// <param name="headers">The decoded protected header set.</param>
    /// <param name="pool">The memory pool each reference's copied digest is rented from.</param>
    /// <returns>One reference per resolvable digest, in header-parameter order; empty when none resolve.</returns>
    internal static List<SigningCertificateReference> BuildSigningCertificateReferences(JAdESProtectedHeaders headers, BaseMemoryPool pool)
    {
        var references = new List<SigningCertificateReference>();

        if(headers.X5tHashS256 is not null
            && SigningCertificateReferenceBuilder.TryBuildFromDigest(headers.X5tHashS256, isSignerReference: true, pool) is SigningCertificateReference s256)
        {
            references.Add(s256);
        }

        if(headers.X5tHashO is not null
            && SigningCertificateReferenceBuilder.TryBuildFromDigest(headers.X5tHashO.Digest, isSignerReference: true, pool) is SigningCertificateReference o)
        {
            references.Add(o);
        }

        if(headers.SigX5ts is not null)
        {
            for(int i = 0; i < headers.SigX5ts.Thumbprints.Count; ++i)
            {
                if(SigningCertificateReferenceBuilder.TryBuildFromDigest(headers.SigX5ts.Thumbprints[i].Digest, isSignerReference: i == 0, pool) is SigningCertificateReference reference)
                {
                    references.Add(reference);
                }
            }
        }

        return references;
    }


    /// <summary>
    /// Maps every PRESENT protected header parameter onto <see cref="SignatureAttributeFacts"/>, one entry per
    /// parameter, all <see cref="SignatureAttributeScope.Signed"/> — every clause-5.1/5.2 member is carried in the
    /// JWS Protected Header by construction — <see cref="SignatureAttributeFacts.Identifier"/> the exact wire
    /// header-parameter name (<see cref="Verifiable.Cryptography.Pki.JAdESBaselineLevelTable"/>'s own row
    /// <c>Name</c>) so a Driving Application's <see cref="SignatureElementsConstraints.MandatedSignedAttributeOids"/>/
    /// <c>ForbiddenSignedAttributeOids</c> can name a JAdES header the same way the matrix itself does — the
    /// direct <see cref="CBAdESSignatureFacts"/> analogue, adapted to JAdES's already-JOSE-native names.
    /// </summary>
    /// <remarks>
    /// <strong>What does NOT map here (a disclosed vacuity, matching <see cref="CBAdESSignatureFacts"/>'s own
    /// residue table).</strong> Every <c>etsiU</c> element (<c>sigTst</c>, <c>arcTst</c>, <c>sigRTst</c>,
    /// <c>rfsTst</c>, <c>xVals</c>, <c>rVals</c>, <c>anyValData</c>, <c>tstVD</c>, <c>axVals</c>, <c>arVals</c>,
    /// the <c>refs</c> family, <c>sigPSt</c>, <c>cSig</c>) is UNSIGNED — clause 5.2.8.4.1's mandated/forbidden
    /// attribute rule and this row's own <see cref="SignatureAttributeScope.Signed"/> scoping never reach them
    /// through <see cref="SignatureAttributeFacts"/> regardless; they are surfaced instead through
    /// <see cref="SignatureFacts.Timestamps"/>/<see cref="SignatureFacts.EmbeddedCertificates"/>/
    /// <see cref="SignatureFacts.EmbeddedCertificateRevocationLists"/>/<see cref="SignatureFacts.EmbeddedOcspResponses"/>
    /// above (<c>BuildFacts</c>'s own switch). <c>alg</c>'s own value is separately reported through
    /// <see cref="SignatureFacts.AlgorithmUses"/>, not duplicated here as an attribute.
    /// </remarks>
    /// <param name="headers">The decoded protected header set.</param>
    /// <returns>One entry per present protected header parameter.</returns>
    private static List<SignatureAttributeFacts> CollectAttributes(JAdESProtectedHeaders headers)
    {
        List<SignatureAttributeFacts> attributes = [];

        if(headers.ContentType is not null)
        {
            attributes.Add(new SignatureAttributeFacts("cty", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.KeyId is not null)
        {
            attributes.Add(new SignatureAttributeFacts("kid", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.X5U is not null)
        {
            attributes.Add(new SignatureAttributeFacts("x5u", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.X5tHashS256 is not null)
        {
            attributes.Add(new SignatureAttributeFacts("x5t#S256", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.X5Chain is not null)
        {
            attributes.Add(new SignatureAttributeFacts("x5c", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.CriticalLabels is not null)
        {
            attributes.Add(new SignatureAttributeFacts("crit", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.B64 is not null)
        {
            attributes.Add(new SignatureAttributeFacts("b64", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.IssuedAt is not null)
        {
            attributes.Add(new SignatureAttributeFacts("iat", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SigT is not null)
        {
            attributes.Add(new SignatureAttributeFacts("sigT", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.X5tHashO is not null)
        {
            attributes.Add(new SignatureAttributeFacts("x5t#o", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SigX5ts is not null)
        {
            attributes.Add(new SignatureAttributeFacts("sigX5ts", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SignerCommitments is not null)
        {
            attributes.Add(new SignatureAttributeFacts("srCms", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SignatureProductionPlace is not null)
        {
            attributes.Add(new SignatureAttributeFacts("sigPl", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SignerAttributes is not null)
        {
            attributes.Add(new SignatureAttributeFacts("srAts", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.PayloadTimestamps is not null)
        {
            attributes.Add(new SignatureAttributeFacts("adoTst", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SignaturePolicyIdentifier is not null)
        {
            attributes.Add(new SignatureAttributeFacts("sigPId", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SigD is not null)
        {
            attributes.Add(new SignatureAttributeFacts("sigD", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        return attributes;
    }


    /// <summary>
    /// Downgrades every attribute <paramref name="violations"/> names to <c>IsWellFormed = false</c> — clause
    /// 5.2.8.4.1's first bullet ("an attribute that is present but malformed... proceed as if the attribute was
    /// not present"), the shared engine's own reading a Table 1 B-B conformance violation satisfies exactly: the
    /// header decoded, but its content or combination violates the profile, so it counts as absent for
    /// <see cref="SignatureAcceptanceValidation"/>'s mandated/forbidden constraint check — never a
    /// <see cref="SignatureFactsStatus.FormatFailure"/> (see the type remarks' mapping discipline).
    /// </summary>
    /// <remarks>
    /// <see cref="JAdESX5tForbiddenViolation"/> and <see cref="JAdESSigningCertificateIdentificationViolation"/>
    /// need no downgrade here: both fire only when the named header is ALREADY absent from
    /// <paramref name="attributes"/> (the forbidden <c>x5t</c> has no representable attribute at all;
    /// the four-way disjunction violation fires only when all four are absent), so there is nothing to mark.
    /// <see cref="JAdESIssuedAtMissingViolation"/> is the identical shape (fires only when <c>iat</c> is already
    /// absent).
    /// </remarks>
    /// <param name="attributes">The attributes <see cref="CollectAttributes"/> produced, downgraded in place.</param>
    /// <param name="violations">Every violation <see cref="JAdESHeaderRules.Check"/> found.</param>
    private static void DowngradeViolatedAttributes(List<SignatureAttributeFacts> attributes, IReadOnlyList<JAdESRuleViolation> violations)
    {
        for(int i = 0; i < violations.Count; ++i)
        {
            switch(violations[i])
            {
                case JAdESContentTypeCountersignedPayloadViolation:
                    Downgrade(attributes, "cty");
                    break;

                case JAdESPayloadTimestampCanonAlgViolation:
                    Downgrade(attributes, "adoTst");
                    break;

                case JAdESDetachedObjectReferenceAttachedPayloadViolation:
                case JAdESDetachedObjectReferenceCriticalLabelViolation:
                case JAdESHttpHeadersMechanismB64Violation:
                case JAdESHttpHeadersParsNotLowercaseViolation:
                    Downgrade(attributes, "sigD");
                    break;
            }
        }

        /// <summary>Replaces the named attribute's entry with an <c>IsWellFormed = false</c> copy, when present.</summary>
        /// <param name="candidates">The attributes to search and update in place.</param>
        /// <param name="identifier">The wire header-parameter name to downgrade.</param>
        static void Downgrade(List<SignatureAttributeFacts> candidates, string identifier)
        {
            for(int i = 0; i < candidates.Count; ++i)
            {
                if(string.Equals(candidates[i].Identifier, identifier, StringComparison.Ordinal))
                {
                    candidates[i] = candidates[i] with { IsWellFormed = false };

                    return;
                }
            }
        }
    }


    /// <summary>Extracts the decoded value from either arm of the dual-mode <c>etsiU</c> carriage (per-instance CMS/imprint verification runs in BOTH incorporation modes, mirroring <see cref="JAdESSignatureValidation"/>'s own reading).</summary>
    /// <typeparam name="TValue">The decoded semantic shape.</typeparam>
    /// <param name="carriage">The dual-mode carriage.</param>
    /// <returns>The decoded value.</returns>
    private static TValue GetDecodedValue<TValue>(JAdESUnsignedValue<TValue> carriage) => carriage switch
    {
        JAdESClearUnsignedValue<TValue> clear => clear.Value,
        JAdESOpaqueUnsignedValue<TValue> opaque => opaque.DecodedValue,
        _ => throw new NotSupportedException($"Unknown etsiU carriage arm '{carriage.GetType()}'.")
    };


    /// <summary>Copies every token of a <see cref="AdESTimestampContainer"/> into classified, freshly-owned <see cref="EmbeddedTimestamp"/> entries.</summary>
    /// <param name="container">The decoded container.</param>
    /// <param name="timestampClass">The class every token in this container is reported as.</param>
    /// <param name="identifier">The carrying header/element's own name.</param>
    /// <param name="timestamps">Collects the copied entries, ordinal-numbered within this class.</param>
    /// <param name="pool">The memory pool every token carrier is rented from.</param>
    private static void CopyTimestamps(
        AdESTimestampContainer container, SignatureTimestampClass timestampClass, string identifier, List<EmbeddedTimestamp> timestamps, BaseMemoryPool pool)
    {
        int ordinalBase = 0;
        for(int i = 0; i < timestamps.Count; ++i)
        {
            if(timestamps[i].Class == timestampClass)
            {
                ++ordinalBase;
            }
        }

        for(int t = 0; t < container.TstTokens.Count; ++t)
        {
            timestamps.Add(new EmbeddedTimestamp
            {
                Class = timestampClass,
                Identifier = identifier,
                Token = CopyBytes(container.TstTokens[t].Val, PkiCertificateTags.TimestampToken, pool),
                Ordinal = ordinalBase + t
            });
        }
    }


    /// <summary>Copies a decoded <c>xVals</c>-shaped value's <c>x509Cert</c> items into freshly-owned certificate carriers. <c>otherCert</c> items are skipped — a declared extensibility placeholder, not DER X.509.</summary>
    /// <param name="certificateValues">The decoded certificate values.</param>
    /// <param name="certificates">Collects every <c>x509Cert</c> entry.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    private static void CopyCertificateValues(JAdESCertificateValues certificateValues, List<PkiCertificateMemory> certificates, BaseMemoryPool pool)
    {
        for(int i = 0; i < certificateValues.Items.Count; ++i)
        {
            if(certificateValues.Items[i] is JAdESX509Certificate x509)
            {
                certificates.Add(CopyBytes(x509.Certificate.Val, PkiCertificateTags.X509Certificate, pool));
            }
        }
    }


    /// <summary>Copies a decoded <c>rVals</c>-shaped value's CRLs and OCSP responses into freshly-owned carriers.</summary>
    /// <param name="revocationValues">The decoded revocation values.</param>
    /// <param name="revocationLists">Collects every <c>crlVals</c> entry.</param>
    /// <param name="ocspResponses">Collects every <c>ocspVals</c> entry.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    private static void CopyRevocationValues(
        JAdESRevocationValues revocationValues, List<PkiCertificateMemory> revocationLists, List<PkiCertificateMemory> ocspResponses, BaseMemoryPool pool)
    {
        if(revocationValues.CrlValues is not null)
        {
            for(int i = 0; i < revocationValues.CrlValues.Count; ++i)
            {
                revocationLists.Add(CopyBytes(revocationValues.CrlValues[i].Val, PkiCertificateTags.X509Crl, pool));
            }
        }

        if(revocationValues.OcspValues is not null)
        {
            for(int i = 0; i < revocationValues.OcspValues.Count; ++i)
            {
                ocspResponses.Add(CopyBytes(revocationValues.OcspValues[i].Val, PkiCertificateTags.OcspResponse, pool));
            }
        }
    }


    /// <summary>Copies a decoded <c>anyValData</c>/<c>tstVD</c>-shaped value's certificates/CRLs/OCSP responses into freshly-owned carriers.</summary>
    /// <param name="validationData">The decoded validation data.</param>
    /// <param name="certificates">Collects every <c>xVals</c>/<c>x509Cert</c> entry.</param>
    /// <param name="revocationLists">Collects every <c>rVals</c>/<c>crlVals</c> entry.</param>
    /// <param name="ocspResponses">Collects every <c>rVals</c>/<c>ocspVals</c> entry.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    private static void CopyValidationData(
        JAdESValidationData validationData, List<PkiCertificateMemory> certificates, List<PkiCertificateMemory> revocationLists, List<PkiCertificateMemory> ocspResponses, BaseMemoryPool pool)
    {
        if(validationData.CertificateValues is not null)
        {
            CopyCertificateValues(validationData.CertificateValues, certificates, pool);
        }

        if(validationData.RevocationValues is not null)
        {
            CopyRevocationValues(validationData.RevocationValues, revocationLists, ocspResponses, pool);
        }
    }


    /// <summary>Copies borrowed bytes into a fresh, pool-rented <see cref="PkiCertificateMemory"/>.</summary>
    /// <param name="bytes">The bytes to copy.</param>
    /// <param name="tag">The kind discriminator the carrier is tagged with.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The owned carrier.</returns>
    private static PkiCertificateMemory CopyBytes(ReadOnlyMemory<byte> bytes, Tag tag, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.Span.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// Performs the cryptographic checks of clause 5.2.7.4 over a JAdES signature — the
    /// <see cref="VerifySignatureCryptographyAsyncDelegate"/> half of <see cref="CreateSeam"/>'s bundle. Re-decodes
    /// <see cref="SignatureFacts.SignedDataObject"/> independently (mirroring <see cref="CBAdESSignatureFacts.VerifyCryptographyAsync"/>'s
    /// own re-parse discipline) to recover the exact base64url-encoded protected-header TEXT and signature bytes
    /// <see cref="Jws"/> needs — neither of which <see cref="SignatureFacts"/> carries, since RFC 7515 §5.1
    /// requires the Signing Input be built from the EXACT wire text, never a re-encoding of the decoded model.
    /// </summary>
    /// <param name="context">The signature's facts, the signing certificate, and the optional chain and documents.</param>
    /// <param name="parse">The injected JAdES message parse seam.</param>
    /// <param name="decodeProtectedHeader">The injected JAdES protected-header decode seam.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url-decoding.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="pool">The memory pool the re-parse and the public-key carrier are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome in the vocabulary of Table 15 of clause 5.2.7.3 — see the type remarks for the mapping.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "'out message' is a traced false-positive under TryParseJAdESMessageDelegate's own " +
            "documented contract ('never throws for malformed input; returns false instead'): a conforming " +
            "implementer sets it only immediately before its own 'return true', so the guarding " +
            "try/catch(IsFailClosedParseException) can never observe a non-null out value alongside a " +
            "propagating exception. Every successful assignment is owned exactly once, by this method's own " +
            "'using(message)' below -- the identical residual-risk acceptance " +
            "JAdESSignatureValidation.VerifyStructureAndSignatureAsync's own suppression already makes for the " +
            "identical out-parameter shape.")]
    private static async ValueTask<SignatureCryptographicVerification> VerifyCryptographyAsync(
        SignatureCryptographicVerificationContext context,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(context.Signature.SignedDataObject is not SensitiveMemory signedDataObject)
        {
            return SignedDataNotFound("The signed data object of a JAdES signature has to be the JWS wire bytes.");
        }

        bool parsed;
        UnverifiedJAdESMessage? message;
        try
        {
            parsed = parse(signedDataObject.AsReadOnlyMemory().Span, base64UrlDecoder, pool, out message, out _);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            return SignedDataNotFound($"The JAdES wire bytes did not re-parse: {ex.Message}");
        }

        if(!parsed || message is null)
        {
            return SignedDataNotFound("The JAdES wire bytes did not re-parse.");
        }

        using(message)
        {
            UnverifiedJwsSignature signature = message.Wire.Signatures[0];

            IMemoryOwner<byte> protectedJsonBytes;
            try
            {
                protectedJsonBytes = base64UrlDecoder(signature.Protected, pool);
            }
            catch(Exception ex) when(IsFailClosedParseException(ex))
            {
                return SignedDataNotFound($"The JWS Protected Header segment did not re-decode: {ex.Message}");
            }

            JAdESProtectedHeaders? headers;
            using(protectedJsonBytes)
            {
                headers = decodeProtectedHeader(protectedJsonBytes.Memory.Span, base64UrlDecoder, pool);
            }

            if(headers is null)
            {
                return SignedDataNotFound("The JWS Protected Header did not re-decode.");
            }

            using(headers)
            {
                if(headers.SigD is not null)
                {
                    //Scope narrowing (see type remarks): this binding does not resolve a sigD-referenced
                    //payload -- cannot-process, never a crypto FAILURE.
                    return NotVerified("This binding does not resolve a sigD-referenced JWS Payload (see the type remarks).");
                }

                ReadOnlyMemory<byte> payload;
                if(!message.Wire.IsDetachedPayload)
                {
                    payload = message.Wire.Payload;
                }
                else if(context.SignerDocuments.Count > 0 && context.SignerDocuments[0].Content is SignedContentMemory detached)
                {
                    payload = detached.AsReadOnlyMemory();
                }
                else
                {
                    //Clause 5.2.7.4 step 1): the signed data items could not be obtained.
                    return SignedDataNotFound("The JWS Payload is detached and no Signer's Document was supplied.");
                }

                if(!EllipticCurveSigningCertificateResolution.TryResolve(context.SigningCertificate, out CryptoAlgorithm algorithm, out ReadOnlyMemory<byte> publicKeyPoint))
                {
                    //The cannot-process case CryptographicVerification's own default arm exists for (NotVerified
                    //maps to Table 15's INDETERMINATE/CUSTOM) -- never SignatureValueFailure, which Table 15
                    //reserves for a signature value that WAS checked and did not verify (TOTAL-FAILED).
                    return NotVerified("This binding verifies only elliptic-curve signing certificates (P-256/P-384/P-521/secp256k1) that parse as well-formed X.509.");
                }

                using PublicKeyMemory publicKey = ToPublicKeyMemory(publicKeyPoint, algorithm, pool);

                CryptoAlgorithm verificationAlgorithm = publicKey.Tag.Get<CryptoAlgorithm>();
                Purpose purpose = publicKey.Tag.Get<Purpose>();
                VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(verificationAlgorithm, purpose);

                bool base64UrlPayload = headers.B64 is null || headers.B64.Value;

                try
                {
                    bool isValid = await Jws.VerifySignatureAsync(
                        signature.Protected,
                        payload,
                        base64UrlPayload,
                        signature.SignatureBytes.Memory,
                        base64UrlEncoder,
                        verificationDelegate,
                        publicKey.AsReadOnlyMemory(),
                        pool,
                        cancellationToken: cancellationToken).ConfigureAwait(false);

                    return isValid
                        ? new SignatureCryptographicVerification { Outcome = SignatureCryptographicOutcome.Verified, SigningCertificate = context.SigningCertificate }
                        : SignatureValueFailure("The JWS signature value does not verify over the Signing Input (RFC 7515 §5.1).");
                }
                catch(Exception ex) when(ex is System.Security.Cryptography.CryptographicException)
                {
                    return SignatureValueFailure($"The registered verification function threw over the resolved Signing Input/signature pair: {ex.Message}");
                }
            }
        }
    }


    /// <summary>Mints a <see cref="SignatureCryptographicOutcome.SignedDataNotFound"/> outcome.</summary>
    /// <param name="reason">What this binding could state about the failure.</param>
    /// <returns>The outcome.</returns>
    private static SignatureCryptographicVerification SignedDataNotFound(string reason) =>
        new() { Outcome = SignatureCryptographicOutcome.SignedDataNotFound, Reason = reason };


    /// <summary>Mints a <see cref="SignatureCryptographicOutcome.SignatureValueFailure"/> outcome.</summary>
    /// <param name="reason">What this binding could state about the failure.</param>
    /// <returns>The outcome.</returns>
    private static SignatureCryptographicVerification SignatureValueFailure(string reason) =>
        new() { Outcome = SignatureCryptographicOutcome.SignatureValueFailure, Reason = reason };


    /// <summary>Mints a <see cref="SignatureCryptographicOutcome.NotVerified"/> outcome — the cannot-process case: no verification was attempted, never that one was attempted and failed.</summary>
    /// <param name="reason">What this binding could state about why verification could not be attempted.</param>
    /// <returns>The outcome.</returns>
    private static SignatureCryptographicVerification NotVerified(string reason) =>
        new() { Outcome = SignatureCryptographicOutcome.NotVerified, Reason = reason };


    /// <summary>
    /// Wraps a raw elliptic-curve public-key point into a pool-owned, correctly-tagged <see cref="PublicKeyMemory"/>.
    /// Internal (not <see langword="private"/>) so <see cref="JAdESSignatureValidation"/>'s own certificate-
    /// accepting <c>ValidateAsync</c> overload can reuse the identical recipe rather than duplicating it.
    /// </summary>
    /// <param name="publicKeyPoint">The uncompressed SEC1 point.</param>
    /// <param name="algorithm">The algorithm identifying which curve tag to use.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The owned carrier; the caller disposes it.</returns>
    internal static PublicKeyMemory ToPublicKeyMemory(ReadOnlyMemory<byte> publicKeyPoint, CryptoAlgorithm algorithm, BaseMemoryPool pool)
    {
        Tag tag = algorithm switch
        {
            var a when a.Equals(CryptoAlgorithm.P256) => CryptoTags.P256PublicKey,
            var a when a.Equals(CryptoAlgorithm.P384) => CryptoTags.P384PublicKey,
            var a when a.Equals(CryptoAlgorithm.P521) => CryptoTags.P521PublicKey,
            _ => CryptoTags.Secp256k1PublicKey
        };

        IMemoryOwner<byte> owner = pool.Rent(publicKeyPoint.Length);
        publicKeyPoint.Span.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, tag);
    }


    /// <summary>Reports whether an exception reflects hostile/malformed wire input a parse seam fails closed on, mirroring <see cref="JAdESSignatureValidation"/>'s own predicate of the identical name/purpose.</summary>
    /// <param name="exception">The exception to classify.</param>
    /// <returns><see langword="true"/> when the exception is a routine parse-failure signal.</returns>
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is FormatException or ArgumentException or InvalidOperationException or OverflowException;
}
