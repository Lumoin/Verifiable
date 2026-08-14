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
/// The CB-AdES binding of <c>Verifiable.Cryptography.Pki</c>'s format-facts seam: it reads a CB-AdES
/// <c>COSE_Sign1</c> structure and presents it as the format-neutral <see cref="SignatureFacts"/> the building
/// blocks of clause 5.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> validate, and performs the cryptographic checks of clause 5.2.7.4 over the
/// COSE encoding.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this file lives here, not in <c>Verifiable.Cryptography/Pki/</c> beside <see cref="CAdESSignatureFacts"/>.</strong>
/// <see cref="CAdESSignatureFacts"/> is "the first binding of the seam and the shape the later ones follow" (its
/// own doc comment) — self-contained, decoding CMS/ASN.1 with no help from a higher layer, because
/// <c>CmsSignedData</c>/<see cref="ManagedCertificate"/> already live in the SAME assembly as the seam types. No
/// analogous CBOR decoder exists in <c>Verifiable.Cryptography</c> for CB-AdES, and none can: the project bans
/// <c>System.Formats.Cbor</c> in every assembly except <c>Verifiable.Json</c>/<c>Verifiable.Cbor</c>/<c>Verifiable</c>/tests
/// (<c>Directory.Build.props</c>, <c>BannedSymbols.Serialization.txt</c>) — a hard, analyzer-enforced boundary,
/// not a convention. The CB-AdES decode/validate machinery (<see cref="CBAdESProtectedHeaders"/>,
/// <see cref="CBAdESHeaderRules"/>) lives in THIS assembly instead, one layer below the CBOR codec
/// (<c>Verifiable.Cbor</c>, which cannot be referenced downward either — <c>Verifiable.Cryptography</c> is below
/// <c>Verifiable.JCose</c> is below <c>Verifiable.Cbor</c>, a directed graph with no cycle allowed). This binding
/// therefore follows the SAME delegate-injection discipline <see cref="CBAdESSignatureValidation"/> itself
/// already uses for the identical reason (its own <c>ParseCBAdESSign1Delegate</c>/<c>BuildSigStructureDelegate</c>
/// parameters): <see cref="CreateSeam"/> is a FACTORY, not a fixed <c>Seam</c> property, closing over the
/// concrete <c>Verifiable.Cbor</c> delegates the composition root supplies — never reaching into
/// <c>Verifiable.Cbor</c> by name.
/// </para>
/// <para>
/// <strong>Never re-implementing decode or verification.</strong> Structural decode is entirely the
/// injected <see cref="ParseCBAdESSign1Delegate"/>'s job; B-B conformance is the shared, already-shipped
/// <see cref="CBAdESHeaderRules.Check"/>; cryptographic verification is the shared, already-shipped
/// <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>.
/// This binding's own code is limited to (a) mapping the already-decoded <see cref="CBAdESProtectedHeaders"/>/
/// <see cref="CBAdESUnsignedHeaders"/> model onto <see cref="SignatureFacts"/>' shape, copying bytes into
/// carriers this binding's own <see cref="SignatureFacts"/> owns (never aliasing a carrier
/// <see cref="CBAdESSign1ParseResult.Dispose"/> also owns), and (b) resolving the signing certificate's raw
/// elliptic-curve public-key point via <see cref="EllipticCurveSigningCertificateResolution"/> (the narrow,
/// CBOR-free seam <c>Verifiable.Cryptography</c> exposes for exactly this).
/// </para>
/// <para>
/// <strong>Scope narrower than <see cref="CAdESSignatureFacts"/> (documented, not silent) — Table 5/6/7 mapping
/// decisions split into two classes.</strong> Class 1 — a
/// CBOR/structural decode failure (the wire bytes do not decode as a well-formed <c>COSE_Sign1</c>, or the
/// decoded structure carries no protected header / no signature) prevents the cryptographic verification
/// building block from processing the signature at all, so it maps to <see cref="SignatureFactsStatus.FormatFailure"/>
/// — clause 5.2.2's own scoping ("to the extent that the cryptographic verification building block is unable to
/// process it", the <see cref="CAdESSignatureFacts"/> precedent's own reading). Class 2 — a Table 14 B-B
/// conformance rule violation (<see cref="CBAdESHeaderRules.Check"/>) — never prevents that processing: every
/// violation Check reports operates on an already-decoded, already-present protected header set (CAdES's own
/// private <c>Extract</c> method never fails extraction on an attribute-presence rule either, that being clause
/// 5.2.8's job, not clause 5.2.2's). Extraction therefore always proceeds to <see cref="BuildFacts"/>,
/// which downgrades the violated header's <see cref="SignatureAttributeFacts.IsWellFormed"/> to
/// <see langword="false"/> instead (<see cref="DowngradeViolatedAttributes"/>) — reachable by
/// <see cref="SignatureAcceptanceValidation"/>'s existing <c>SIG_CONSTRAINTS_FAILURE</c>/<c>INDETERMINATE</c> arm
/// when a Driving Application's <see cref="SignatureElementsConstraints"/> names the header, never a second,
/// CB-AdES-private constraint engine. This binding does NOT decode <c>sigD</c>'s <c>ObjectIdByURIHash</c> <c>hashV</c> cross-check, the
/// unsigned <c>x5chain</c> occurrence's <c>bstr</c>/<c>[2*certs:bstr]</c> split (Table 8 label 33 — the
/// disclosed "RFC 9360 COSE_X509 structured x5chain decode" residue: its raw bytes are surfaced as ONE opaque
/// certificate entry, never split), or <c>refs</c>/<c>sigPSt</c>/countersignature content. Table 14's "Signing Certificate" input is
/// expected to be supplied directly by the Driving Application
/// (<see cref="SignatureValidationInputs.SigningCertificate"/>) — <see cref="SignatureFacts.SigningCertificateReferences"/>
/// stays empty; the signed <c>x5t</c>/<c>x5ts</c>/<c>x5chain</c> occurrences that would populate it are not
/// decoded into references here. In <see cref="CreateSeam"/>'s cryptographic-verification delegate: a payload
/// that cannot be obtained (detached with no Signer's Document supplied, or the wire bytes fail to re-parse) maps
/// to <see cref="SignatureCryptographicOutcome.SignedDataNotFound"/> — the direct analogue of
/// <c>CBAdESDetachedObjectUnresolvableFailure</c>; a signature value that WAS checked and does not verify maps to
/// <see cref="SignatureCryptographicOutcome.SignatureValueFailure"/> — the direct analogue of
/// <c>CBAdESSignatureInvalidFailure</c>. <see cref="SignatureCryptographicOutcome.HashFailure"/> has NO reachable
/// arm from this binding, the direct analogue of the out-of-scope <c>CBAdESDetachedObjectDigestMismatchFailure</c>
/// (<c>ObjectIdByURIHash</c>'s <c>hashV</c> check) — recorded here as a deliberate gap, not a silent one.
/// </para>
/// <para>
/// <strong>An unsupported/unparseable signing certificate is cannot-process, not a failed check.</strong>
/// When <see cref="EllipticCurveSigningCertificateResolution.TryResolve"/> cannot
/// resolve <see cref="SignatureCryptographicVerificationContext.SigningCertificate"/> at all (an RSA certificate,
/// or one that does not parse as well-formed X.509), no verification could even be ATTEMPTED — the outcome is
/// <see cref="SignatureCryptographicOutcome.NotVerified"/>, which <see cref="CryptographicVerification"/>'s own
/// default arm maps to Table 15's <c>INDETERMINATE</c>/<c>CUSTOM</c>, mirroring the CAdES binding's
/// <see cref="SignatureCryptographicOutcome.SignedDataNotFound"/> precedent of reporting "nothing was checked"
/// as indeterminate rather than failed. <see cref="SignatureCryptographicOutcome.SignatureValueFailure"/> stays
/// reserved for the one case Table 15's <c>SIG_CRYPTO_FAILURE</c> actually names: a signature value that WAS
/// checked, under a resolved key, and did not verify.
/// </para>
/// </remarks>
public static class CBAdESSignatureFacts
{
    /// <summary>
    /// Builds the <see cref="SignatureFormatSeam"/> bundle for CB-AdES, closing over the concrete
    /// <c>Verifiable.Cbor</c> delegates the composition root supplies (see the type remarks for why this is a
    /// factory rather than a fixed property).
    /// </summary>
    /// <param name="parse">The fail-closed CB-AdES <c>COSE_Sign1</c> parse seam (implemented in <c>Verifiable.Cbor</c>).</param>
    /// <param name="buildSigStructure">Builds the RFC 9052 §4.4 Sig_structure for verification.</param>
    /// <returns>The seam, tagged <see cref="SignatureFormatIdentifier.CBAdES"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="parse"/> or <paramref name="buildSigStructure"/> is <see langword="null"/>.</exception>
    public static SignatureFormatSeam CreateSeam(ParseCBAdESSign1Delegate parse, BuildSigStructureDelegate buildSigStructure)
    {
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(buildSigStructure);

        return new SignatureFormatSeam
        {
            Format = SignatureFormatIdentifier.CBAdES,
            ExtractFacts = (context, pool, cancellationToken) => ExtractAsync(context, parse, pool, cancellationToken),
            VerifyCryptography = (context, pool, cancellationToken) => VerifyCryptographyAsync(context, parse, buildSigStructure, pool, cancellationToken)
        };
    }


    /// <summary>Extracts the facts of a CB-AdES signature — the <see cref="ExtractSignatureFactsAsyncDelegate"/> half of <see cref="CreateSeam"/>'s bundle.</summary>
    /// <param name="context">The Signed Data Object (the <c>COSE_Sign1</c> wire bytes) and any caller-supplied Signer's Documents.</param>
    /// <param name="parse">The injected CB-AdES parse seam.</param>
    /// <param name="pool">The memory pool every carrier the returned facts own is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The extracted facts, or a <see cref="SignatureFactsStatus.FormatFailure"/>. The caller disposes them.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the SignatureFacts BuildFacts returns transfers into the ValueTask this " +
            "method returns, which the caller disposes; Roslyn's CA2000 analysis cannot see across the " +
            "ValueTask.FromResult boundary into that transfer.")]
    private static ValueTask<SignatureFacts> ExtractAsync(
        SignatureFactsExtractionContext context,
        ParseCBAdESSign1Delegate parse,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        CBAdESSign1ParseResult parseResult;
        try
        {
            parseResult = parse(context.SignedDataObject.AsReadOnlyMemory(), pool);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            return ValueTask.FromResult(FormatFailure($"The wire bytes do not decode as a well-formed CB-AdES COSE_Sign1 structure: {ex.Message}"));
        }

        using(parseResult)
        {
            if(!parseResult.IsSuccess || parseResult.ProtectedHeaders is null || parseResult.Signature is null)
            {
                return ValueTask.FromResult(FormatFailure("The wire bytes do not decode as a well-formed CB-AdES COSE_Sign1 structure."));
            }

            //Table 6's own scoping splits a violation by whether it prevents the
            //cryptographic verification building block from processing the signature at all. Nothing reachable
            //through CBAdESHeaderRules.Check operates on anything OTHER than an already-decoded, already-present
            //protected header set (the two checks above are what gate malformed structure to FormatFailure) --
            //every violation Check can report here is a Table 14 B-B CONFORMANCE rule, never a decode blocker, so
            //none of them gate extraction. They flow into BuildFacts instead, which downgrades the affected
            //header's SignatureAttributeFacts entry to IsWellFormed=false (clause 5.2.8.4.1's own "present but
            //malformed counts as absent" rule) so that a Driving Application's SignatureElementsConstraints
            //reaches SignatureAcceptanceValidation's SIG_CONSTRAINTS_FAILURE/INDETERMINATE arm for it, exactly
            //the same building block CAdES's own attribute-presence rules are checked by -- never a second,
            //CB-AdES-private constraint engine.
            bool payloadIsDetached = !parseResult.PayloadIsPresent;
            IReadOnlyList<CBAdESRuleViolation> violations = CBAdESHeaderRules.Check(parseResult.ProtectedHeaders, payloadIsDetached, parseResult.UnsignedHeaders);

            return ValueTask.FromResult(BuildFacts(context, parseResult, payloadIsDetached, violations, pool));
        }
    }


    /// <summary>Mints a <see cref="SignatureFactsStatus.FormatFailure"/> tagged <see cref="SignatureFormatIdentifier.CBAdES"/>.</summary>
    /// <param name="reason">What this binding could state about the failure.</param>
    /// <returns>The failed facts.</returns>
    private static SignatureFacts FormatFailure(string reason) => SignatureFacts.FormatFailure(SignatureFormatIdentifier.CBAdES, reason);


    /// <summary>
    /// Maps an already B-B-conformant <see cref="CBAdESSign1ParseResult"/> onto <see cref="SignatureFacts"/>,
    /// copying every carrier's bytes into fresh, this-instance-owned pool memory (never aliasing a carrier
    /// <paramref name="parseResult"/> also owns and will dispose).
    /// </summary>
    /// <param name="context">The extraction context (for the caller-supplied Signer's Documents, and the original Signed Data Object).</param>
    /// <param name="parseResult">The successful parse result (successful decode; B-B conformance may still be violated — see <see cref="ExtractAsync"/>'s remarks).</param>
    /// <param name="payloadIsDetached">Whether the COSE Payload is detached.</param>
    /// <param name="violations">Every B-B conformance violation <see cref="CBAdESHeaderRules.Check"/> found, applied to <see cref="SignatureAttributeFacts.IsWellFormed"/> per <see cref="DowngradeViolatedAttributes"/>.</param>
    /// <param name="pool">The memory pool every copied carrier is rented from.</param>
    /// <returns>The extracted facts.</returns>
    private static SignatureFacts BuildFacts(
        SignatureFactsExtractionContext context, CBAdESSign1ParseResult parseResult, bool payloadIsDetached, IReadOnlyList<CBAdESRuleViolation> violations, BaseMemoryPool pool)
    {
        CBAdESProtectedHeaders headers = parseResult.ProtectedHeaders!;
        CBAdESUnsignedHeaders? unsignedHeaders = parseResult.UnsignedHeaders;

        List<PkiCertificateMemory> certificates = [];
        List<PkiCertificateMemory> revocationLists = [];
        List<PkiCertificateMemory> ocspResponses = [];
        List<EmbeddedTimestamp> timestamps = [];

        if(unsignedHeaders is not null)
        {
            for(int i = 0; i < unsignedHeaders.Count; ++i)
            {
                switch(unsignedHeaders[i])
                {
                    case CBAdESUnsignedHeaderElementSignatureTimestamp sigTst:
                        CopyTimestamps(sigTst.SignatureTimestamp.TimestampContainer, SignatureTimestampClass.SignatureTimestamp, "sigTst", timestamps, pool);
                        break;

                    case CBAdESUnsignedHeaderElementArchiveTimestamp arcTst:
                        CopyTimestamps(arcTst.ArchiveTimestamp.TimestampContainer, SignatureTimestampClass.ArchiveTimestamp, "arcTst", timestamps, pool);
                        break;

                    case CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp sigRTst:
                        CopyTimestamps(sigRTst.SignatureAndReferencesTimestamp.TimestampContainer, SignatureTimestampClass.ValidationDataTimestamp, "sigRTst", timestamps, pool);
                        break;

                    case CBAdESUnsignedHeaderElementReferencesTimestamp rfsTst:
                        CopyTimestamps(rfsTst.ReferencesTimestamp.TimestampContainer, SignatureTimestampClass.ValidationDataTimestamp, "rfsTst", timestamps, pool);
                        break;

                    case CBAdESUnsignedHeaderElementValidationData valData:
                        CopyValidationData(valData.ValidationData, certificates, revocationLists, ocspResponses, pool);
                        break;

                    case CBAdESUnsignedHeaderElementCertificateChain x5chain:
                        //Carried opaque -- the residue named in the type remarks: the bstr/[2*certs:bstr] split
                        //is not performed here, so the whole raw value is surfaced as one certificate entry.
                        certificates.Add(CopyBytes(x5chain.Value, PkiCertificateTags.X509Certificate, pool));
                        break;
                }
            }
        }

        SignedContentMemory? signedContent = null;
        SignedContentPlacement placement = SignedContentPlacement.NotPresent;
        if(!payloadIsDetached)
        {
            signedContent = SignedContentMemory.FromBytes(parseResult.Payload.Span, pool);
            placement = SignedContentPlacement.Encapsulated;
        }
        else if(context.SignerDocuments.Count > 0 && context.SignerDocuments[0].Content is SignedContentMemory suppliedDocument)
        {
            signedContent = SignedContentMemory.FromBytes(suppliedDocument.AsReadOnlySpan(), pool);
            placement = SignedContentPlacement.Detached;
        }

        SignedContentMemory signatureValue = SignedContentMemory.FromBytes(parseResult.Signature!.AsReadOnlySpan(), pool);

        List<AlgorithmUse> algorithmUses = [new AlgorithmUse(
            new AlgorithmIdentifier(headers.Algorithm.ToString(System.Globalization.CultureInfo.InvariantCulture)) { Name = CoseAlgorithmName(headers.Algorithm) },
            KeySizeBits: null,
            SignatureMaterialIdentifiers.SignatureValue)];

        List<SignatureAttributeFacts> attributes = CollectAttributes(headers);
        DowngradeViolatedAttributes(attributes, violations);

        return new SignatureFacts
        {
            Status = SignatureFactsStatus.Extracted,
            Format = SignatureFormatIdentifier.CBAdES,
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
            ClaimedSigningTime = headers.CwtClaims?.IssuedAt,
            SignaturePolicyIdentifier = headers.SignaturePolicyIdentifier?.Id.Id.ToString(),
            AlgorithmUses = algorithmUses
        };
    }


    /// <summary>
    /// Builds every <see cref="SigningCertificateReference"/> the signed header set's own signing-certificate-
    /// identification parameters carry — <see cref="CBAdESProtectedHeaders.X5T"/> names the signer's own
    /// certificate directly, and <see cref="CBAdESProtectedHeaders.CertificateDigests"/>'s own first entry does
    /// too (clause 5.2.2), the rest naming the remaining certification path in order.
    /// <see cref="CBAdESProtectedHeaders.X5Chain"/> carries full DER certificates, not digests, so it contributes
    /// no reference here (mirrors the JAdES analogue's identical exclusion). Closes the trivial-PASS hole
    /// <see cref="SigningCertificateIdentification"/> otherwise takes when
    /// <see cref="SignatureFacts.SigningCertificateReferences"/> is left empty (clause 5.2.3.4's last paragraph)
    /// even though the signature itself carries a checkable commitment.
    /// </summary>
    /// <param name="headers">The decoded protected header set.</param>
    /// <param name="pool">The memory pool each reference's copied digest is rented from.</param>
    /// <returns>One reference per resolvable digest, in header-parameter order; empty when none resolve.</returns>
    internal static List<SigningCertificateReference> BuildSigningCertificateReferences(CBAdESProtectedHeaders headers, BaseMemoryPool pool)
    {
        var references = new List<SigningCertificateReference>();

        if(headers.X5T is not null
            && SigningCertificateReferenceBuilder.TryBuildFromDigest(headers.X5T.Digest, isSignerReference: true, pool) is SigningCertificateReference x5t)
        {
            references.Add(x5t);
        }

        if(headers.CertificateDigests is not null)
        {
            for(int i = 0; i < headers.CertificateDigests.Thumbprints.Count; ++i)
            {
                if(SigningCertificateReferenceBuilder.TryBuildFromDigest(headers.CertificateDigests.Thumbprints[i].Digest, isSignerReference: i == 0, pool) is SigningCertificateReference reference)
                {
                    references.Add(reference);
                }
            }
        }

        return references;
    }


    /// <summary>
    /// Maps every PRESENT protected header parameter Table 14 profiles onto <see cref="SignatureAttributeFacts"/>,
    /// one entry per parameter, all <see cref="SignatureAttributeScope.Signed"/> (CB-5.2.2-07's own "protected
    /// headers only" scoping, mirrored by <see cref="CBAdESHeaderRules"/>) — the CAdES facts shape's attribute
    /// analog, <see cref="SignatureAttributeFacts.Identifier"/> the exact Table 14
    /// column-1 name (<see cref="CBAdESBaselineLevelTable"/>'s own row <c>Name</c>) so a Driving Application's
    /// <see cref="SignatureElementsConstraints.MandatedSignedAttributeOids"/>/<c>ForbiddenSignedAttributeOids</c>
    /// can name a CB-AdES header by the specification's own row name.
    /// </summary>
    /// <remarks>
    /// <strong>What does NOT map here (a disclosed vacuity, not a silent one).</strong> <c>uHeaders</c> elements (<c>sigTst</c>,
    /// <c>valData</c>, <c>refs</c>, <c>sigRTst</c>, <c>rfsTst</c>, <c>arcTst</c>, the unsigned <c>x5chain</c>
    /// occurrence, <c>sigPSt</c>, counter signatures) are UNSIGNED — clause 5.2.8.4.1's mandated/forbidden
    /// attribute rule and this row's own <see cref="SignatureAttributeScope.Signed"/> scoping never reach them
    /// through <see cref="SignatureAttributeFacts"/> regardless; they are surfaced instead through
    /// <see cref="SignatureFacts.Timestamps"/>/<see cref="SignatureFacts.EmbeddedCertificates"/>/
    /// <see cref="SignatureFacts.EmbeddedCertificateRevocationLists"/>/<see cref="SignatureFacts.EmbeddedOcspResponses"/>
    /// above, which is where CAdES's own unsigned-attribute facts also end up. <c>counter signature</c> (Table
    /// 14, CB-6.3-30) has no attribute-facts representation at all — CAdES's own shape has no analog for it
    /// either. <c>alg</c>'s own value is separately reported through <see cref="SignatureFacts.AlgorithmUses"/>,
    /// not duplicated here as an attribute.
    /// </remarks>
    /// <param name="headers">The decoded protected header set.</param>
    /// <returns>One entry per present protected header parameter, in Table 14 row order.</returns>
    private static List<SignatureAttributeFacts> CollectAttributes(CBAdESProtectedHeaders headers)
    {
        List<SignatureAttributeFacts> attributes = [];

        if(headers.ContentType is not null)
        {
            attributes.Add(new SignatureAttributeFacts("content type", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.KeyId is not null)
        {
            attributes.Add(new SignatureAttributeFacts("kid", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.X5U is not null)
        {
            attributes.Add(new SignatureAttributeFacts("x5u", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.X5Chain is not null)
        {
            attributes.Add(new SignatureAttributeFacts("x5chain", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.CriticalLabels is not null)
        {
            attributes.Add(new SignatureAttributeFacts("crit", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.CwtClaims is not null)
        {
            attributes.Add(new SignatureAttributeFacts("CWT Claims", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.X5T is not null)
        {
            attributes.Add(new SignatureAttributeFacts("x5t", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.CertificateDigests is not null)
        {
            attributes.Add(new SignatureAttributeFacts("x5ts", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.DetachedObjects is not null)
        {
            attributes.Add(new SignatureAttributeFacts("sigD", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SignerAttributes is not null)
        {
            attributes.Add(new SignatureAttributeFacts("srAts", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SignerCommitments is not null)
        {
            attributes.Add(new SignatureAttributeFacts("srCms", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SignatureProductionPlace is not null)
        {
            attributes.Add(new SignatureAttributeFacts("sigPl", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.SignaturePolicyIdentifier is not null)
        {
            attributes.Add(new SignatureAttributeFacts("sigPId", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        if(headers.PayloadTimestamps is not null)
        {
            attributes.Add(new SignatureAttributeFacts("adoTst", SignatureAttributeScope.Signed, IsWellFormed: true));
        }

        return attributes;
    }


    /// <summary>
    /// Downgrades every attribute <paramref name="violations"/> names to <c>IsWellFormed = false</c> — clause
    /// 5.2.8.4.1's first bullet ("an attribute that is present but malformed... proceed as if the attribute was
    /// not present"), the shared engine's own reading a Table 14 B-B conformance violation satisfies exactly:
    /// the header decoded, but its content or combination violates the profile, so it counts as absent for
    /// <see cref="SignatureAcceptanceValidation"/>'s mandated/forbidden constraint check — never a
    /// <see cref="SignatureFactsStatus.FormatFailure"/> (see <see cref="ExtractAsync"/>'s remarks for the
    /// per-class mapping).
    /// </summary>
    /// <remarks>
    /// <see cref="CBAdESCertificateReferenceTriWayViolation"/> and <see cref="CBAdESCwtClaimsMissingViolation"/>
    /// need no downgrade here: both fire only when the named header is ALREADY absent from
    /// <paramref name="attributes"/>, so there is nothing to mark. <see cref="CBAdESSignaturePolicyStoreGateViolation"/>
    /// names the UNSIGNED <c>sigPSt</c> component, outside this method's protected-header-only scope (a disclosed
    /// residue, see <see cref="CollectAttributes"/>'s own remarks). <see cref="CBAdESMd5DigestAlgorithmViolation"/>
    /// is a cryptographic-constraints concern (Table 14's CB-6.2.1-02), not an attribute-presence one — the
    /// shared engine checks algorithm reliability through <see cref="SignatureFacts.AlgorithmUses"/>/
    /// <see cref="CryptographicConstraints"/>, which this binding does not populate per-digest-site; recorded
    /// here as a residue rather than force-fit into the attribute shape.
    /// </remarks>
    /// <param name="attributes">The attributes <see cref="CollectAttributes"/> produced, downgraded in place.</param>
    /// <param name="violations">Every violation <see cref="CBAdESHeaderRules.Check"/> found.</param>
    private static void DowngradeViolatedAttributes(List<SignatureAttributeFacts> attributes, IReadOnlyList<CBAdESRuleViolation> violations)
    {
        for(int i = 0; i < violations.Count; ++i)
        {
            switch(violations[i])
            {
                case CBAdESContentTypeDetachedObjectsExclusivityViolation:
                    Downgrade(attributes, "content type");
                    Downgrade(attributes, "sigD");
                    break;

                case CBAdESContentTypeCountersignedPayloadViolation:
                    Downgrade(attributes, "content type");
                    break;

                case CBAdESDetachedObjectsCriticalLabelViolation:
                case CBAdESDetachedObjectsAttachedPayloadViolation:
                case CBAdESDetachedObjectsUriMechanismDigestViolation:
                case CBAdESDetachedObjectsUriHashMechanismDigestViolation:
                    Downgrade(attributes, "sigD");
                    break;
            }
        }

        /// <summary>Replaces the named attribute's entry with an <c>IsWellFormed = false</c> copy, when present.</summary>
        /// <param name="candidates">The attributes to search and update in place.</param>
        /// <param name="identifier">The Table 14 column-1 name to downgrade.</param>
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


    /// <summary>Names a COSE <c>alg</c> value, for report readability; unrecognised values report their raw number.</summary>
    /// <param name="algValue">The <c>alg</c> header's integer value.</param>
    /// <returns>A human-readable name.</returns>
    private static string CoseAlgorithmName(int algValue) => algValue switch
    {
        -7 => "ES256",
        -35 => "ES384",
        -36 => "ES512",
        -47 => "ES256K",
        _ => $"COSE alg {algValue}"
    };


    /// <summary>Copies every token of a <see cref="AdESTimestampContainer"/> into classified, freshly-owned <see cref="EmbeddedTimestamp"/> entries.</summary>
    /// <param name="container">The decoded container.</param>
    /// <param name="timestampClass">The class every token in this container is reported as.</param>
    /// <param name="identifier">The UHeaderInstance arm's own name.</param>
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


    /// <summary>Copies a decoded <c>valData</c> component's certificates/CRLs/OCSP responses into freshly-owned carriers. <c>otherCert</c>/<c>otherVals</c> entries are skipped — a declared extensibility placeholder, not DER X.509/CRL/OCSP.</summary>
    /// <param name="validationData">The decoded component.</param>
    /// <param name="certificates">Collects every <c>xVals</c>/<c>x509Cert</c> entry.</param>
    /// <param name="revocationLists">Collects every <c>rVals</c>/<c>crlVals</c> entry.</param>
    /// <param name="ocspResponses">Collects every <c>rVals</c>/<c>ocspVals</c> entry.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    private static void CopyValidationData(
        CBAdESValidationData validationData, List<PkiCertificateMemory> certificates, List<PkiCertificateMemory> revocationLists, List<PkiCertificateMemory> ocspResponses, BaseMemoryPool pool)
    {
        if(validationData.CertificateValues is not null)
        {
            for(int i = 0; i < validationData.CertificateValues.Count; ++i)
            {
                if(validationData.CertificateValues[i] is CBAdESX509Certificate x509)
                {
                    certificates.Add(CopyBytes(x509.Certificate.Val, PkiCertificateTags.X509Certificate, pool));
                }
            }
        }

        CBAdESRevocationValues? revocationValues = validationData.RevocationValues;
        if(revocationValues?.CrlValues is not null)
        {
            for(int i = 0; i < revocationValues.CrlValues.Count; ++i)
            {
                revocationLists.Add(CopyBytes(revocationValues.CrlValues[i].Val, PkiCertificateTags.X509Crl, pool));
            }
        }

        if(revocationValues?.OcspValues is not null)
        {
            for(int i = 0; i < revocationValues.OcspValues.Count; ++i)
            {
                ocspResponses.Add(CopyBytes(revocationValues.OcspValues[i].Val, PkiCertificateTags.OcspResponse, pool));
            }
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
    /// Performs the cryptographic checks of clause 5.2.7.4 over a CB-AdES signature — the
    /// <see cref="VerifySignatureCryptographyAsyncDelegate"/> half of <see cref="CreateSeam"/>'s bundle.
    /// Re-decodes <see cref="SignatureFacts.SignedDataObject"/> independently (mirroring
    /// <see cref="CAdESSignatureFacts.VerifyCryptographyAsync"/>'s own re-parse discipline) to recover the exact
    /// raw <c>body_protected</c> bytes and the signature carrier <see cref="Cose"/> needs — neither of which
    /// <see cref="SignatureFacts"/> carries, since RFC 9052 §4.4 requires the Sig_structure be built from the
    /// EXACT wire bytes, never a re-encoding of the decoded model.
    /// </summary>
    /// <param name="context">The signature's facts, the signing certificate, and the optional chain and documents.</param>
    /// <param name="parse">The injected CB-AdES parse seam.</param>
    /// <param name="buildSigStructure">Builds the Sig_structure for verification.</param>
    /// <param name="pool">The memory pool the re-parse and the public-key carrier are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome in the vocabulary of Table 15 of clause 5.2.7.3 — see the type remarks for the mapping.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "message shares parseResult's own RawProtectedHeader/Signature carriers verbatim -- " +
            "neither is disposed by this method (the enclosing 'using(parseResult)' disposes both once this " +
            "method returns) -- mirroring CBAdESSignatureValidation.VerifyStructureAndSignatureAsync's own " +
            "identical CA2000 justification for the identical shape. Roslyn tracks the locally-constructed " +
            "CoseSign1Message itself, not the fact that its constituent IDisposable members are owned and " +
            "disposed one level up by parseResult.")]
    private static async ValueTask<SignatureCryptographicVerification> VerifyCryptographyAsync(
        SignatureCryptographicVerificationContext context,
        ParseCBAdESSign1Delegate parse,
        BuildSigStructureDelegate buildSigStructure,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(context.Signature.SignedDataObject is not SensitiveMemory signedDataObject)
        {
            return SignedDataNotFound("The signed data object of a CB-AdES signature has to be the COSE_Sign1 wire bytes.");
        }

        CBAdESSign1ParseResult parseResult;
        try
        {
            parseResult = parse(signedDataObject.AsReadOnlyMemory(), pool);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            return SignedDataNotFound($"The COSE_Sign1 wire bytes did not re-parse: {ex.Message}");
        }

        using(parseResult)
        {
            if(!parseResult.IsSuccess || parseResult.RawProtectedHeader is null || parseResult.Signature is null)
            {
                return SignedDataNotFound("The COSE_Sign1 wire bytes did not re-parse.");
            }

            ReadOnlyMemory<byte> payload;
            if(parseResult.PayloadIsPresent)
            {
                payload = parseResult.Payload;
            }
            else if(context.SignerDocuments.Count > 0 && context.SignerDocuments[0].Content is SignedContentMemory detached)
            {
                payload = detached.AsReadOnlyMemory();
            }
            else
            {
                //Clause 5.2.7.4 step 1): the signed data items could not be obtained.
                return SignedDataNotFound("The COSE Payload is detached (clause 4.5) and no Signer's Document was supplied.");
            }

            if(!EllipticCurveSigningCertificateResolution.TryResolve(context.SigningCertificate, out CryptoAlgorithm algorithm, out ReadOnlyMemory<byte> publicKeyPoint))
            {
                //An unsupported/unparseable signing certificate means no
                //verification could even be ATTEMPTED, which is the cannot-process case CryptographicVerification's
                //own default arm exists for (NotVerified maps to Table 15's INDETERMINATE/CUSTOM, mirroring the
                //CAdES binding's own SignedDataNotFound precedent for "nothing was checked") -- never
                //SignatureValueFailure, which Table 15 reserves for a signature value that WAS checked and did
                //not verify (TOTAL-FAILED).
                return NotVerified("This binding verifies only elliptic-curve signing certificates (P-256/P-384/P-521/secp256k1) that parse as well-formed X.509.");
            }

            using PublicKeyMemory publicKey = ToPublicKeyMemory(publicKeyPoint, algorithm, pool);
            var message = new CoseSign1Message(parseResult.RawProtectedHeader, null, payload, parseResult.Signature);

            try
            {
                bool isValid = await Cose.VerifyAsync(message, buildSigStructure, publicKey, cancellationToken: cancellationToken).ConfigureAwait(false);

                return isValid
                    ? new SignatureCryptographicVerification { Outcome = SignatureCryptographicOutcome.Verified, SigningCertificate = context.SigningCertificate }
                    : SignatureValueFailure("The COSE signature value does not verify over the Sig_structure (RFC 9052 §4.4).");
            }
            catch(Exception ex) when(ex is System.Security.Cryptography.CryptographicException)
            {
                return SignatureValueFailure($"The registered verification function threw over the resolved Sig_structure/signature pair: {ex.Message}");
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


    /// <summary>Wraps a raw elliptic-curve public-key point into a pool-owned, correctly-tagged <see cref="PublicKeyMemory"/>.</summary>
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


    /// <summary>Reports whether an exception reflects hostile/malformed wire input a parse seam fails closed on, mirroring <see cref="CBAdESSignatureValidation"/>'s own predicate of the identical name/purpose.</summary>
    /// <param name="exception">The exception to classify.</param>
    /// <returns><see langword="true"/> when the exception is a routine parse-failure signal.</returns>
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is InvalidOperationException or ArgumentException
            or IndexOutOfRangeException or OverflowException or FormatException;
}
