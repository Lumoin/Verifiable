using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The CAdES binding of the format-facts seam: it reads a CMS SignedData
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652">RFC 5652</see>) carrying the CAdES signed and unsigned
/// attributes of ETSI EN 319 122-1 and presents it as the format-neutral <see cref="SignatureFacts"/> the
/// building blocks of clause 5.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> validate, and performs the cryptographic checks of clause 5.2.7.4 over the
/// CMS encoding.
/// </summary>
/// <remarks>
/// <para>
/// This is the first binding of the seam and the shape the later ones follow: nothing here reaches into the
/// validation algorithm, and nothing in the validation algorithm reaches into CMS. The signature verification
/// itself is delegated to the registered <see cref="VerifyCmsSignedDataDelegate"/> — the same CMS core
/// <see cref="CAdESVerification"/> and eMRTD Passive Authentication use — and the CAdES rules are applied over
/// the facts by the building blocks, not here.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> The Signed Data Object arrives from a network location or a
/// document, so the DER is read exactly as <see cref="ManagedCertificate"/> reads a certificate: bounds-checked
/// <see cref="AsnReader"/> cursors under <see cref="AsnEncodingRules.DER"/>, straight-line walks with no
/// recursion, and every structure closed. A structure this binding cannot parse yields
/// <see cref="SignatureFactsStatus.FormatFailure"/>, never an exception; an individual attribute this binding
/// cannot decode is reported as present-but-malformed, which clause 5.2.8.4.1 requires the SVA to treat as
/// absent.
/// </para>
/// <para>
/// <strong>Encapsulated content only.</strong> The shipped <see cref="VerifyCmsSignedDataDelegate"/> verifies a
/// SignedData that encapsulates its content, so a detached CAdES signature reports
/// <see cref="SignatureCryptographicOutcome.SignedDataNotFound"/> — the clause 5.2.7.4 step 1) outcome for
/// signed data that cannot be obtained — rather than silently passing.
/// </para>
/// </remarks>
public static class CAdESSignatureFacts
{
    /// <summary>
    /// The largest number of time-stamp attributes this binding surfaces from one signature. The number of
    /// unsigned attributes a CMS SignerInfo may carry is unbounded and every one of them costs the validation
    /// process a complete clause 5.4 run, so the count an attacker chooses is bounded here, at the parse
    /// boundary, per the hostile-input discipline the rest of this binding follows.
    /// </summary>
    private const int MaximumTimestampAttributes = 64;

    /// <summary>The largest number of certificates this binding surfaces from one signature, bounding both the chain building of clause 5.2.6.4 step 2) and the reference matching of clause 5.6.2.3 step 4).</summary>
    private const int MaximumEmbeddedCertificates = 256;

    /// <summary>The largest number of revocation data objects of each kind this binding surfaces from one signature.</summary>
    private const int MaximumEmbeddedRevocationObjects = 256;

    /// <summary>The largest number of signing certificate references this binding surfaces, bounding the per-reference digest work of clause 5.6.2.3 step 4).</summary>
    private const int MaximumSigningCertificateReferences = 16;

    /// <summary>The id-signedData content type (RFC 5652 §5.1).</summary>
    private const string SignedDataOid = "1.2.840.113549.1.7.2";

    /// <summary>The id-data content type (RFC 5652 §4), the default encapsulated content type.</summary>
    private const string DataOid = "1.2.840.113549.1.7.1";

    /// <summary>The content-type signed attribute (RFC 5652 §11.1).</summary>
    public static string ContentTypeAttributeOid => "1.2.840.113549.1.9.3";

    /// <summary>The message-digest signed attribute (RFC 5652 §11.2).</summary>
    public static string MessageDigestAttributeOid => "1.2.840.113549.1.9.4";

    /// <summary>The signing-time signed attribute (RFC 5652 §11.3), which carries the claimed signing time of clause 4.2.5.8.</summary>
    public static string SigningTimeAttributeOid => "1.2.840.113549.1.9.5";

    /// <summary>The signing-certificate signed attribute (ESS, RFC 2634 §5.4), whose certificate hashes are SHA-1.</summary>
    public static string SigningCertificateAttributeOid => "1.2.840.113549.1.9.16.2.12";

    /// <summary>The signing-certificate-v2 signed attribute (ESS, RFC 5035 §3).</summary>
    public static string SigningCertificateV2AttributeOid => "1.2.840.113549.1.9.16.2.47";

    /// <summary>The signature-policy-identifier signed attribute, which carries the identifier of clause 4.2.5.3.</summary>
    public static string SignaturePolicyIdentifierAttributeOid => "1.2.840.113549.1.9.16.2.15";

    /// <summary>The content-timestamp signed attribute — a time-stamp on a Signed Data Object (clause 5.2.8.4.2.5).</summary>
    public static string ContentTimestampAttributeOid => "1.2.840.113549.1.9.16.2.20";

    /// <summary>The signature-time-stamp-token unsigned attribute (CAdES-T), whose token time-stamps the signature value.</summary>
    public static string SignatureTimestampAttributeOid => "1.2.840.113549.1.9.16.2.14";

    /// <summary>The certificate-values unsigned attribute, carrying certificates for long-term validation.</summary>
    public static string CertificateValuesAttributeOid => "1.2.840.113549.1.9.16.2.23";

    /// <summary>The revocation-values unsigned attribute, carrying CRLs and OCSP responses for long-term validation.</summary>
    public static string RevocationValuesAttributeOid => "1.2.840.113549.1.9.16.2.24";

    /// <summary>The escTimeStamp unsigned attribute — a time-stamp over the signature and its validation data references.</summary>
    public static string EscTimestampAttributeOid => "1.2.840.113549.1.9.16.2.25";

    /// <summary>The certCRLTimestamp unsigned attribute — a time-stamp over the validation data references alone.</summary>
    public static string CertificateAndCrlTimestampAttributeOid => "1.2.840.113549.1.9.16.2.26";

    /// <summary>The archive-timestamp-v2 unsigned attribute.</summary>
    public static string ArchiveTimestampV2AttributeOid => "1.2.840.113549.1.9.16.2.48";

    /// <summary>The archive-timestamp-v3 unsigned attribute of ETSI EN 319 122-1.</summary>
    public static string ArchiveTimestampV3AttributeOid => "0.4.0.1733.2.4";


    /// <summary>
    /// The seam bundle a caller hands the building blocks to validate a CAdES signature.
    /// </summary>
    public static SignatureFormatSeam Seam { get; } = new()
    {
        Format = SignatureFormatIdentifier.CAdES,
        ExtractFacts = ExtractAsync,
        VerifyCryptography = VerifyCryptographyAsync,
        StateTimestampCoverage = StateTimestampCoverageAsync
    };


    /// <summary>
    /// States the octets an embedded time-stamp's <c>messageImprint</c> is computed over — the
    /// <see cref="StateTimestampCoverageAsyncDelegate"/> implementation of the bundle in <see cref="Seam"/>.
    /// </summary>
    /// <param name="context">The signature and the time-stamp.</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The octets, which the caller disposes, or <see langword="null"/> when this binding cannot state them.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// A content-timestamp is computed over the octets of the encapsulated content and a signature time-stamp
    /// over the <c>SignerInfo.signature</c> octets, which are both carriers the extracted facts already hold.
    /// </para>
    /// <para>
    /// <strong>Archive and validation-data time-stamps are not stated.</strong> Their message imprints are
    /// computed over the concatenation ETSI EN 319 122-1 defines for <c>archive-time-stamp-v3</c> (and its
    /// predecessors), which reaches encoded fields of the CMS structure this binding does not reassemble and, for
    /// the v3 attribute, the <c>ats-hash-index-v3</c> attribute that names which of them are covered. Until that
    /// computation is implemented, this binding states nothing for those classes, and the POE extraction building
    /// block therefore derives no proof of existence from such a token unless the caller's validation constraints
    /// explicitly accept a coverage this binding cannot verify.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned carrier transfers to the caller, which disposes it once it has verified the message imprint against it.")]
    public static ValueTask<SignedContentMemory?> StateTimestampCoverageAsync(
        TimestampCoverageContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        SignedContentMemory? covered = context.Timestamp.Class switch
        {
            SignatureTimestampClass.ContentTimestamp => context.Signature.SignedContent,
            SignatureTimestampClass.SignatureTimestamp => context.Signature.SignatureValue,
            _ => null
        };

        return ValueTask.FromResult(covered is null ? null : SignedContentMemory.FromBytes(covered.AsReadOnlyMemory().Span, pool));
    }


    /// <summary>
    /// Extracts the facts of a CAdES signature — the <see cref="ExtractSignatureFactsAsyncDelegate"/>
    /// implementation of the bundle in <see cref="Seam"/>.
    /// </summary>
    /// <param name="context">The Signed Data Object and any caller-supplied Signer's Documents.</param>
    /// <param name="pool">The memory pool every carrier the returned facts own is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The extracted facts, or a <see cref="SignatureFactsStatus.FormatFailure"/> when the bytes are not a processable CMS SignedData. The caller disposes them.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the extracted facts transfers to the caller, which disposes them once the validation run is complete; every failure path inside the extraction releases what it built before returning.")]
    public static ValueTask<SignatureFacts> ExtractAsync(
        SignatureFactsExtractionContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(Extract(context, pool));
    }


    /// <summary>
    /// Performs the cryptographic checks of clause 5.2.7.4 over a CAdES signature — the
    /// <see cref="VerifySignatureCryptographyAsyncDelegate"/> implementation of the bundle in
    /// <see cref="Seam"/>.
    /// </summary>
    /// <param name="context">The signature's facts, the signing certificate, and the optional chain and documents.</param>
    /// <param name="pool">The memory pool the content digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome in the vocabulary of Table 15 of clause 5.2.7.3.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no <see cref="VerifyCmsSignedDataDelegate"/> or no <see cref="ComputeDigestDelegate"/> has been registered — a composition fault of the host, not an outcome of the signature.</exception>
    /// <remarks>
    /// Step 2) of clause 5.2.7.4 (the integrity of the signed data items) and step 3) (the signature value) are
    /// separated deliberately: the CMS core reports both as one failure, but Table 15 requires
    /// <c>HASH_FAILURE</c> and <c>SIG_CRYPTO_FAILURE</c> to be distinguished. The <c>message-digest</c> signed
    /// attribute is therefore checked against the encapsulated content here, before the CMS core runs, so a
    /// content that does not match its own digest attribute is reported as a hash failure and only a signature
    /// value that fails under an otherwise-consistent structure is reported as a cryptographic failure.
    /// </remarks>
    public static async ValueTask<SignatureCryptographicVerification> VerifyCryptographyAsync(
        SignatureCryptographicVerificationContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        if(context.Signature.SignedDataObject is not CmsSignedData signedData)
        {
            return new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.SignedDataNotFound,
                FailingObjectIdentifiers = [context.Signature.SignedContentIdentifier],
                Reason = "The signed data object of a CAdES signature has to be a CMS SignedData carrier."
            };
        }

        if(context.Signature.SignedContent is null)
        {
            //Clause 5.2.7.4 step 1): the signed data items could not be obtained. A detached CAdES signature
            //reaches this branch because the shipped CMS verification seam verifies encapsulated content only.
            return new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.SignedDataNotFound,
                FailingObjectIdentifiers = [context.Signature.SignedContentIdentifier],
                Reason = "The CMS SignedData encapsulates no content and no signer's document was supplied."
            };
        }

        CmsStructure structure;
        try
        {
            structure = ParseCms(signedData.AsReadOnlyMemory());
        }
        catch(AsnContentException)
        {
            return new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.SignedDataNotFound,
                FailingObjectIdentifiers = [context.Signature.SignedContentIdentifier],
                Reason = "The CMS SignedData is not well-formed DER."
            };
        }

        //Clause 5.2.7.4 step 2): the integrity of the signed data items, which for CMS is the message-digest
        //signed attribute over the encapsulated content (RFC 5652 §11.2).
        SignatureCryptographicVerification? hashFailure = await CheckMessageDigestAsync(
            structure, context.Signature, pool, cancellationToken).ConfigureAwait(false);
        if(hashFailure is not null)
        {
            return hashFailure;
        }

        VerifyCmsSignedDataDelegate verifyCms = CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate))
            ?? throw new InvalidOperationException("No VerifyCmsSignedDataDelegate has been registered.");

        try
        {
            //Clause 5.2.7.4 step 3): the signature value under the signing certificate's public key.
            using CmsVerifiedContent verified = await verifyCms(signedData, pool, cancellationToken).ConfigureAwait(false);
            if(!verified.SignerCertificate.Equals(context.SigningCertificate))
            {
                //The certificate the CMS core verified under is not the one the identification building block
                //settled on, so nothing has been verified about the signature the engine is validating.
                return new SignatureCryptographicVerification
                {
                    Outcome = SignatureCryptographicOutcome.SignatureValueFailure,
                    Reason = "The certificate the CMS signature verified under is not the identified signing certificate."
                };
            }

            return new SignatureCryptographicVerification { Outcome = SignatureCryptographicOutcome.Verified };
        }
        catch(CryptographicException)
        {
            return new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.SignatureValueFailure,
                Reason = "The CMS signature over the signed attributes did not verify."
            };
        }
    }


    /// <summary>
    /// Checks the <c>message-digest</c> signed attribute against the encapsulated content, which is what
    /// "the integrity of the signed data items" means for CMS.
    /// </summary>
    /// <param name="structure">The parsed CMS structure.</param>
    /// <param name="facts">The signature's facts, holding the content.</param>
    /// <param name="pool">The memory pool the computed digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The hash-failure verification to return, or <see langword="null"/> when the content matches its digest attribute.</returns>
    private static async ValueTask<SignatureCryptographicVerification?> CheckMessageDigestAsync(
        CmsStructure structure,
        SignatureFacts facts,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> declaredDigest = default;
        bool hasDeclaredDigest = false;
        for(int i = 0; i < structure.Signer.SignedAttributes.Count; ++i)
        {
            if(string.Equals(structure.Signer.SignedAttributes[i].Oid, MessageDigestAttributeOid, StringComparison.Ordinal))
            {
                try
                {
                    var reader = new AsnReader(structure.Signer.SignedAttributes[i].Value, AsnEncodingRules.DER);
                    declaredDigest = reader.ReadOctetString();
                    reader.ThrowIfNotEmpty();
                    hasDeclaredDigest = true;
                }
                catch(AsnContentException)
                {
                    hasDeclaredDigest = false;
                }

                break;
            }
        }

        if(!hasDeclaredDigest)
        {
            //Without the attribute the signature does not bind the content at all; the CMS core would reject it
            //too, but reporting the hash failure here keeps Table 15's distinction exact.
            return new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.HashFailure,
                FailingObjectIdentifiers = [facts.SignedContentIdentifier],
                Reason = "The CMS SignerInfo carries no well-formed message-digest signed attribute."
            };
        }

        PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(structure.Signer.DigestAlgorithmOid);
        if(algorithm is null)
        {
            return new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.HashFailure,
                FailingObjectIdentifiers = [facts.SignedContentIdentifier],
                Reason = "The CMS SignerInfo names a digest algorithm this library cannot compute."
            };
        }

        using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
            facts.SignedContent!.AsReadOnlyMemory(), algorithm.Value.OutputByteLength, algorithm.Value.DigestTag, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return computed.AsReadOnlySpan().SequenceEqual(declaredDigest.Span)
            ? null
            : new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.HashFailure,
                FailingObjectIdentifiers = [facts.SignedContentIdentifier],
                Reason = "The encapsulated content does not match the message-digest signed attribute."
            };
    }


    /// <summary>
    /// Reads a CMS SignedData and assembles the facts, releasing every carrier already built when a later step
    /// fails.
    /// </summary>
    /// <param name="context">The extraction context.</param>
    /// <param name="pool">The memory pool the owned carriers are rented from.</param>
    /// <returns>The facts, or a format failure.</returns>
    private static SignatureFacts Extract(SignatureFactsExtractionContext context, MemoryPool<byte> pool)
    {
        if(context.SignedDataObject is not CmsSignedData signedData)
        {
            return SignatureFacts.FormatFailure(
                SignatureFormatIdentifier.CAdES,
                "The signed data object of a CAdES signature has to be a CMS SignedData carrier.");
        }

        List<PkiCertificateMemory> certificates = [];
        List<PkiCertificateMemory> revocationLists = [];
        List<PkiCertificateMemory> ocspResponses = [];
        List<EmbeddedTimestamp> timestamps = [];
        List<SigningCertificateReference> signingCertificateReferences = [];
        SignedContentMemory? signedContent = null;
        SignedContentMemory? signatureValue = null;
        try
        {
            CmsStructure structure = ParseCms(signedData.AsReadOnlyMemory());
            signatureValue = SignedContentMemory.FromBytes(structure.Signer.Signature.Span, pool);

            for(int i = 0; i < structure.Certificates.Count && certificates.Count < MaximumEmbeddedCertificates; ++i)
            {
                certificates.Add(Copy(structure.Certificates[i], PkiCertificateTags.X509Certificate, pool));
            }

            for(int i = 0; i < structure.CertificateRevocationLists.Count && revocationLists.Count < MaximumEmbeddedRevocationObjects; ++i)
            {
                revocationLists.Add(Copy(structure.CertificateRevocationLists[i], PkiCertificateTags.X509Crl, pool));
            }

            for(int i = 0; i < structure.OcspResponses.Count && ocspResponses.Count < MaximumEmbeddedRevocationObjects; ++i)
            {
                ocspResponses.Add(Copy(structure.OcspResponses[i], PkiCertificateTags.OcspResponse, pool));
            }

            if(structure.HasContent)
            {
                signedContent = SignedContentMemory.FromBytes(structure.Content.Span, pool);
            }

            List<SignatureAttributeFacts> attributes = [];
            List<AlgorithmUse> algorithmUses = [];
            DateTimeOffset? claimedSigningTime = null;
            string? signaturePolicyIdentifier = null;

            CollectAttributes(
                structure.Signer.SignedAttributes, SignatureAttributeScope.Signed, attributes, timestamps,
                signingCertificateReferences, certificates, revocationLists, ocspResponses, pool,
                ref claimedSigningTime, ref signaturePolicyIdentifier);
            CollectAttributes(
                structure.Signer.UnsignedAttributes, SignatureAttributeScope.Unsigned, attributes, timestamps,
                signingCertificateReferences, certificates, revocationLists, ocspResponses, pool,
                ref claimedSigningTime, ref signaturePolicyIdentifier);

            PkiCertificateMemory? signingCertificate = MatchSigner(certificates, structure.Signer);
            algorithmUses.Add(new AlgorithmUse(
                new AlgorithmIdentifier(structure.Signer.DigestAlgorithmOid), KeySizeBits: null, SignatureMaterialIdentifiers.SignedAttributesDigest));
            algorithmUses.Add(new AlgorithmUse(
                new AlgorithmIdentifier(structure.Signer.SignatureAlgorithmOid), KeySizeBits(signingCertificate), SignatureMaterialIdentifiers.SignatureValue));

            return new SignatureFacts
            {
                Status = SignatureFactsStatus.Extracted,
                Format = SignatureFormatIdentifier.CAdES,
                SignedDataObject = signedData,
                SignedContentIdentifier = structure.ContentType,
                SignedContent = signedContent,
                SignatureValue = signatureValue,
                Attributes = attributes,
                SigningCertificateReferences = signingCertificateReferences,
                SigningCertificate = signingCertificate,
                EmbeddedCertificates = certificates,
                EmbeddedCertificateRevocationLists = revocationLists,
                EmbeddedOcspResponses = ocspResponses,
                Timestamps = timestamps,
                ClaimedSigningTime = claimedSigningTime,
                SignaturePolicyIdentifier = signaturePolicyIdentifier,
                AlgorithmUses = algorithmUses
            };
        }
        catch(AsnContentException exception)
        {
            Release(signedContent, signatureValue, certificates, revocationLists, ocspResponses, timestamps, signingCertificateReferences);

            return SignatureFacts.FormatFailure(SignatureFormatIdentifier.CAdES, exception.Message);
        }

        //Releases every carrier built before the failure, so a format failure leaks no pooled memory.
        static void Release(
            SignedContentMemory? signedContent,
            SignedContentMemory? signatureValue,
            List<PkiCertificateMemory> certificates,
            List<PkiCertificateMemory> revocationLists,
            List<PkiCertificateMemory> ocspResponses,
            List<EmbeddedTimestamp> timestamps,
            List<SigningCertificateReference> signingCertificateReferences)
        {
            signedContent?.Dispose();
            signatureValue?.Dispose();
            for(int i = 0; i < certificates.Count; ++i)
            {
                certificates[i].Dispose();
            }

            for(int i = 0; i < revocationLists.Count; ++i)
            {
                revocationLists[i].Dispose();
            }

            for(int i = 0; i < ocspResponses.Count; ++i)
            {
                ocspResponses[i].Dispose();
            }

            for(int i = 0; i < timestamps.Count; ++i)
            {
                timestamps[i].Token.Dispose();
            }

            for(int i = 0; i < signingCertificateReferences.Count; ++i)
            {
                signingCertificateReferences[i].CertificateDigest?.Dispose();
            }
        }
    }


    /// <summary>
    /// Walks one attribute set, recording every attribute's identity and decoding the CAdES attributes the
    /// validation algorithm reasons over. An attribute whose value does not decode is recorded as
    /// present-but-malformed and contributes nothing, per clause 5.2.8.4.1's first bullet.
    /// </summary>
    /// <param name="source">The attributes to walk.</param>
    /// <param name="scope">Whether the signature covers them.</param>
    /// <param name="attributes">The list every attribute's identity is appended to.</param>
    /// <param name="timestamps">The list decoded time-stamp tokens are appended to.</param>
    /// <param name="references">The list decoded signing certificate references are appended to.</param>
    /// <param name="certificates">The list certificates carried by validation-data attributes are appended to.</param>
    /// <param name="revocationLists">The list CRLs carried by validation-data attributes are appended to.</param>
    /// <param name="ocspResponses">The list OCSP responses carried by validation-data attributes are appended to.</param>
    /// <param name="pool">The memory pool the appended carriers are rented from.</param>
    /// <param name="claimedSigningTime">Set to the first well-formed signing-time attribute's value.</param>
    /// <param name="signaturePolicyIdentifier">Set to the first well-formed signature-policy-identifier attribute's object identifier.</param>
    private static void CollectAttributes(
        IReadOnlyList<CmsAttributeStructure> source,
        SignatureAttributeScope scope,
        List<SignatureAttributeFacts> attributes,
        List<EmbeddedTimestamp> timestamps,
        List<SigningCertificateReference> references,
        List<PkiCertificateMemory> certificates,
        List<PkiCertificateMemory> revocationLists,
        List<PkiCertificateMemory> ocspResponses,
        MemoryPool<byte> pool,
        ref DateTimeOffset? claimedSigningTime,
        ref string? signaturePolicyIdentifier)
    {
        for(int i = 0; i < source.Count; ++i)
        {
            CmsAttributeStructure attribute = source[i];
            bool isWellFormed = true;
            try
            {
                SignatureTimestampClass timestampClass = ClassifyTimestamp(attribute.Oid);
                if(timestampClass != SignatureTimestampClass.Unknown)
                {
                    if(!IsPermittedScope(timestampClass, scope))
                    {
                        //ETSI EN 319 122-1 places the content-timestamp attribute among the signed attributes and
                        //every other time-stamp attribute among the unsigned ones. A token carried in the other
                        //set is not the attribute its object identifier claims: honouring it would let anyone who
                        //can append an unsigned attribute state a content time-stamp the signer never made, and
                        //the conclusions of steps 4) and 6) of clause 5.3.4 and step 4)e) of clause 5.5.4 turn on
                        //content time-stamps. Clause 5.2.8.4.1 has a present-but-malformed attribute treated as
                        //absent, which is what this reports.
                        isWellFormed = false;
                    }
                    else if(timestamps.Count < MaximumTimestampAttributes)
                    {
                        timestamps.Add(new EmbeddedTimestamp
                        {
                            Class = timestampClass,
                            Identifier = attribute.Oid,
                            Token = Copy(attribute.Value, PkiCertificateTags.TimestampToken, pool),
                            Ordinal = CountOfClass(timestamps, timestampClass)
                        });
                    }
                }
                else if(string.Equals(attribute.Oid, SigningTimeAttributeOid, StringComparison.Ordinal))
                {
                    claimedSigningTime ??= ReadSigningTime(attribute.Value);
                }
                else if(string.Equals(attribute.Oid, SigningCertificateV2AttributeOid, StringComparison.Ordinal))
                {
                    ReadEssCertificateReferences(attribute.Value, version2: true, references, pool);
                }
                else if(string.Equals(attribute.Oid, SigningCertificateAttributeOid, StringComparison.Ordinal))
                {
                    ReadEssCertificateReferences(attribute.Value, version2: false, references, pool);
                }
                else if(string.Equals(attribute.Oid, SignaturePolicyIdentifierAttributeOid, StringComparison.Ordinal))
                {
                    signaturePolicyIdentifier ??= ReadSignaturePolicyIdentifier(attribute.Value);
                }
                else if(string.Equals(attribute.Oid, CertificateValuesAttributeOid, StringComparison.Ordinal))
                {
                    ReadCertificateValues(attribute.Value, certificates, pool);
                }
                else if(string.Equals(attribute.Oid, RevocationValuesAttributeOid, StringComparison.Ordinal))
                {
                    ReadRevocationValues(attribute.Value, revocationLists, ocspResponses, pool);
                }
            }
            catch(AsnContentException)
            {
                isWellFormed = false;
            }

            attributes.Add(new SignatureAttributeFacts(attribute.Oid, scope, isWellFormed));
        }
    }


    /// <summary>
    /// Classifies a CAdES attribute that carries a time-stamp token.
    /// </summary>
    /// <param name="attributeOid">The attribute's object identifier.</param>
    /// <returns>The class, or <see cref="SignatureTimestampClass.Unknown"/> when the attribute carries no token.</returns>
    private static SignatureTimestampClass ClassifyTimestamp(string attributeOid) => attributeOid switch
    {
        "1.2.840.113549.1.9.16.2.20" => SignatureTimestampClass.ContentTimestamp,
        "1.2.840.113549.1.9.16.2.14" => SignatureTimestampClass.SignatureTimestamp,
        "1.2.840.113549.1.9.16.2.25" => SignatureTimestampClass.ValidationDataTimestamp,
        "1.2.840.113549.1.9.16.2.26" => SignatureTimestampClass.ValidationDataTimestamp,
        "1.2.840.113549.1.9.16.2.48" => SignatureTimestampClass.ArchiveTimestamp,
        "0.4.0.1733.2.4" => SignatureTimestampClass.ArchiveTimestamp,
        _ => SignatureTimestampClass.Unknown
    };


    /// <summary>
    /// Decides whether a time-stamp attribute of one class may appear in an attribute set of one scope, per the
    /// attribute definitions of ETSI EN 319 122-1: the content-timestamp attribute is a signed attribute, and the
    /// signature time-stamp, validation-data time-stamp and archive time-stamp attributes are unsigned ones.
    /// </summary>
    /// <param name="timestampClass">The class the attribute's object identifier names.</param>
    /// <param name="scope">The set the attribute was found in.</param>
    /// <returns><see langword="true"/> when the attribute is in the set its definition places it in.</returns>
    private static bool IsPermittedScope(SignatureTimestampClass timestampClass, SignatureAttributeScope scope) => timestampClass switch
    {
        SignatureTimestampClass.ContentTimestamp => scope == SignatureAttributeScope.Signed,
        SignatureTimestampClass.SignatureTimestamp => scope == SignatureAttributeScope.Unsigned,
        SignatureTimestampClass.ValidationDataTimestamp => scope == SignatureAttributeScope.Unsigned,
        SignatureTimestampClass.ArchiveTimestamp => scope == SignatureAttributeScope.Unsigned,
        _ => false
    };


    /// <summary>
    /// Counts the tokens of one class already collected, which is the next token's ordinal.
    /// </summary>
    /// <param name="timestamps">The tokens collected so far.</param>
    /// <param name="timestampClass">The class to count.</param>
    /// <returns>The count.</returns>
    private static int CountOfClass(List<EmbeddedTimestamp> timestamps, SignatureTimestampClass timestampClass)
    {
        int count = 0;
        for(int i = 0; i < timestamps.Count; ++i)
        {
            if(timestamps[i].Class == timestampClass)
            {
                ++count;
            }
        }

        return count;
    }


    /// <summary>
    /// Reads a signing-time attribute value (a <c>UTCTime</c> or a <c>GeneralizedTime</c>, RFC 5652 §11.3).
    /// </summary>
    /// <param name="value">The DER-encoded attribute value.</param>
    /// <returns>The claimed signing time.</returns>
    /// <exception cref="AsnContentException">Thrown when the value is neither time form.</exception>
    private static DateTimeOffset ReadSigningTime(ReadOnlyMemory<byte> value)
    {
        var reader = new AsnReader(value, AsnEncodingRules.DER);
        Asn1Tag tag = reader.PeekTag();
        DateTimeOffset signingTime = tag == new Asn1Tag(UniversalTagNumber.UtcTime)
            ? reader.ReadUtcTime()
            : tag == new Asn1Tag(UniversalTagNumber.GeneralizedTime)
                ? reader.ReadGeneralizedTime()
                : throw new AsnContentException("A signing-time attribute must be a UTCTime or a GeneralizedTime (RFC 5652 §11.3).");
        reader.ThrowIfNotEmpty();

        return signingTime;
    }


    /// <summary>
    /// Reads a signature-policy-identifier attribute value, returning the policy object identifier of its
    /// <c>signaturePolicyId</c> alternative.
    /// </summary>
    /// <param name="value">The DER-encoded attribute value.</param>
    /// <returns>The policy object identifier, or <see langword="null"/> for the <c>signaturePolicyImplied</c> alternative.</returns>
    /// <exception cref="AsnContentException">Thrown when the value is not a well-formed <c>SignaturePolicyIdentifier</c>.</exception>
    private static string? ReadSignaturePolicyIdentifier(ReadOnlyMemory<byte> value)
    {
        var reader = new AsnReader(value, AsnEncodingRules.DER);
        if(reader.PeekTag() != new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true))
        {
            //signaturePolicyImplied [0] NULL: the signature declares a policy without naming it.
            _ = reader.ReadEncodedValue();
            reader.ThrowIfNotEmpty();

            return null;
        }

        AsnReader policyId = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        return policyId.ReadObjectIdentifier();
    }


    /// <summary>
    /// Reads an ESS signing certificate attribute value, appending one reference per certificate identifier.
    /// </summary>
    /// <param name="value">The DER-encoded attribute value.</param>
    /// <param name="version2">Whether the attribute is the v2 form, whose identifiers name their own hash algorithm.</param>
    /// <param name="references">The list the references are appended to.</param>
    /// <param name="pool">The memory pool each reference's digest carrier is rented from.</param>
    /// <exception cref="AsnContentException">Thrown when the value is not a well-formed ESS signing certificate attribute.</exception>
    private static void ReadEssCertificateReferences(
        ReadOnlyMemory<byte> value,
        bool version2,
        List<SigningCertificateReference> references,
        MemoryPool<byte> pool)
    {
        var reader = new AsnReader(value, AsnEncodingRules.DER);
        AsnReader signingCertificate = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        AsnReader identifiers = signingCertificate.ReadSequence();
        int index = 0;
        while(identifiers.HasData && references.Count < MaximumSigningCertificateReferences)
        {
            AsnReader identifier = identifiers.ReadSequence();

            //ESSCertIDv2.hashAlgorithm is DEFAULT id-sha256 — present when the next element is the
            //AlgorithmIdentifier SEQUENCE, omitted when the certHash OCTET STRING comes first. ESSCertID (v1)
            //has no algorithm field at all: its hash is SHA-1 by definition (RFC 2634 §5.4).
            string hashOid = version2 ? WellKnownOids.Sha256 : WellKnownOids.Sha1;
            if(version2 && identifier.PeekTag() == new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true))
            {
                AsnReader hashAlgorithm = identifier.ReadSequence();
                hashOid = hashAlgorithm.ReadObjectIdentifier();
                if(hashAlgorithm.HasData)
                {
                    _ = hashAlgorithm.ReadEncodedValue();
                }

                hashAlgorithm.ThrowIfNotEmpty();
            }

            byte[] certificateHash = identifier.ReadOctetString();
            string? issuerName = null;
            string? serialNumber = null;
            if(identifier.HasData)
            {
                AsnReader issuerSerial = identifier.ReadSequence();
                AsnReader generalNames = issuerSerial.ReadSequence();
                if(generalNames.HasData && generalNames.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true))
                {
                    issuerName = PkiDistinguishedNameText.Read(generalNames.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4)));
                }

                serialNumber = Convert.ToHexString(issuerSerial.ReadIntegerBytes().Span);
            }

            identifier.ThrowIfNotEmpty();

            PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(hashOid);
            DigestValue? digest = algorithm is not null && certificateHash.Length == algorithm.Value.OutputByteLength
                ? CopyDigest(certificateHash, algorithm.Value.DigestTag, pool)
                : null;

            references.Add(new SigningCertificateReference
            {
                DigestAlgorithm = new AlgorithmIdentifier(hashOid),
                CertificateDigest = digest,
                IssuerName = issuerName,
                SerialNumber = serialNumber,

                //RFC 5035 §3: "The first certificate identified in the sequence of certificate identifiers MUST
                //be the certificate used to verify the signature." That is the direct identification step 1) of
                //clause 5.2.3.4 allows the building block to use.
                IsSignerReference = index == 0
            });

            ++index;
        }
    }


    /// <summary>
    /// Reads a certificate-values attribute value, appending each certificate it carries.
    /// </summary>
    /// <param name="value">The DER-encoded attribute value.</param>
    /// <param name="certificates">The list the certificates are appended to.</param>
    /// <param name="pool">The memory pool each certificate carrier is rented from.</param>
    /// <exception cref="AsnContentException">Thrown when the value is not a well-formed <c>CertificateValues</c>.</exception>
    private static void ReadCertificateValues(ReadOnlyMemory<byte> value, List<PkiCertificateMemory> certificates, MemoryPool<byte> pool)
    {
        var reader = new AsnReader(value, AsnEncodingRules.DER);
        AsnReader values = reader.ReadSequence();
        reader.ThrowIfNotEmpty();
        while(values.HasData && certificates.Count < MaximumEmbeddedCertificates)
        {
            certificates.Add(Copy(values.ReadEncodedValue(), PkiCertificateTags.X509Certificate, pool));
        }
    }


    /// <summary>
    /// Reads a revocation-values attribute value, appending the CRLs of its <c>crlVals</c> and the OCSP
    /// responses of its <c>ocspVals</c>.
    /// </summary>
    /// <param name="value">The DER-encoded attribute value.</param>
    /// <param name="revocationLists">The list the CRLs are appended to.</param>
    /// <param name="ocspResponses">The list the OCSP responses are appended to.</param>
    /// <param name="pool">The memory pool each carrier is rented from.</param>
    /// <exception cref="AsnContentException">Thrown when the value is not a well-formed <c>RevocationValues</c>.</exception>
    /// <remarks>
    /// The <c>ocspVals</c> field carries <c>BasicOCSPResponse</c> structures rather than the <c>OCSPResponse</c>
    /// wrapper an OCSP client receives; the carriers are tagged <see cref="PkiObjectKind.OcspResponse"/> and a
    /// consumer reads them accordingly.
    /// </remarks>
    private static void ReadRevocationValues(
        ReadOnlyMemory<byte> value,
        List<PkiCertificateMemory> revocationLists,
        List<PkiCertificateMemory> ocspResponses,
        MemoryPool<byte> pool)
    {
        var reader = new AsnReader(value, AsnEncodingRules.DER);
        AsnReader revocationValues = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        if(revocationValues.HasData && revocationValues.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            AsnReader crlValues = revocationValues.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            while(crlValues.HasData && revocationLists.Count < MaximumEmbeddedRevocationObjects)
            {
                revocationLists.Add(Copy(crlValues.ReadEncodedValue(), PkiCertificateTags.X509Crl, pool));
            }
        }

        if(revocationValues.HasData && revocationValues.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            AsnReader ocspValues = revocationValues.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            while(ocspValues.HasData && ocspResponses.Count < MaximumEmbeddedRevocationObjects)
            {
                ocspResponses.Add(Copy(ocspValues.ReadEncodedValue(), PkiCertificateTags.OcspResponse, pool));
            }
        }

        if(revocationValues.HasData && revocationValues.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true))
        {
            //otherRevVals [2] carries formats outside RFC 5280 and RFC 6960; consumed so the structure closes.
            _ = revocationValues.ReadEncodedValue();
        }

        revocationValues.ThrowIfNotEmpty();
    }


    /// <summary>
    /// Finds the certificate the SignerInfo identifies, by issuer-and-serial-number or by subject key
    /// identifier (RFC 5652 §5.3).
    /// </summary>
    /// <param name="certificates">The certificates carried by the signature.</param>
    /// <param name="signer">The parsed SignerInfo.</param>
    /// <returns>The signer's certificate, or <see langword="null"/> when the signature carries no copy of it.</returns>
    private static PkiCertificateMemory? MatchSigner(List<PkiCertificateMemory> certificates, CmsSignerStructure signer)
    {
        for(int i = 0; i < certificates.Count; ++i)
        {
            ManagedCertificate parsed;
            try
            {
                parsed = ManagedCertificate.Parse(certificates[i].AsReadOnlyMemory());
            }
            catch(AsnContentException)
            {
                //A certificate this library cannot parse cannot be matched against a signer identifier; it stays
                //in the carried set for a chain builder that may understand it.
                continue;
            }

            bool matchesIssuerAndSerial = !signer.IssuerDer.IsEmpty
                && parsed.IssuerDer.Span.SequenceEqual(signer.IssuerDer.Span)
                && parsed.SerialNumber.Span.SequenceEqual(signer.SerialNumber.Span);
            bool matchesSubjectKeyIdentifier = !signer.SubjectKeyIdentifier.IsEmpty
                && parsed.SubjectKeyIdentifier.Span.SequenceEqual(signer.SubjectKeyIdentifier.Span);
            if(matchesIssuerAndSerial || matchesSubjectKeyIdentifier)
            {
                return certificates[i];
            }
        }

        return null;
    }


    /// <summary>
    /// Reads the key size, in bits, of a certificate's subject public key, for the cryptographic constraints
    /// assessment of clause 5.2.8.4.1.
    /// </summary>
    /// <param name="certificate">The certificate, or <see langword="null"/> when the signature carries none.</param>
    /// <returns>The key size, or <see langword="null"/> when it is unknown.</returns>
    private static int? KeySizeBits(PkiCertificateMemory? certificate)
    {
        if(certificate is null)
        {
            return null;
        }

        try
        {
            return ManagedCertificate.Parse(certificate.AsReadOnlyMemory()).SubjectPublicKeySizeBits;
        }
        catch(AsnContentException)
        {
            return null;
        }
    }


    /// <summary>
    /// Copies DER bytes into a pooled <see cref="PkiCertificateMemory"/> the caller owns.
    /// </summary>
    /// <param name="der">The bytes to copy.</param>
    /// <param name="tag">The tag the carrier declares its kind with.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <returns>The carrier.</returns>
    private static PkiCertificateMemory Copy(ReadOnlyMemory<byte> der, Tag tag, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        try
        {
            der.Span.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, tag);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Copies a digest read off the wire into a pooled <see cref="DigestValue"/> the caller owns.
    /// </summary>
    /// <param name="digest">The digest bytes.</param>
    /// <param name="tag">The digest tag naming the algorithm.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <returns>The carrier.</returns>
    private static DigestValue CopyDigest(ReadOnlySpan<byte> digest, Tag tag, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(digest.Length);
        try
        {
            digest.CopyTo(owner.Memory.Span);

            return new DigestValue(owner, tag);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Reads the structure of a CMS SignedData: its encapsulated content, the certificates and revocation
    /// information it carries, and its first SignerInfo.
    /// </summary>
    /// <param name="encoded">The DER-encoded <c>ContentInfo</c> wrapping the SignedData.</param>
    /// <returns>The parsed structure, whose byte members are slices of <paramref name="encoded"/>.</returns>
    /// <exception cref="AsnContentException">Thrown when the bytes are not a well-formed CMS SignedData.</exception>
    private static CmsStructure ParseCms(ReadOnlyMemory<byte> encoded)
    {
        var outer = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader contentInfo = outer.ReadSequence();
        outer.ThrowIfNotEmpty();

        string contentInfoType = contentInfo.ReadObjectIdentifier();
        if(!string.Equals(contentInfoType, SignedDataOid, StringComparison.Ordinal))
        {
            throw new AsnContentException($"The CMS content type '{contentInfoType}' is not id-signedData (RFC 5652 §5.1).");
        }

        AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        AsnReader signedData = explicitContent.ReadSequence();

        _ = signedData.ReadInteger();
        _ = signedData.ReadSetOf();

        AsnReader encapContentInfo = signedData.ReadSequence();
        string eContentType = encapContentInfo.ReadObjectIdentifier();
        ReadOnlyMemory<byte> content = default;
        bool hasContent = false;
        if(encapContentInfo.HasData)
        {
            AsnReader eContent = encapContentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            content = eContent.ReadOctetString();
            eContent.ThrowIfNotEmpty();
            hasContent = true;
        }

        List<ReadOnlyMemory<byte>> certificates = [];
        if(signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            AsnReader certificateSet = signedData.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 0));
            while(certificateSet.HasData)
            {
                ReadOnlyMemory<byte> candidate = certificateSet.ReadEncodedValue();

                //CertificateChoices also admits attribute certificates and other context-tagged alternatives;
                //only the universal SEQUENCE alternative is an X.509 certificate (RFC 5652 §10.2.2).
                if(new AsnReader(candidate, AsnEncodingRules.DER).PeekTag() == new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true))
                {
                    certificates.Add(candidate);
                }
            }
        }

        List<ReadOnlyMemory<byte>> revocationLists = [];
        List<ReadOnlyMemory<byte>> ocspResponses = [];
        if(signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            AsnReader revocationSet = signedData.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 1));
            while(revocationSet.HasData)
            {
                ReadOnlyMemory<byte> candidate = revocationSet.ReadEncodedValue();
                var candidateReader = new AsnReader(candidate, AsnEncodingRules.DER);
                if(candidateReader.PeekTag() == new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true))
                {
                    revocationLists.Add(candidate);

                    continue;
                }

                if(candidateReader.PeekTag() != new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
                {
                    continue;
                }

                //OtherRevocationInfoFormat ::= SEQUENCE { otherRevInfoFormat OID, otherRevInfo ANY } (RFC 5652
                //§10.2.1); the id-pkix-ocsp-basic format carries a BasicOCSPResponse.
                AsnReader otherRevocationInfo = candidateReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                string format = otherRevocationInfo.ReadObjectIdentifier();
                if(string.Equals(format, WellKnownOids.OcspBasicResponseType, StringComparison.Ordinal))
                {
                    ocspResponses.Add(otherRevocationInfo.ReadEncodedValue());
                }
            }
        }

        AsnReader signerInfos = signedData.ReadSetOf();
        CmsSignerStructure signer = ParseSignerInfo(signerInfos.ReadSequence());

        return new CmsStructure(
            eContentType.Length == 0 ? DataOid : eContentType,
            content,
            hasContent,
            certificates,
            revocationLists,
            ocspResponses,
            signer);
    }


    /// <summary>
    /// Reads a CMS SignerInfo: the signer identifier, the digest and signature algorithms, and the signed and
    /// unsigned attributes.
    /// </summary>
    /// <param name="signerInfo">The reader positioned inside the SignerInfo SEQUENCE.</param>
    /// <returns>The parsed signer.</returns>
    /// <exception cref="AsnContentException">Thrown when the structure is not a well-formed SignerInfo.</exception>
    private static CmsSignerStructure ParseSignerInfo(AsnReader signerInfo)
    {
        _ = signerInfo.ReadInteger();

        ReadOnlyMemory<byte> issuerDer = default;
        ReadOnlyMemory<byte> serialNumber = default;
        ReadOnlyMemory<byte> subjectKeyIdentifier = default;
        if(signerInfo.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0))
        {
            subjectKeyIdentifier = signerInfo.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
        }
        else
        {
            AsnReader issuerAndSerial = signerInfo.ReadSequence();
            issuerDer = issuerAndSerial.ReadEncodedValue();
            serialNumber = issuerAndSerial.ReadIntegerBytes();
            issuerAndSerial.ThrowIfNotEmpty();
        }

        AsnReader digestAlgorithm = signerInfo.ReadSequence();
        string digestAlgorithmOid = digestAlgorithm.ReadObjectIdentifier();

        List<CmsAttributeStructure> signedAttributes = [];
        if(signerInfo.HasData && signerInfo.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            ReadAttributes(signerInfo.ReadEncodedValue(), new Asn1Tag(TagClass.ContextSpecific, 0), signedAttributes);
        }

        AsnReader signatureAlgorithm = signerInfo.ReadSequence();
        string signatureAlgorithmOid = signatureAlgorithm.ReadObjectIdentifier();

        //RFC 5652 §5.3: the signature field. These are the octets an RFC 3161 signature time-stamp takes its
        //message imprint over, and the object clause 5.6.2.4 of EN 319 102-1 asks a proof of existence about.
        ReadOnlyMemory<byte> signature = signerInfo.ReadOctetString();

        List<CmsAttributeStructure> unsignedAttributes = [];
        if(signerInfo.HasData && signerInfo.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            ReadAttributes(signerInfo.ReadEncodedValue(), new Asn1Tag(TagClass.ContextSpecific, 1), unsignedAttributes);
        }

        return new CmsSignerStructure(
            issuerDer, serialNumber, subjectKeyIdentifier, digestAlgorithmOid, signatureAlgorithmOid, signature, signedAttributes, unsignedAttributes);
    }


    /// <summary>
    /// Itemises one implicitly tagged attribute set, collecting each attribute's type and its first value
    /// (RFC 5652 §5.3).
    /// </summary>
    /// <param name="attributes">The DER-encoded attribute set.</param>
    /// <param name="setTag">The implicit tag the set carries.</param>
    /// <param name="into">The list the attributes are appended to.</param>
    /// <exception cref="AsnContentException">Thrown when the set is not well-formed.</exception>
    private static void ReadAttributes(ReadOnlyMemory<byte> attributes, Asn1Tag setTag, List<CmsAttributeStructure> into)
    {
        var reader = new AsnReader(attributes, AsnEncodingRules.DER);
        AsnReader set = reader.ReadSetOf(skipSortOrderValidation: true, setTag);
        reader.ThrowIfNotEmpty();
        while(set.HasData)
        {
            AsnReader attribute = set.ReadSequence();
            string attributeType = attribute.ReadObjectIdentifier();
            AsnReader values = attribute.ReadSetOf();
            if(values.HasData)
            {
                into.Add(new CmsAttributeStructure(attributeType, values.ReadEncodedValue()));
            }
        }
    }


    /// <summary>One CMS attribute: its type object identifier and the DER of its first value.</summary>
    /// <param name="Oid">The attribute type object identifier.</param>
    /// <param name="Value">The DER-encoded first value, a slice of the Signed Data Object's bytes.</param>
    private sealed record CmsAttributeStructure(string Oid, ReadOnlyMemory<byte> Value);


    /// <summary>The SignerInfo fields this binding reads.</summary>
    /// <param name="IssuerDer">The signer identifier's issuer name as raw DER; empty when the signer is identified by subject key identifier.</param>
    /// <param name="SerialNumber">The signer identifier's serial number as its DER INTEGER content octets; empty when the signer is identified by subject key identifier.</param>
    /// <param name="SubjectKeyIdentifier">The signer identifier's subject key identifier; empty when the signer is identified by issuer and serial number.</param>
    /// <param name="DigestAlgorithmOid">The digest algorithm the signer used over the signed attributes.</param>
    /// <param name="SignatureAlgorithmOid">The signature algorithm the signer used.</param>
    /// <param name="Signature">The signature field's octets, a slice of the Signed Data Object's bytes.</param>
    /// <param name="SignedAttributes">The signed attributes, in encoding order.</param>
    /// <param name="UnsignedAttributes">The unsigned attributes, in encoding order.</param>
    private sealed record CmsSignerStructure(
        ReadOnlyMemory<byte> IssuerDer,
        ReadOnlyMemory<byte> SerialNumber,
        ReadOnlyMemory<byte> SubjectKeyIdentifier,
        string DigestAlgorithmOid,
        string SignatureAlgorithmOid,
        ReadOnlyMemory<byte> Signature,
        IReadOnlyList<CmsAttributeStructure> SignedAttributes,
        IReadOnlyList<CmsAttributeStructure> UnsignedAttributes);


    /// <summary>The SignedData fields this binding reads.</summary>
    /// <param name="ContentType">The encapsulated content type object identifier.</param>
    /// <param name="Content">The encapsulated content bytes, a slice of the Signed Data Object's bytes.</param>
    /// <param name="HasContent">Whether the SignedData encapsulates its content at all.</param>
    /// <param name="Certificates">The DER of each X.509 certificate the structure carries.</param>
    /// <param name="CertificateRevocationLists">The DER of each certificate revocation list the structure carries.</param>
    /// <param name="OcspResponses">The DER of each <c>BasicOCSPResponse</c> the structure carries.</param>
    /// <param name="Signer">The first SignerInfo.</param>
    private sealed record CmsStructure(
        string ContentType,
        ReadOnlyMemory<byte> Content,
        bool HasContent,
        IReadOnlyList<ReadOnlyMemory<byte>> Certificates,
        IReadOnlyList<ReadOnlyMemory<byte>> CertificateRevocationLists,
        IReadOnlyList<ReadOnlyMemory<byte>> OcspResponses,
        CmsSignerStructure Signer);
}
