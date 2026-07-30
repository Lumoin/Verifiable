using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
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

    /// <summary>
    /// The complete-certificate-references unsigned attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause A.1.1.1</see> (<c>id-aa-ets-certificateRefs</c>), which references the
    /// certificates of the signer's chain by hash value rather than carrying them. It is
    /// <c>shall not be present</c> at every baseline level of clause 6.3 and is never created here; it is
    /// recognised because the time-stamps of clause A.1.5 are computed over it.
    /// </summary>
    public static string CompleteCertificateReferencesAttributeOid => "1.2.840.113549.1.9.16.2.21";

    /// <summary>
    /// The complete-revocation-references unsigned attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause A.1.2.1</see> (<c>id-aa-ets-revocationRefs</c>), the revocation-data
    /// counterpart of <see cref="CompleteCertificateReferencesAttributeOid"/>, recognised for the same reason
    /// and equally never created.
    /// </summary>
    public static string CompleteRevocationReferencesAttributeOid => "1.2.840.113549.1.9.16.2.22";

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
    /// The ats-hash-index-v3 unsigned attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.5.2</see> (<c>id-aa-ATSHashIndex-v3</c>, Annex D). It names which
    /// certificates, revocation information objects and unsigned attribute values an archive time-stamp
    /// protects, and clause 5.5.3 requires an archive-time-stamp-v3 token to carry exactly one of them among the
    /// unsigned attributes of its own SignerInfo — which is where <see cref="ArchiveTimestampV3"/> reads it, not
    /// among the attributes of the signature this binding surfaces.
    /// </summary>
    public static string AtsHashIndexV3AttributeOid => "0.4.0.19122.1.5";

    /// <summary>
    /// The long-term-validation unsigned attribute, deprecated by
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause A.2.5</see> ("New long-term-validation attributes shall not be created").
    /// It is recognised, never emitted, and its presence selects the second validation-data placement strategy
    /// of clause 5.5.3. The object identifier's value is not printed in EN 319 122-1 itself, which names the
    /// attribute by reference to the legacy specification it is inherited from.
    /// </summary>
    public static string LongTermValidationAttributeOid => "0.4.0.1733.2.2";

    /// <summary>
    /// The ats-hash-index unsigned attribute preceding <see cref="AtsHashIndexV3AttributeOid"/>, deprecated by
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause A.2.6</see> ("Instead the ats-hash-index-v3 attribute ... shall be
    /// used"). Recognised, never emitted. The object identifier's value is not printed in EN 319 122-1 itself,
    /// which names the attribute by reference to the legacy specification it is inherited from.
    /// </summary>
    public static string AtsHashIndexAttributeOid => "0.4.0.1733.2.5";

    /// <summary>
    /// The ats-hash-index-v2 unsigned attribute, the second of the three forms and deprecated by the same
    /// clause A.2.6 as the first. Recognised, never emitted. The object identifier's value is not printed in
    /// EN 319 122-1 V1.3.1, which inherits it from the earlier version of the present document.
    /// </summary>
    public static string AtsHashIndexV2AttributeOid => "0.4.0.19122.1.4";

    /// <summary>
    /// The commitment-type-indication signed attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.2.3</see> (<c>id-aa-ets-commitmentType</c>), which qualifies the
    /// commitment the signer made when signing the data object.
    /// </summary>
    public static string CommitmentTypeIndicationAttributeOid => "1.2.840.113549.1.9.16.2.16";

    /// <summary>
    /// The content-hints signed attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.2.4.1</see> (<c>id-aa-contentHint</c>, ESS
    /// <see href="https://www.rfc-editor.org/rfc/rfc2634#section-2.9">RFC 2634 §2.9</see>), one of the two
    /// Service Provision Options for the "identifying the signed data type" service of Table 1 requirement t).
    /// </summary>
    public static string ContentHintsAttributeOid => "1.2.840.113549.1.9.16.2.4";

    /// <summary>
    /// The mime-type signed attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.2.4.2</see> (<c>id-aa-ets-mimeType</c>), the other Service Provision
    /// Option for Table 1 requirement t).
    /// </summary>
    public static string MimeTypeAttributeOid => "0.4.0.1733.2.1";

    /// <summary>
    /// The signer-location signed attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.2.5</see> (<c>id-aa-ets-signerLocation</c>).
    /// </summary>
    public static string SignerLocationAttributeOid => "1.2.840.113549.1.9.16.2.17";

    /// <summary>
    /// The content-reference signed attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.2.11</see> (<c>id-aa-contentReference</c>, ESS
    /// <see href="https://www.rfc-editor.org/rfc/rfc2634#section-2.11">RFC 2634 §2.11</see>).
    /// </summary>
    public static string ContentReferenceAttributeOid => "1.2.840.113549.1.9.16.2.10";

    /// <summary>
    /// The content-identifier signed attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.2.12</see> (<c>id-aa-contentIdentifier</c>, ESS
    /// <see href="https://www.rfc-editor.org/rfc/rfc2634#section-2.7">RFC 2634 §2.7</see>).
    /// </summary>
    public static string ContentIdentifierAttributeOid => "1.2.840.113549.1.9.16.2.7";

    /// <summary>
    /// The signature-policy-store unsigned attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.2.10</see> (<c>id-aa-ets-sigPolicyStore</c>). Table 1 requirement k)
    /// gates its incorporation on <see cref="SignaturePolicyIdentifierAttributeOid"/> being present with a
    /// non-zero <c>sigPolicyHash</c> — enforced by <see cref="CAdESSignatureAugmentation.AddSignaturePolicyStore"/>.
    /// </summary>
    public static string SignaturePolicyStoreAttributeOid => "0.4.0.19122.1.3";

    /// <summary>
    /// The signer-attributes-v2 signed attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.2.6.1</see> (<c>id-aa-ets-signerAttrV2</c>, Annex D), which encapsulates
    /// attributes of the signer: claimed attributes, attribute certificates issued by an Attribute Authority, or
    /// assertions signed by a third party. Table 1 requirement n) admits
    /// <see cref="CompleteCertificateReferencesAttributeOid"/>'s attribute-certificate siblings only when a
    /// <c>certifiedAttributesV2</c> or <c>signedAssertions</c> arm of this attribute is present — the
    /// <c>claimedAttributes</c> arm on its own does not legitimize them.
    /// </summary>
    public static string SignerAttributesV2AttributeOid => "0.4.0.19122.1.1";

    /// <summary>
    /// The countersignature unsigned attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.2.7</see>, which states it "shall be as defined in CMS" —
    /// <c>id-countersignature</c> of
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-11.4">RFC 5652 §11.4</see>, whose value is a
    /// whole <c>SignerInfo</c> signed over the outer <c>SignerInfo.signature</c> value octets. Table 1 gives it
    /// cardinality <c>&gt;= 0</c>, so a signature may carry none, one, or several — as several values of one
    /// attribute or as several attributes, both of which clause 5.5.3 NOTE 6 names explicitly.
    /// </summary>
    public static string CountersignatureAttributeOid => "1.2.840.113549.1.9.6";


    /// <summary>
    /// The seam bundle a caller hands the building blocks to validate a CAdES signature.
    /// </summary>
    public static SignatureFormatSeam Seam { get; } = new()
    {
        Format = SignatureFormatIdentifier.CAdES,
        ExtractFacts = ExtractAsync,
        VerifyCryptography = VerifyCryptographyAsync,
        StateTimestampCoverage = StateTimestampCoverageAsync,
        StateTimestampProtectsObject = StateTimestampProtectsObjectAsync
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
    /// An archive time-stamp's imprint is the four-part concatenation of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.5.3</see>, driven by the <c>ats-hash-index-v3</c> of clause 5.5.2 that
    /// the token itself carries; it is recomputed from the Signed Data Object's own octets by
    /// <see cref="ArchiveTimestampV3.StateCoverageAsync"/> — the same component the generator side computes the
    /// index and the imprint input with, so the two directions cannot drift. A time-stamp on references to
    /// validation data uses the third convention of clause A.1.5, which
    /// <see cref="ValidationDataTimestampCoverage"/> states.
    /// </para>
    /// <para>
    /// <strong>Nothing stated is the fail-closed outcome, and it is reached without an exception.</strong> An
    /// archive time-stamp of the deprecated v2 form carries no hash index, a token whose index no longer matches
    /// the material the signature carries is invalid per clause 5.5.2, and a detached signature has no
    /// encapsulated content for step 2) of clause 5.5.3 — each of those, and every unreadable structure, yields
    /// <see langword="null"/>. The POE extraction building block then derives no proof of existence from the
    /// token unless the caller's validation constraints explicitly accept a coverage this binding did not state.
    /// </para>
    /// </remarks>
    public static async ValueTask<SignedContentMemory?> StateTimestampCoverageAsync(
        TimestampCoverageContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        //The archive time-stamp is the only class whose coverage reaches the digest seam, so it is resolved on
        //its own and every other class maps straight to the octets it is computed over.
        if(context.Timestamp.Class == SignatureTimestampClass.ArchiveTimestamp)
        {
            return await StateArchiveTimestampCoverageAsync(context, pool, cancellationToken).ConfigureAwait(false);
        }

        return context.Timestamp.Class switch
        {
            SignatureTimestampClass.ContentTimestamp => CopyStatedOctets(context.Signature.SignedContent, pool),
            SignatureTimestampClass.SignatureTimestamp => CopyStatedOctets(context.Signature.SignatureValue, pool),
            SignatureTimestampClass.ValidationDataTimestamp => StateValidationDataTimestampCoverage(context, pool),
            _ => null
        };
    }


    /// <summary>
    /// States coverage the extracted facts already hold as a carrier, copied into a carrier the caller owns.
    /// </summary>
    /// <param name="stated">The octets the class is computed over, or <see langword="null"/> when the signature carries none.</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <returns>The copy, which the caller disposes, or <see langword="null"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned carrier transfers to the caller, which disposes it once it has verified the message imprint against it.")]
    private static SignedContentMemory? CopyStatedOctets(SignedContentMemory? stated, MemoryPool<byte> pool) =>
        stated is null ? null : SignedContentMemory.FromBytes(stated.AsReadOnlyMemory().Span, pool);


    /// <summary>
    /// States the octets an <c>archive-time-stamp-v3</c>'s message imprint is computed over, by recomputing the
    /// clause 5.5.3 concatenation from the Signed Data Object and the token's own <c>ats-hash-index-v3</c>.
    /// </summary>
    /// <param name="context">The signature and the time-stamp.</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The octets, which the caller disposes, or <see langword="null"/> when nothing could be stated.</returns>
    /// <remarks>
    /// The signer index is zero because this binding surfaces the facts of the first <c>SignerInfo</c> alone —
    /// the same signer every other member of <see cref="SignatureFacts"/> describes — so an archive time-stamp
    /// it surfaced is the one of clause 5.5.1 belonging to that signer.
    /// <para>
    /// A detached signature states nothing here: step 2) of clause 5.5.3 needs the signed data, its NOTE 1 has
    /// that hash come from outside the signature for the detached case, and the coverage seam carries no channel
    /// for the Driving Application's Signer's Document. The same binding already reports
    /// <see cref="SignatureCryptographicOutcome.SignedDataNotFound"/> for a detached signature, so no run
    /// reaches proof-of-existence extraction with one.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned carrier transfers to the caller, which disposes it once it has verified the message imprint against it.")]
    private static async ValueTask<SignedContentMemory?> StateArchiveTimestampCoverageAsync(
        TimestampCoverageContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(context.Signature.SignedDataObject is not CmsSignedData signedData)
        {
            return null;
        }

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext
            {
                SignedData = signedData,
                ArchiveTimestampToken = context.Timestamp.Token,
                SignerIndex = 0
            },
            pool,
            cancellationToken).ConfigureAwait(false);

        return coverage.MessageImprintInput is SignedContentMemory imprintInput
            ? SignedContentMemory.FromBytes(imprintInput.AsReadOnlyMemory().Span, pool)
            : null;
    }


    /// <summary>
    /// States the octets a time-stamp on references to validation data — clause A.1.5's
    /// <c>CAdES-C-timestamp</c> or <c>time-stamped-certs-crls-references</c> — has its message imprint computed
    /// over.
    /// </summary>
    /// <param name="context">The signature and the time-stamp.</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <returns>The octets, which the caller disposes, or <see langword="null"/> when nothing could be stated.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned carrier transfers to the caller, which disposes it once it has verified the message imprint against it.")]
    private static SignedContentMemory? StateValidationDataTimestampCoverage(
        TimestampCoverageContext context,
        MemoryPool<byte> pool) =>
        context.Signature.SignedDataObject is CmsSignedData signedData
            ? ValidationDataTimestampCoverage.StateCoverage(signedData, signerIndex: 0, context.Timestamp.Identifier, pool)
            : null;


    /// <summary>
    /// Decides whether one embedded time-stamp is shown to protect one individual object of the signature — the
    /// <see cref="StateTimestampProtectsObjectAsyncDelegate"/> implementation of the bundle in <see cref="Seam"/>.
    /// </summary>
    /// <param name="context">The signature, the time-stamp, and the one candidate object.</param>
    /// <param name="pool">The memory pool the scratch buffer and the computed digest are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when this format shows the time-stamp protects the object.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// An <c>archive-time-stamp-v3</c> names the objects it protects one by one, in the <c>ats-hash-index-v3</c> of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.5.2</see>: one hash value per instance of <c>CertificateChoices</c>, one
    /// per instance of <c>RevocationInfoChoice</c>, and one per <c>AttributeValue</c> of every unsigned attribute,
    /// "as present at the time when the corresponding archive time-stamp is requested". That is strictly finer than
    /// the per-class rule of clause 5.6.3.1 of ETSI EN 319 102-1, which classifies an archive time-stamp as
    /// protecting "the whole signature except the last archive time-stamp"; the difference is exactly the material
    /// somebody appended to the signature <em>after</em> the archive time-stamp was applied, which the index cannot
    /// name and which no part of the token's message imprint binds. Answering from the index closes that gap: a
    /// revocation object or a certificate added after the fact gains no proof of existence at the archive
    /// time-stamp's instant.
    /// </para>
    /// <para>
    /// A time-stamp on references to validation data protects no such object at all. The imprints of clauses
    /// A.1.5.1 and A.1.5.2 are computed over the <c>complete-certificate-references</c> and
    /// <c>complete-revocation-references</c> attributes — and, for the <c>escTimeStamp</c> form, the signature
    /// value and the <c>signature-time-stamp</c> attribute as well — never over the certificates and revocation
    /// data the signature carries. Those attributes name the material by hash value, which is a <em>reference</em>
    /// of step 4) of clause 5.6.2.3 rather than an object of step 5), and this binding does not surface those
    /// references. The answer is therefore <see langword="false"/>: a proof of existence is lost rather than one
    /// granted that the token does not establish.
    /// </para>
    /// </remarks>
    public static async ValueTask<bool> StateTimestampProtectsObjectAsync(
        TimestampProtectedObjectContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        //The archive class is the only one whose answer reaches the digest seam, so it is resolved on its own and
        //every other class answers from its own imprint definition alone.
        if(context.Timestamp.Class == SignatureTimestampClass.ArchiveTimestamp)
        {
            return await StateArchiveTimestampProtectsObjectAsync(context, pool, cancellationToken).ConfigureAwait(false);
        }

        return context.Timestamp.Class switch
        {
            //Clause A.1.5: the imprint covers the reference attributes, not the material they reference.
            SignatureTimestampClass.ValidationDataTimestamp => false,

            //A content time-stamp covers the signed content and a signature time-stamp the signature value, and
            //the extraction block admits those two objects without consulting this filter at all, so neither class
            //ever reaches here. An unforeseen class has shown nothing about a certificate, a revocation object or
            //an earlier token either.
            _ => false
        };
    }


    /// <summary>
    /// Decides whether the <c>ats-hash-index-v3</c> of an <c>archive-time-stamp-v3</c> names one candidate object
    /// of the signature, by recomputing that object's hash value the way clause 5.5.2 counts it and testing
    /// membership in the matching index list.
    /// </summary>
    /// <param name="context">The signature, the archive time-stamp, and the one candidate object.</param>
    /// <param name="pool">The memory pool the scratch buffer and the computed digest are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when an index entry matches the object.</returns>
    /// <remarks>
    /// <para>
    /// <strong>The object is looked up in the Signed Data Object's own structure, because that is what the index
    /// counts.</strong> Clause 5.5.2 hashes whole members of <c>SignedData.certificates</c> and
    /// <c>SignedData.crls</c>, and for an unsigned attribute the concatenation of the <c>attrType</c> field and the
    /// one <c>AttributeValue</c>. For a certificate and for a certificate revocation list that member is the
    /// object's own encoding, but for an OCSP response it is not: clause 5.4.2.2 places it as the <c>other</c>
    /// alternative of <c>RevocationInfoChoice</c>, an <c>OtherRevocationInfoFormat</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5940">RFC 5940</see>) whose <c>otherRevInfo</c> field is what
    /// the extracted facts surface. Hashing the surfaced octets alone would report every embedded OCSP response
    /// uncovered, so the member that carries it is located and hashed instead — no re-encoding is involved, the
    /// member's own octets are taken as they stand.
    /// </para>
    /// <para>
    /// <strong>A signed attribute value is protected through the imprint, not the index.</strong> A
    /// <c>content-time-stamp</c> is a SIGNED attribute (clause 5.2.8), and step 3) of clause 5.5.3 concatenates
    /// the whole <c>signedAttrs</c> TLV verbatim into the archive time-stamp's message imprint, so its token is
    /// bound by the archive time-stamp exactly as the signature value and the signed content are — none of which
    /// the <c>ats-hash-index-v3</c> of clause 5.5.2 names, because that index holds hashes of certificates,
    /// revocation objects and <em>unsigned</em> attribute values alone. This object-granular filter therefore
    /// admits a <see cref="ValidationObjectKind.TimestampToken"/> candidate whose octets are one of the signer's
    /// signed attribute values unconditionally, before any index list is consulted and with no hash-index lookup;
    /// a lookup would find nothing and wrongly cost the token its proof of existence. Only the timestamp-token
    /// kind is tested this way — a certificate or a revocation object never appears among <c>signedAttrs</c>.
    /// </para>
    /// <para>
    /// <strong>Accepted over-strictness (fail-closed), and its exact reach.</strong> One placement is still read
    /// as unprotected when it is in fact protected: a certificate this binding surfaced out of a
    /// <c>certificate-values</c> attribute, or a revocation object out of a <c>revocation-values</c> attribute —
    /// the legacy placement of clauses A.1.1.2 and A.1.2.2 that clause 5.5.3's second strategy writes to. That
    /// object is not a member of the root <c>certificates</c> or <c>crls</c> field, so it is not found and reads
    /// as unprotected, though it is in fact protected through the index entry of the whole attribute value that
    /// contains it; a finer reading would descend into that attribute's own syntax. This is deliberately not done:
    /// the outcome costs a proof of existence rather than granting one, and it is only reachable on a signature
    /// carrying the deprecated legacy attributes that select that second strategy at all — nothing this library
    /// creates does. A <c>content-time-stamp</c>, by contrast, is a signed attribute this library <em>does</em>
    /// create (clause 6.3, an opt-in attribute) and is reached through the signed-attribute-value admission above,
    /// so it is not among the over-strict placements.
    /// </para>
    /// </remarks>
    private static async ValueTask<bool> StateArchiveTimestampProtectsObjectAsync(
        TimestampProtectedObjectContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(context.Signature.SignedDataObject is not CmsSignedData signedData)
        {
            return false;
        }

        AtsHashIndexV3? hashIndex = null;
        try
        {
            hashIndex = ArchiveTimestampV3.ReadHashIndexFromToken(context.Timestamp.Token, pool);
            if(hashIndex is null)
            {
                //A token carrying no ats-hash-index-v3 names no protected objects one by one; the deprecated
                //archive-time-stamp form of clause A.2.4 is exactly that. Nothing here can narrow the class rule,
                //and nothing needs to: StateTimestampCoverageAsync already states no coverage for such a token, so
                //a validation run reaches this filter with one only when the caller's constraints explicitly
                //accept a coverage this binding did not state — which is itself the declaration that the per-class
                //admission of clause 5.6.3.1 may stand for that token.
                return true;
            }

            //A content-time-stamp is a SIGNED attribute (clause 5.2.8), and step 3) of clause 5.5.3 concatenates
            //the whole signedAttrs TLV verbatim into the archive time-stamp's message imprint — so a candidate
            //whose octets are one of the signer's signed attribute values is bound by the archive time-stamp
            //exactly as its signature value and signed content are (the objects the extraction block admits
            //without ever consulting this filter). The ats-hash-index-v3 of clause 5.5.2 never names it — the
            //index holds hashes of certificates, revocation objects and UNSIGNED attribute values alone — so the
            //answer is stated here, before any index list is consulted, and admitted unconditionally on a hit
            //with no hash-index lookup. Only the TimestampToken kind can be a signed attribute value; a
            //certificate or a revocation object never appears in signedAttrs, so no other kind is tested this way.
            if(context.Kind == ValidationObjectKind.TimestampToken && CandidateIsSignedAttributeValue(signedData, context.Object))
            {
                return true;
            }

            if(PkiDigestAlgorithm.FromOid(hashIndex.HashIndexAlgorithm.Oid) is not PkiDigestAlgorithm algorithm)
            {
                return false;
            }

            IReadOnlyList<ReadOnlyMemory<byte>> entries = context.Kind switch
            {
                ValidationObjectKind.Certificate => hashIndex.CertificatesHashIndex,
                ValidationObjectKind.RevocationData => hashIndex.CrlsHashIndex,
                ValidationObjectKind.TimestampToken => hashIndex.UnsignedAttributeValuesHashIndex,
                _ => []
            };
            if(entries.Count == 0)
            {
                return false;
            }

            IndexedObjectEncoding? indexed = LocateIndexedEncoding(signedData, context.Object, context.Kind);
            if(indexed is null)
            {
                return false;
            }

            using DigestValue digest = await ComputeIndexedDigestAsync(
                indexed.Value, algorithm, pool, cancellationToken).ConfigureAwait(false);
            for(int i = 0; i < entries.Count; ++i)
            {
                if(digest.AsReadOnlySpan().SequenceEqual(entries[i].Span))
                {
                    return true;
                }
            }

            return false;
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            //Attacker-reachable input: a structure this walk cannot read shows nothing about the object.
            return false;
        }
        finally
        {
            hashIndex?.Dispose();
        }

        //Finds the encoding clause 5.5.2 counts a hash value of for one candidate object, as it stands in the
        //Signed Data Object, and names the attribute type it has to be concatenated after when the object is
        //carried as an unsigned attribute value.
        static IndexedObjectEncoding? LocateIndexedEncoding(CmsSignedData signedData, PkiCertificateMemory candidate, ValidationObjectKind kind)
        {
            if(kind == ValidationObjectKind.Certificate)
            {
                IReadOnlyList<ReadOnlyMemory<byte>> members = CmsSignedDataAugmentation.ReadCertificates(signedData);
                for(int i = 0; i < members.Count; ++i)
                {
                    if(members[i].Span.SequenceEqual(candidate.AsReadOnlySpan()))
                    {
                        return new IndexedObjectEncoding(AttributeType: null, members[i]);
                    }
                }

                return null;
            }

            if(kind == ValidationObjectKind.RevocationData)
            {
                IReadOnlyList<ReadOnlyMemory<byte>> members = CmsSignedDataAugmentation.ReadRevocationInformation(signedData);
                for(int i = 0; i < members.Count; ++i)
                {
                    if(members[i].Span.SequenceEqual(candidate.AsReadOnlySpan()) || CarriesOtherRevocationInfo(members[i], candidate.AsReadOnlySpan()))
                    {
                        return new IndexedObjectEncoding(AttributeType: null, members[i]);
                    }
                }

                return null;
            }

            if(kind != ValidationObjectKind.TimestampToken)
            {
                return null;
            }

            //An earlier time-stamp token is one AttributeValue of one unsigned attribute, and clause 5.5.2 indexes
            //those per value: the hash is over the attribute's attrType field followed by the one value.
            IReadOnlyList<CmsUnsignedAttributeValueLocation> locations = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex: 0);
            for(int i = 0; i < locations.Count; ++i)
            {
                ReadOnlyMemory<byte> value = CmsSignedDataAugmentation.ReadUnsignedAttributeValue(
                    signedData, signerIndex: 0, locations[i].AttributeIndex, locations[i].ValueIndex);
                if(value.Span.SequenceEqual(candidate.AsReadOnlySpan()))
                {
                    return new IndexedObjectEncoding(locations[i].AttributeType, value);
                }
            }

            return null;
        }

        //Tells whether one member of SignedData.crls is the other alternative of RevocationInfoChoice (RFC 5652
        //§10.2.1) carrying the candidate object as its otherRevInfo field, which is the shape clause 5.4.2.2 gives
        //an embedded OCSP response and the reason the octets the extracted facts surface are shorter than the
        //member whose hash value the index holds.
        static bool CarriesOtherRevocationInfo(ReadOnlyMemory<byte> member, ReadOnlySpan<byte> candidate)
        {
            try
            {
                var reader = new AsnReader(member, AsnEncodingRules.DER);
                if(reader.PeekTag() != new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
                {
                    return false;
                }

                AsnReader otherRevocationInfo = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                string format = otherRevocationInfo.ReadObjectIdentifier();
                ReadOnlyMemory<byte> otherRevInfo = otherRevocationInfo.ReadEncodedValue();

                //The candidate is the surfaced OCSP response, always a whole OCSPResponse; the member is
                //normalised the same way the surfacing walk normalises it (the id-pkix-ocsp-basic form's bare
                //BasicOCSPResponse wrapped, the RFC 5940 §2 id-ri-ocsp-response form's whole response left as it
                //stands) so the two forms compare on the one canonical shape the index member is then hashed by.
                return string.Equals(format, WellKnownOids.OcspBasicResponseType, StringComparison.Ordinal)
                    ? WrapBasicResponseAsOcspResponse(otherRevInfo.Span).AsSpan().SequenceEqual(candidate)
                    : otherRevInfo.Span.SequenceEqual(candidate);
            }
            catch(AsnContentException)
            {
                //One member this walk cannot read is one member that does not match; the remaining members are
                //still worth asking about, so the failure is local rather than the whole answer's.
                return false;
            }
        }

        //Computes the hash value clause 5.5.2 holds for one object: of the located encoding alone, or of the
        //attribute's attrType field laid before it when the object is an unsigned attribute value. The attrType
        //field is re-encoded from the object identifier the walk read, which reproduces the octets the index was
        //computed over because an object identifier's DER encoding is canonical — and a structure whose attribute
        //types are not DER states no archive coverage in the first place, so nothing reaches here from one.
        static async ValueTask<DigestValue> ComputeIndexedDigestAsync(
            IndexedObjectEncoding indexed,
            PkiDigestAlgorithm algorithm,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            if(indexed.AttributeType is not string attributeType)
            {
                return await CryptographicKeyEvents.ComputeDigestAsync(
                    indexed.Encoding, algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
            }

            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteObjectIdentifier(attributeType);
            int attributeTypeLength = writer.GetEncodedLength();
            int total = attributeTypeLength + indexed.Encoding.Length;
            using IMemoryOwner<byte> concatenation = pool.Rent(total);
            if(!writer.TryEncode(concatenation.Memory.Span[..attributeTypeLength], out _))
            {
                throw new CryptographicException("An unsigned attribute's attrType object identifier did not encode into the length its own encoder stated.");
            }

            indexed.Encoding.CopyTo(concatenation.Memory[attributeTypeLength..]);

            return await CryptographicKeyEvents.ComputeDigestAsync(
                concatenation.Memory[..total], algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        //Tells whether one candidate object's octets are one of the signer's signed attribute values, which
        //step 3) of clause 5.5.3 binds as a whole — the placement of a content-time-stamp (clause 5.2.8) —
        //rather than through the ats-hash-index-v3. The single signedAttrs walker of CmsSignedDataAugmentation is
        //reused, so no fourth CMS descent is opened here, and any parse failure it raises is caught by the outer
        //fail-closed handler exactly as every other read on this path is.
        static bool CandidateIsSignedAttributeValue(CmsSignedData signedData, PkiCertificateMemory candidate)
        {
            IReadOnlyList<ReadOnlyMemory<byte>> values = CmsSignedDataAugmentation.ReadSignedAttributeValues(signedData, signerIndex: 0);
            for(int i = 0; i < values.Count; ++i)
            {
                if(values[i].Span.SequenceEqual(candidate.AsReadOnlySpan()))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// The encoding whose hash value the <c>ats-hash-index-v3</c> of clause 5.5.2 holds for one object of a
    /// signature, as it stands in the Signed Data Object.
    /// </summary>
    /// <param name="AttributeType">The <c>attrType</c> object identifier the encoding has to be concatenated after, when the object is one <c>AttributeValue</c> of an unsigned attribute; <see langword="null"/> for a member of <c>certificates</c> or <c>crls</c>, whose whole encoding is hashed on its own.</param>
    /// <param name="Encoding">The whole encoding of the member or the attribute value, tag and length octets included.</param>
    [DebuggerDisplay("IndexedObjectEncoding: {Encoding.Length} octets after {AttributeType}")]
    private readonly record struct IndexedObjectEncoding(string? AttributeType, ReadOnlyMemory<byte> Encoding);


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
    /// Reads a revocation-values attribute value, appending the CRLs of its <c>crlVals</c>, the OCSP responses
    /// of its <c>ocspVals</c>, and any whole <c>OCSPResponse</c> its <c>otherRevVals</c> carries under
    /// <c>id-ri-ocsp-response</c>.
    /// </summary>
    /// <param name="value">The DER-encoded attribute value.</param>
    /// <param name="revocationLists">The list the CRLs are appended to.</param>
    /// <param name="ocspResponses">The list the OCSP responses are appended to.</param>
    /// <param name="pool">The memory pool each carrier is rented from.</param>
    /// <exception cref="AsnContentException">Thrown when the value is not a well-formed <c>RevocationValues</c>.</exception>
    /// <remarks>
    /// <para>
    /// The Annex D module (<c>ETSI-CAdES-ExplicitSyntax97</c>) opens <c>DEFINITIONS EXPLICIT TAGS</c>, so a
    /// conformant <c>RevocationValues</c> tags each field explicitly: <c>crlVals [0] { SEQUENCE OF
    /// CertificateList }</c>, <c>ocspVals [1] { SEQUENCE OF BasicOCSPResponse }</c>, and <c>otherRevVals [2]
    /// { OtherRevVals SEQUENCE { OID, SEQUENCE OF } }</c>. This reader reads that shape and ALSO tolerates the
    /// tag-replacing legacy shape a foreign encoder may have written (the context tag standing in for the inner
    /// SEQUENCE's own tag) — a lenient read is defensible, a lenient write is not (the writer always emits the
    /// explicit shape). See <see cref="RevocationSequenceOfMembers"/> for how the two are told apart.
    /// </para>
    /// <para>
    /// The <c>ocspVals</c> field carries bare <c>BasicOCSPResponse</c> structures (clause A.1.2.2) while the
    /// <c>otherRevVals</c> field carries whole <c>OCSPResponse</c> values under <c>id-ri-ocsp-response</c>
    /// (RFC 5940 §2). Both surface as whole <c>OCSPResponse</c> carriers tagged
    /// <see cref="PkiObjectKind.OcspResponse"/> — the form <see cref="OcspResponseVerification.VerifyAsync"/>
    /// reads — so a consumer never receives a bare <c>BasicOCSPResponse</c> under that tag.
    /// </para>
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
            AsnReader crlValues = RevocationSequenceOfMembers(revocationValues.ReadEncodedValue(), new Asn1Tag(TagClass.ContextSpecific, 0));
            while(crlValues.HasData && revocationLists.Count < MaximumEmbeddedRevocationObjects)
            {
                revocationLists.Add(Copy(crlValues.ReadEncodedValue(), PkiCertificateTags.X509Crl, pool));
            }
        }

        if(revocationValues.HasData && revocationValues.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            AsnReader ocspValues = RevocationSequenceOfMembers(revocationValues.ReadEncodedValue(), new Asn1Tag(TagClass.ContextSpecific, 1));
            while(ocspValues.HasData && ocspResponses.Count < MaximumEmbeddedRevocationObjects)
            {
                //ocspVals carries bare BasicOCSPResponse values (clause A.1.2.2); each surfaces as the whole
                //OCSPResponse OcspResponseVerification.VerifyAsync reads, so it is wrapped into that shape here.
                ocspResponses.Add(Copy(WrapBasicResponseAsOcspResponse(ocspValues.ReadEncodedValue().Span), PkiCertificateTags.OcspResponse, pool));
            }
        }

        if(revocationValues.HasData && revocationValues.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true))
        {
            //otherRevVals [2] is OtherRevVals ::= SEQUENCE { otherRevValType OID, otherRevVals SEQUENCE OF ANY }
            //(clause A.1.2.2). The module's EXPLICIT TagDefault gives the conformant shape [2] { OtherRevVals
            //SEQUENCE { ... } }; a tag-replacing legacy encoder wrote [2] AS the OtherRevVals content, its first
            //child the OID rather than a SEQUENCE. Both are read (lenient read, strict write), told apart by the
            //first child's tag. RFC 5940 §2's id-ri-ocsp-response types a whole OCSPResponse; any other
            //otherRevValType names a format outside RFC 5280/RFC 6960 and is consumed so the structure closes.
            AsnReader otherField = revocationValues.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            AsnReader otherRevocationValues = otherField.HasData && otherField.PeekTag() == Asn1Tag.Sequence
                ? otherField.ReadSequence()
                : otherField;
            string otherRevValType = otherRevocationValues.ReadObjectIdentifier();
            if(string.Equals(otherRevValType, WellKnownOids.OcspResponseRevocationInfo, StringComparison.Ordinal))
            {
                AsnReader responses = otherRevocationValues.ReadSequence();
                while(responses.HasData && ocspResponses.Count < MaximumEmbeddedRevocationObjects)
                {
                    ocspResponses.Add(Copy(responses.ReadEncodedValue(), PkiCertificateTags.OcspResponse, pool));
                }
            }
        }

        revocationValues.ThrowIfNotEmpty();
    }


    /// <summary>
    /// Returns a reader positioned at the members of a <c>crlVals</c>/<c>ocspVals</c> field, accepting both the
    /// conformant EXPLICIT-TAGS shape (<c>[n] { SEQUENCE OF Value }</c>, per the Annex D module's
    /// <c>DEFINITIONS EXPLICIT TAGS</c>) and the tag-replacing legacy shape a foreign encoder may have written
    /// (<c>[n] { Value, ... }</c>). Lenient read, strict write.
    /// </summary>
    /// <param name="fieldTlv">The whole encoding of the <c>[n]</c> field.</param>
    /// <param name="fieldTag">The field's context tag (<c>[0]</c> for <c>crlVals</c>, <c>[1]</c> for <c>ocspVals</c>).</param>
    /// <returns>A reader over the field's values.</returns>
    /// <remarks>
    /// The two shapes coincide only when the field holds a single element that is a SEQUENCE. They are told
    /// apart structurally: each <c>Value</c> (a <c>CertificateList</c>, RFC 5280 §5.1, or a
    /// <c>BasicOCSPResponse</c>, RFC 6960 §4.2.1) carries a mandatory BIT STRING signature among its members, so
    /// a field whose first element is a SEQUENCE all of whose members are themselves SEQUENCEs is the explicit
    /// <c>SEQUENCE OF</c> (each member a <c>Value</c>), whereas a first element with any non-SEQUENCE member is a
    /// lone legacy <c>Value</c>.
    /// </remarks>
    private static AsnReader RevocationSequenceOfMembers(ReadOnlyMemory<byte> fieldTlv, Asn1Tag fieldTag)
    {
        AsnReader field = new AsnReader(fieldTlv, AsnEncodingRules.DER).ReadSequence(fieldTag);
        if(!field.HasData || field.PeekTag() != Asn1Tag.Sequence)
        {
            return field;
        }

        AsnReader firstMembers = new AsnReader(field.PeekEncodedValue(), AsnEncodingRules.DER).ReadSequence();
        bool explicitSequenceOf = firstMembers.HasData;
        int probed = 0;
        while(firstMembers.HasData && probed++ < MaximumEmbeddedRevocationObjects)
        {
            if(firstMembers.PeekTag() != Asn1Tag.Sequence)
            {
                explicitSequenceOf = false;
                break;
            }

            firstMembers.ReadEncodedValue();
        }

        return explicitSequenceOf ? field.ReadSequence() : field;
    }


    /// <summary>
    /// Wraps a bare <c>BasicOCSPResponse</c> as the whole <c>OCSPResponse</c> that
    /// <see cref="OcspResponseVerification.VerifyAsync"/> reads and <see cref="PkiCertificateTags.OcspResponse"/>
    /// names: a successful <c>responseStatus</c> followed by a <c>ResponseBytes</c> that types the basic response
    /// with <c>id-pkix-ocsp-basic</c> (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1">RFC 6960
    /// §4.2.1</see>). The pre-RFC-5940 <c>id-pkix-ocsp-basic</c> <c>otherRevInfo</c> form and the
    /// <c>revocation-values.ocspVals</c> form both carry the bare basic response, so surfacing them through this
    /// one canonical shape is what keeps a consumer from ever receiving a bare <c>BasicOCSPResponse</c> under the
    /// whole-response tag. A whole <c>OCSPResponse</c> (the RFC 5940 §2 <c>id-ri-ocsp-response</c> form) needs no
    /// wrapping and is surfaced as it stands.
    /// </summary>
    /// <param name="basicResponse">The DER-encoded <c>BasicOCSPResponse</c>.</param>
    /// <returns>The DER-encoded whole <c>OCSPResponse</c>.</returns>
    private static byte[] WrapBasicResponseAsOcspResponse(ReadOnlySpan<byte> basicResponse)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteEnumeratedValue(OcspResponseStatus.Successful);
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(WellKnownOids.OcspBasicResponseType);
                    writer.WriteOctetString(basicResponse);
                }
            }
        }

        return writer.Encode();
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
                //§10.2.1). Clause 5.4.2.2 of ETSI EN 319 122-1 places an embedded OCSP response here under RFC
                //5940 §2's id-ri-ocsp-response, whose otherRevInfo is a whole OCSPResponse; the pre-RFC-5940
                //id-pkix-ocsp-basic (RFC 6960 §4.2.1) instead carries a bare BasicOCSPResponse. Both are
                //recognised, and both surface as the whole OCSPResponse OcspResponseVerification.VerifyAsync
                //reads and PkiCertificateTags.OcspResponse names — the basic form wrapped into that shape so a
                //consumer never receives a bare BasicOCSPResponse under the whole-response tag.
                AsnReader otherRevocationInfo = candidateReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                string format = otherRevocationInfo.ReadObjectIdentifier();
                if(string.Equals(format, WellKnownOids.OcspResponseRevocationInfo, StringComparison.Ordinal))
                {
                    ocspResponses.Add(otherRevocationInfo.ReadEncodedValue());
                }
                else if(string.Equals(format, WellKnownOids.OcspBasicResponseType, StringComparison.Ordinal))
                {
                    ocspResponses.Add(WrapBasicResponseAsOcspResponse(otherRevocationInfo.ReadEncodedValue().Span));
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
