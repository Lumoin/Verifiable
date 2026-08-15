using System;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The PAdES binding of the format-facts seam (the FOURTH binding, after <see cref="CAdESSignatureFacts"/>,
/// <c>CBAdESSignatureFacts</c> and <c>JAdESSignatureFacts</c>): it reads the CMS <c>SignedData</c> a PDF
/// Signature Dictionary's own <c>Contents</c> entry carries and presents it as the format-neutral
/// <see cref="SignatureFacts"/> the building blocks of clause 5.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> validate.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Composition, not re-parsing (RP-3, PA-6.3-h).</strong> ETSI EN 319 142-1 V1.2.1's own requirement h)
/// states outright that a PDF Signature Dictionary's <c>Contents</c> entry "shall contain a DER-encoded SignedData
/// object ... [that] forms a CAdES signature described in ETSI EN 319 122-1" — the CMS bytes a PAdES signature
/// carries are byte-identical to a CAdES signature's own <c>SignedDataObject</c>. Every delegate of <see cref="Seam"/>
/// therefore composes <see cref="CAdESSignatureFacts"/>'s own implementation unchanged (via the <c>format</c>
/// overload <see cref="CAdESSignatureFacts.ExtractAsync"/> grew for exactly this reuse) rather than re-walking the
/// identical ASN.1 a second time; only <see cref="SignatureFacts.Format"/> differs, so a Driving Application can
/// tell which base standard's own conformance clause 5.2.2 checked against.
/// </para>
/// <para>
/// <strong>What this binding does NOT cover: PAdES's own PDF-native LTV mechanism.</strong> Unlike CAdES's
/// <c>archive-time-stamp-v3</c> (an unsigned CMS attribute of the SAME <c>SignedData</c>, clause 5.5.3 of
/// ETSI EN 319 122-1), PAdES's own B-LT/B-LTA material — the DSS/VRI dictionaries (clause 5.4.2) and the Document
/// Time-stamp (clause 5.4.3, PA-6.3-T25/T27/T28/T29/T30) — lives entirely OUTSIDE the CMS object this binding
/// extracts facts from, as separate PDF objects a document's own incremental-update chain carries. Forcing that
/// PDF-native, whole-document-ByteRange-covering mechanism into the CMS-shaped
/// <see cref="SignatureFormatSeam.StateTimestampCoverage"/>/<see cref="SignatureFormatSeam.StateTimestampProtectsObject"/>
/// delegates below — which exist to state what one CMS unsigned attribute's <c>messageImprint</c> covers — would
/// misrepresent the mechanism rather than model it; <see cref="EmbeddedTimestamp.Class"/> never carries
/// <see cref="SignatureTimestampClass.ArchiveTimestamp"/> for a PAdES signature's own facts. The B-LT/B-LTA
/// determination is instead made by <see cref="PAdESLifecycleValidation"/>, composing <see cref="PdfDssReader"/>
/// and <see cref="PAdESDocTimeStampValidation"/> directly over the PDF byte surface — the shape the CAdES LTA
/// machinery's own precedent teaches (compose at the level a mechanism actually lives, never force-fit).
/// </para>
/// <para>
/// <strong>The mapping discipline (cannot-process → INDETERMINATE, never a crypto-failure verdict).</strong> When
/// <see cref="BuildExtractionContext"/>'s own caller (<see cref="PAdESLifecycleValidation"/>) cannot even locate a
/// well-formed Signature Dictionary — a malformed <c>ByteRange</c>, an unsupported <c>SubFilter</c>, missing
/// <c>Contents</c> — that PDF-side failure is reported through <see cref="PAdESSignatureStatus"/> (as
/// <see cref="PAdESSignatureValidation"/> already does) BEFORE this binding is ever reached; nothing here forces a
/// verdict onto bytes that are not even shaped like a signature. Once reached, <see cref="ExtractAsync"/> itself
/// reports a CMS structure it cannot parse as <see cref="SignatureFactsStatus.FormatFailure"/> — the
/// <c>FAILED</c> outcome of clause 5.2.2.3 — never an exception and never
/// <see cref="SignatureCryptographicOutcome.SignatureValueFailure"/>; format-checking failures and cryptographic
/// failures are Table 15's own separate rows, and this binding keeps them separate exactly as
/// <see cref="CAdESSignatureFacts"/> does.
/// </para>
/// </remarks>
public static class PAdESSignatureFacts
{
    /// <summary>
    /// The seam bundle a caller hands the building blocks to validate a PAdES signature's own embedded CMS
    /// object. Every delegate composes <see cref="CAdESSignatureFacts"/>'s own implementation (RP-3).
    /// </summary>
    public static SignatureFormatSeam Seam { get; } = new()
    {
        Format = SignatureFormatIdentifier.PAdES,
        ExtractFacts = ExtractAsync,
        VerifyCryptography = CAdESSignatureFacts.VerifyCryptographyAsync,
        StateTimestampCoverage = CAdESSignatureFacts.StateTimestampCoverageAsync,
        StateTimestampProtectsObject = CAdESSignatureFacts.StateTimestampProtectsObjectAsync
    };


    /// <summary>
    /// Extracts the facts of a PAdES signature's own embedded CMS object — the
    /// <see cref="ExtractSignatureFactsAsyncDelegate"/> implementation of the bundle in <see cref="Seam"/>.
    /// </summary>
    /// <param name="context">The Signed Data Object (a PDF Signature Dictionary's own <c>Contents</c>) and the <c>ByteRange</c>-gapped Signer's Document beside it (see <see cref="BuildExtractionContext"/>).</param>
    /// <param name="pool">The memory pool every carrier the returned facts own is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The extracted facts, stamped <see cref="SignatureFormatIdentifier.PAdES"/>. The caller disposes them.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static ValueTask<SignatureFacts> ExtractAsync(
        SignatureFactsExtractionContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        return CAdESSignatureFacts.ExtractAsync(context, pool, cancellationToken, SignatureFormatIdentifier.PAdES);
    }


    /// <summary>
    /// Builds the extraction context for one located Signature Dictionary: a right-sized copy of its own
    /// <c>Contents</c> as the Signed Data Object (PA-6.3-h), and its own <c>ByteRange</c>-gapped bytes as the one
    /// Signer's Document a detached PAdES signature (PA-6.3-l, <c>ETSI.CAdES.detached</c>) needs for clause
    /// 5.2.7.4 step 1).
    /// </summary>
    /// <param name="signature">The located Signature Dictionary — the caller (<see cref="PAdESLifecycleValidation"/>) has already checked its own <c>SubFilter</c>/<c>ByteRange</c> coverage (PA-6.3-k/l) before reaching this point.</param>
    /// <param name="pool">The memory pool the returned carriers are rented from.</param>
    /// <returns>
    /// The extraction context. Unlike most instances of this record, BOTH <see cref="SignatureFactsExtractionContext.SignedDataObject"/>
    /// and its one <see cref="SignatureFactsExtractionContext.SignerDocuments"/> entry are carriers this call
    /// freshly rents — the caller disposes both once the run that consumes them is complete.
    /// </returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signature"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static SignatureFactsExtractionContext BuildExtractionContext(PdfSignatureDictionary signature, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(pool);

        SignedContentMemory detachedContent = PAdESSignatureValidation.BuildByteRangeContent(signature, pool);
        if(!TryTrimToDerLength(signature.Contents, pool, out CmsSignedData? rightSizedContents))
        {
            //Unreachable through PAdESLifecycleValidation's own call order: this context is built only after
            //PAdESSignatureValidation.ValidateSignatureAsync already proved -- via the SAME TryTrimToDerLength gate
            //-- that signature.Contents trims to a well-formed DER value followed by nothing but zero octets.
            //A caller reaching this method over bytes that were never proven that way is a composition fault, not
            //an attacker-reachable outcome this method itself needs to report through Unverified carriage.
            detachedContent.Dispose();

            throw new InvalidOperationException(
                "The Signature Dictionary's own Contents does not trim to a well-formed DER SignedData followed " +
                "by all-zero padding; PAdESSignatureValidation.ValidateSignatureAsync must reject this signature " +
                "before PAdESLifecycleValidation ever reaches BuildExtractionContext.");
        }

        return new SignatureFactsExtractionContext
        {
            SignedDataObject = rightSizedContents,
            SignerDocuments = [new SignerDocumentReference { Identifier = "PAdES-ByteRange", Content = detachedContent }]
        };
    }


    /// <summary>
    /// Copies exactly the encoded octets of the outer DER TLV a PDF <c>Contents</c> value's own decoded bytes
    /// start with, REQUIRING the discarded suffix to be all-zero octets — the reserved-capacity padding
    /// <see cref="PdfIncrementalUpdateWriter.CompleteSignature"/> writes past the real signature's own end to fill
    /// out <see cref="PAdESSigningRequest.ContentsCapacityBytes"/>'s reserved <c>Contents</c> capacity, and the
    /// ONLY shape this method tolerates discarding: a non-zero trailing octet is the smuggling vector a second,
    /// unaccounted-for structure appended in that same reserved space would open, and fails this method closed
    /// rather than silently trimming it away.
    /// </summary>
    /// <param name="paddedContents">The Signature Dictionary's own decoded <c>Contents</c> — the real <c>SignedData</c> TLV, expected to be followed by zero or more trailing <c>0x00</c> padding octets and nothing else.</param>
    /// <param name="pool">The memory pool the right-sized copy is rented from.</param>
    /// <param name="trimmed">The right-sized copy, when this method returns <see langword="true"/>. The caller disposes it.</param>
    /// <returns><see langword="true"/> when <paramref name="paddedContents"/> is a well-formed DER TLV followed by nothing but zero octets (possibly none).</returns>
    /// <remarks>
    /// Nothing about legitimate padding is attacker-controlled — it is the reserved-capacity convention clause
    /// 7.3.4 of ISO 32000-1 requires ("space for the Contents value to be allocated before the message digest is
    /// computed") — but bounding what this method accepts as "padding" to exactly the all-zero octets this
    /// library's own writer ever emits (never a second DER structure, never attacker-chosen bytes) is what makes
    /// the trim safe to apply before <see cref="ManagedCmsVerification"/>'s own whole-buffer trailing-data check
    /// (<c>AsnReader.ThrowIfNotEmpty()</c>) runs over the SAME bytes elsewhere in this signature's own validation
    /// (<see cref="PAdESSignatureValidation.ValidateSignatureAsync"/> calls this method first, over the identical
    /// <c>signature.Contents</c>, before ever reaching <see cref="CAdESVerification.VerifyDetachedAsync"/>).
    /// </remarks>
    internal static bool TryTrimToDerLength(CmsSignedData paddedContents, BaseMemoryPool pool, [NotNullWhen(true)] out CmsSignedData? trimmed)
    {
        trimmed = null;
        ReadOnlySpan<byte> padded = paddedContents.AsReadOnlySpan();
        int consumed;
        try
        {
            AsnDecoder.ReadEncodedValue(padded, AsnEncodingRules.DER, out _, out _, out consumed);
        }
        catch(AsnContentException)
        {
            return false;
        }

        ReadOnlySpan<byte> discardedSuffix = padded[consumed..];
        for(int i = 0; i < discardedSuffix.Length; ++i)
        {
            if(discardedSuffix[i] != 0)
            {
                return false;
            }
        }

        trimmed = CmsSignedData.FromBytes(padded[..consumed], pool);

        return true;
    }
}
