using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The highest PAdES baseline level a document's own newest signature was shown to reach — the capstone-facing
/// summary <see cref="PAdESLifecycleValidation.ValidateAsync"/> reports alongside the process-level
/// <see cref="SignatureValidationIndication"/> Table 5 of clause 5.1.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> mandates.
/// </summary>
public enum PAdESReachedLevel
{
    /// <summary>No level was reached — the signature itself did not validate, or no Signature Dictionary was located. The value of an unset field, by design.</summary>
    None = 0,

    /// <summary>PAdES-B-B (PA-6.1-DEF-a) was reached.</summary>
    BB = 1,

    /// <summary>PAdES-B-T (PA-6.1-DEF-b) was reached: a verified trusted token proves the signature existed at a given date and time.</summary>
    BT = 2,

    /// <summary>PAdES-B-LT (PA-6.1-DEF-c) was reached: a DSS dictionary carrying at least one certificate, CRL or OCSP response is present (PA-6.3-T27).</summary>
    BLT = 3,

    /// <summary>PAdES-B-LTA (PA-6.1-DEF-d) was reached: at least one valid Document Time-stamp is present over a document already carrying B-LT material (PA-6.3-T30).</summary>
    BLTA = 4
}


/// <summary>
/// The PAdES facts a TOTAL-PASSED <see cref="PAdESLifecycleValidation.ValidateAsync"/> run promotes into an
/// identity-bound <see cref="Verified{T}"/> — the record a relying party consumes once the full EN 319
/// 102-1 pipeline concluded and the signing certificate's own digest was bound against the signature's signed
/// signing-certificate reference. Mirrors <c>JAdESVerifiedSignatureFacts</c>, the family's first promotion
/// template.
/// </summary>
/// <remarks><strong>Ownership.</strong> This instance owns <see cref="SigningCertificate"/> — a right-sized
/// copy of the certificate the cryptographic verification ran under, taken because the borrowed original
/// belongs to the validation run's resources and is released when the run's outcome disposes;
/// <see cref="Dispose"/> releases the copy.</remarks>
public sealed class PAdESVerifiedSignatureFacts: IDisposable
{
    private bool disposed;

    internal PAdESVerifiedSignatureFacts(PAdESReachedLevel reachedLevel, PkiCertificateMemory signingCertificate)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ReachedLevel = reachedLevel;
        SigningCertificate = signingCertificate;
    }

    /// <summary>Gets the highest PAdES baseline level shown to be reached.</summary>
    public PAdESReachedLevel ReachedLevel { get; }

    /// <summary>Gets the signing certificate the pipeline verified under and this run bound by digest — a
    /// right-sized copy this instance owns.</summary>
    public PkiCertificateMemory SigningCertificate { get; }

    /// <summary>Disposes the owned signing-certificate copy.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            SigningCertificate.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// One firewalled outcome of <see cref="PAdESLifecycleValidation.ValidateAsync"/>: the level reached and the
/// process-level indication/sub-indications Table 5 of clause 5.1.3 of ETSI EN 319 102-1 V1.4.1 mandates, pinned
/// rather than inferred by the caller.
/// </summary>
[System.Diagnostics.DebuggerDisplay("PAdESLifecycleResult: {ReachedLevel}, {Indication}")]
public sealed class PAdESLifecycleResult: IDisposable
{
    private bool disposed;


    /// <summary>Gets the highest PAdES baseline level shown to be reached.</summary>
    public required PAdESReachedLevel ReachedLevel { get; init; }

    /// <summary>Gets the process-level status indication (<c>TOTAL-PASSED</c>/<c>TOTAL-FAILED</c>/<c>INDETERMINATE</c>).</summary>
    public required SignatureValidationIndication Indication { get; init; }

    /// <summary>Gets the sub-indications explaining a non-<c>TotalPassed</c> indication (Table 6); empty on <see cref="SignatureValidationIndication.TotalPassed"/>.</summary>
    public IReadOnlyList<SignatureValidationSubIndication> SubIndications { get; init; } = [];

    /// <summary>Gets what could be stated about the outcome beyond the indication, for a Driving Application to present.</summary>
    public string? Reason { get; init; }

    /// <summary>
    /// The identity-bound promoted facts when the run reached TOTAL-PASSED and bound the signing certificate's
    /// digest against the signature's signed reference; <see langword="null"/> on every non-passing outcome. The
    /// sole route through which this class hands a relying party a
    /// <see cref="Verified{PAdESVerifiedSignatureFacts}"/>. Owned by this instance; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public Verified<PAdESVerifiedSignatureFacts>? VerifiedSignature { get; init; }


    /// <summary>Mints a <c>TOTAL-PASSED</c> result at the stated level, carrying <paramref name="verifiedSignature"/>.</summary>
    internal static PAdESLifecycleResult Passed(PAdESReachedLevel level, Verified<PAdESVerifiedSignatureFacts>? verifiedSignature) =>
        new() { ReachedLevel = level, Indication = SignatureValidationIndication.TotalPassed, VerifiedSignature = verifiedSignature };


    /// <summary>Mints a non-passing result carrying the level reached before the failure/indeterminacy and its sub-indication.</summary>
    internal static PAdESLifecycleResult NotPassed(
        PAdESReachedLevel level, SignatureValidationIndication indication, SignatureValidationSubIndication subIndication, string? reason = null) =>
        new() { ReachedLevel = level, Indication = indication, SubIndications = [subIndication], Reason = reason };


    /// <summary>Disposes <see cref="VerifiedSignature"/>'s wrapped facts when present.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            VerifiedSignature?.Value.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// The capstone-facing PAdES lifecycle orchestrator: determines the highest PAdES baseline
/// level a document's own newest signature reaches by composing three PDF-native building blocks at the level
/// each one actually applies —
/// <see cref="PAdESSignatureValidation"/> (the PA-6.3-k/l/T12/T13 framework gates and B-B/B-T cryptography),
/// the full EN 319 102-1 engine's validation process for Signatures with Time (clause 5.5, over the embedded CMS
/// object through <see cref="PAdESSignatureFacts.Seam"/> — chain building, revocation and best-signature-time),
/// <see cref="PdfDssReader"/> (B-LT), and <see cref="PAdESDocTimeStampValidation"/> (B-LTA) — rather than forcing
/// PAdES's own PDF-native LTV material through the CMS-shaped archive-time-stamp seam CAdES uses (see
/// <see cref="PAdESSignatureFacts"/>'s own remarks for why that composition would misrepresent the mechanism).
/// </summary>
public static class PAdESLifecycleValidation
{
    /// <summary>
    /// Validates a document's own newest signature end to end and reports the highest PAdES baseline level it
    /// reaches, from wire bytes alone.
    /// </summary>
    /// <param name="document">The whole PDF document's bytes.</param>
    /// <param name="constraints">The X.509/cryptographic constraints the validation process for Signatures with Time (clause 5.5) applies.</param>
    /// <param name="completeCertificateChain">The chain-building seam clause 5.2.6.4 step 2) composes.</param>
    /// <param name="validateCertificateChain">The RFC 5280 §6.1 path validation seam clause 5.2.6.4 step 4) composes.</param>
    /// <param name="checkRevocation">The revocation seam consulted for a certificate the caller supplied no revocation status about, or <see langword="null"/> for an offline run.</param>
    /// <param name="currentTime">The current time — NOTE 1 of clause 5.1.3's determination instant.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The lifecycle result. On a TOTAL-PASSED run it owns the minted <see cref="PAdESLifecycleResult.VerifiedSignature"/>
    /// — the caller disposes the returned result; every OTHER intermediate carrier is still released before this
    /// method returns.
    /// </returns>
    /// <exception cref="ArgumentNullException">When <paramref name="constraints"/>, <paramref name="completeCertificateChain"/>, <paramref name="validateCertificateChain"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<PAdESLifecycleResult> ValidateAsync(
        ReadOnlyMemory<byte> document,
        SignatureValidationConstraints constraints,
        CompleteCertificateChainAsyncDelegate completeCertificateChain,
        ValidateCertificateChainAsyncDelegate validateCertificateChain,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        DateTimeOffset currentTime,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(constraints);
        ArgumentNullException.ThrowIfNull(completeCertificateChain);
        ArgumentNullException.ThrowIfNull(validateCertificateChain);
        ArgumentNullException.ThrowIfNull(pool);

        int newestOrdinaryDocumentLength;
        using(PdfByteSurfaceParseResult probe = PdfByteSurfaceReader.Locate(document, pool))
        {
            if(!probe.IsSuccess || probe.SignatureDictionaries is not { Count: > 0 } candidates)
            {
                return PAdESLifecycleResult.NotPassed(
                    PAdESReachedLevel.None, SignatureValidationIndication.TotalFailed, SignatureValidationSubIndication.FormatFailure,
                    probe.FailureReason ?? "No Signature Dictionary was located.");
            }

            //A Document Time-stamp (PA-6.3-y, SubFilter ETSI.RFC3161) matches the same {ByteRange, Contents}
            //candidate shape a CAdES.detached signature does; once a document reaches B-LTA the newest CANDIDATE
            //is the Document Time-stamp, not the ordinary signature this method's own facts extraction and
            //framework-gate check are about (PAdESDocTimeStampValidation, composed separately below, owns the
            //Document Time-stamp itself). The newest ORDINARY signature is found explicitly instead of assumed to
            //be the list's own last entry — this probe reads only its own ByteRange (a value type), so nothing it
            //owns needs to outlive this scope.
            int ordinaryIndex = -1;
            for(int i = candidates.Count - 1; i >= 0; --i)
            {
                if(candidates[i].SubFilter == PdfSubFilter.EtsiCAdESDetached)
                {
                    ordinaryIndex = i;

                    break;
                }
            }

            if(ordinaryIndex < 0)
            {
                return PAdESLifecycleResult.NotPassed(
                    PAdESReachedLevel.None, SignatureValidationIndication.TotalFailed, SignatureValidationSubIndication.FormatFailure,
                    "No ordinary (ETSI.CAdES.detached) Signature Dictionary was located.");
            }

            newestOrdinaryDocumentLength = candidates[ordinaryIndex].ByteRange.DocumentLength;
        }

        //PA-6.3-k's own coverage obligation is scoped to the document AS IT EXISTED when the signature was minted
        //-- DSS/Document Time-stamp material a LATER incremental update appends is legitimate (PA-5.4.2.3-20,
        //PA-5.4.3-12 both carve exactly this out), never a shadow-attack signal, and every augmentation verb
        //here is append-only/byte-preserving (proved by PAdESSignatureAugmentationTests's own retained-bytes
        //assertions) -- so PAdESSignatureValidation.ValidateAsync's own "the newest signature must reach the
        //document's true EOF" rule is applied here to the TRUNCATED view the signature itself claims, not to
        //whatever the document has since grown to.
        //
        //Truncating alone would silently accept ANY suffix an attacker appends past that claimed length -- the
        //very shadow attack PA-6.3-k exists to catch, reopened through this method's own LTV path: the entry point
        //(PAdESSignatureValidation.ValidateAsync, called over the FULL document) would reject such a document,
        //while this method, validating only the truncated prefix, would not even notice it. The discarded suffix
        //is therefore independently re-walked here BEFORE anything else runs: every object it declares must be
        //either the one recognised DSS-catalog-extension shape this library's own writer produces, or genuinely
        //new DSS/VRI/Document-Time-stamp/supporting material -- never a redefinition of anything the covered
        //prefix already decided, and never a new '/Root'.
        if(!TryValidateDiscardedSuffix(document, newestOrdinaryDocumentLength, out string? suffixFailureReason))
        {
            return PAdESLifecycleResult.NotPassed(
                PAdESReachedLevel.None, SignatureValidationIndication.TotalFailed, SignatureValidationSubIndication.FormatFailure,
                suffixFailureReason);
        }

        //Re-locating over the truncated view below also yields a Signature Dictionary this method can safely
        //keep alive for its own remaining lifetime.
        ReadOnlyMemory<byte> signatureView = document[..newestOrdinaryDocumentLength];
        using PAdESValidationResult pdfValidation = await PAdESSignatureValidation.ValidateAsync(signatureView, pool, cancellationToken).ConfigureAwait(false);
        if(!pdfValidation.IsSuccess || pdfValidation.Signatures is not { Count: > 0 } signatures)
        {
            return PAdESLifecycleResult.NotPassed(
                PAdESReachedLevel.None, SignatureValidationIndication.TotalFailed, SignatureValidationSubIndication.FormatFailure,
                pdfValidation.FailureReason ?? "No Signature Dictionary was located.");
        }

        PAdESSignatureValidationResult newestSignature = signatures[^1];
        if(!newestSignature.IsValid)
        {
            return PAdESLifecycleResult.NotPassed(
                PAdESReachedLevel.None, SignatureValidationIndication.TotalFailed, MapPdfSideFailure(newestSignature.Status),
                $"PAdESSignatureValidation reported {newestSignature.Status}.");
        }

        using PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(signatureView, pool);
        PdfSignatureDictionary newestDictionary = located.SignatureDictionaries![^1];

        SignatureFactsExtractionContext extractionContext = PAdESSignatureFacts.BuildExtractionContext(newestDictionary, pool);
        try
        {
            var seams = new SignatureValidationSeams
            {
                Format = PAdESSignatureFacts.Seam,
                CompleteCertificateChain = completeCertificateChain,
                ValidateCertificateChain = validateCertificateChain,
                CheckRevocation = checkRevocation
            };

            var inputs = new SignatureValidationInputs
            {
                SignedDataObject = extractionContext.SignedDataObject,
                Constraints = constraints,
                TimestampConstraints = constraints,
                SignerDocuments = extractionContext.SignerDocuments
            };

            using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
                inputs, seams, SignatureValidationProcessSelection.SignaturesWithTime, SignatureValidationCapabilities.All,
                currentTime, pool, cancellationToken).ConfigureAwait(false);

            if(outcome.Conclusion.Indication != SignatureValidationIndication.TotalPassed)
            {
                IReadOnlyList<SignatureValidationSubIndication> subIndications = outcome.Conclusion.SubIndications.Count > 0
                    ? outcome.Conclusion.SubIndications
                    : [SignatureValidationSubIndication.Custom];

                return new PAdESLifecycleResult
                {
                    ReachedLevel = PAdESReachedLevel.None,
                    Indication = outcome.Conclusion.Indication,
                    SubIndications = subIndications,
                    Reason = "The validation process for Signatures with Time (clause 5.5) did not reach TOTAL-PASSED over the embedded CMS object."
                };
            }

            PAdESReachedLevel level = newestSignature.Level == AdESBaselineLevel.BT ? PAdESReachedLevel.BT : PAdESReachedLevel.BB;

            //The ladder is cumulative, never a set of independently-satisfiable per-level conditions: leg 2's own
            //Table 1 states the trusted-time SERVICE (PA-6.3-T23) as "shall be provided" at B-T AND at B-LT AND at
            //B-LTA alike (clause 6.2.2's own presence vocabulary carries the SAME value forward through the higher
            //levels, never resets it), and clause 6.1's own definitions read the same way: PA-6.1-DEF-c states
            //B-LT "provides requirements for the incorporation of ALL the material required for validating the
            //signature" -- which already presupposes a trusted time token exists to validate (PA-6.1-DEF-b) --
            //while PA-6.1-DEF-d states B-LTA "allow[s] validation of the signature long time after its
            //generation", meaningless without B-LT's own material first. A DSS present over a signature that
            //never reached B-T therefore reports at most B-B, never B-LT; a Document Time-stamp over a document
            //that never reached B-LT reports at most whatever level it already carried.
            using PdfDssParseResult dss = PdfDssReader.Locate(document, pool);
            bool hasDss = dss.IsSuccess && dss.HasDss && HasValidationMaterial(dss.Dss!);
            if(hasDss && level == PAdESReachedLevel.BT)
            {
                level = PAdESReachedLevel.BLT;
            }

            using PAdESDocTimeStampCollectionResult docTimeStamps = await PAdESDocTimeStampValidation.ValidateAsync(document, pool, cancellationToken).ConfigureAwait(false);
            if(level == PAdESReachedLevel.BLT && docTimeStamps.IsSuccess && HasAtLeastOneValidTimestamp(docTimeStamps.DocTimeStamps))
            {
                level = PAdESReachedLevel.BLTA;
            }

            Verified<PAdESVerifiedSignatureFacts>? verifiedSignature = await TryMintBoundSignatureAsync(
                outcome, level, pool, cancellationToken).ConfigureAwait(false);
            if(verifiedSignature is null)
            {
                //Fail-closed: the EN 319 102-1 pipeline reached TOTAL-PASSED, yet the signing certificate's
                //own digest could not be re-bound against the signature's signed reference. Step 2)'s identification
                //already matched that reference, so this is a genuine internal inconsistency, not a conformant
                //document -- refuse to hand back a TOTAL-PASSED result carrying no bound proof (the exact gap the
                //verified-binding arc closed), rather than silently downgrading to an unbound/asserted mint.
                return new PAdESLifecycleResult
                {
                    ReachedLevel = PAdESReachedLevel.None,
                    Indication = SignatureValidationIndication.Indeterminate,
                    SubIndications = [SignatureValidationSubIndication.Custom],
                    Reason = "The validation process reached TOTAL-PASSED, but the signing certificate's own digest could not be bound against the signature's signed signing-certificate reference."
                };
            }

            return PAdESLifecycleResult.Passed(level, verifiedSignature);
        }
        finally
        {
            //SignatureFactsExtractionContext holds no ownership of its own (SignatureFactsExtractionContext's own
            //remarks); both carriers PAdESSignatureFacts.BuildExtractionContext rented -- the right-sized Signed
            //Data Object copy and the ByteRange-gapped Signer's Document -- are this method's own responsibility
            //to release, exactly once, regardless of which branch above returned.
            (extractionContext.SignedDataObject as IDisposable)?.Dispose();
            for(int i = 0; i < extractionContext.SignerDocuments.Count; ++i)
            {
                extractionContext.SignerDocuments[i].Content?.Dispose();
            }
        }
    }


    /// <summary>
    /// Mints the identity-bound <see cref="Verified{PAdESVerifiedSignatureFacts}"/> for a TOTAL-PASSED run by
    /// recomputing the certificate the cryptographic verification ran under and binding it against the signature's
    /// own signed signing-certificate reference (<see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>),
    /// then witness-minting (<see cref="Verified{T}.TryCreateBound"/>). Returns <see langword="null"/> only in the
    /// should-not-occur case where the pipeline reached TOTAL-PASSED yet no certificate/reference binding can be
    /// re-established — a genuine internal inconsistency, since step 2)'s signing-certificate identification already
    /// matched the same reference. Owns nothing on a null return: the facts (and their certificate copy) are
    /// disposed before returning null.
    /// </summary>
    /// <param name="outcome">The TOTAL-PASSED outcome, still alive.</param>
    /// <param name="level">The PAdES baseline level the run reached.</param>
    /// <param name="pool">The memory pool the certificate copy and digest recompute rent from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The minted, identity-bound facts, or <see langword="null"/> when the bind could not be re-established.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "facts is disposed explicitly on both non-success paths (a refused bind and a rethrown " +
            "exception); on the success path ownership transfers to the caller through the returned " +
            "Verified<PAdESVerifiedSignatureFacts>, which PAdESLifecycleResult.Dispose releases via its own " +
            "VerifiedSignature member -- mirrors JAdESValidationResult.Success's identical traced-ownership case.")]
    private static async ValueTask<Verified<PAdESVerifiedSignatureFacts>?> TryMintBoundSignatureAsync(
        SignatureValidationOutcome outcome, PAdESReachedLevel level, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        if(outcome.BasicValidation.CryptographicVerification is not { SigningCertificate: PkiCertificateMemory verifiedCertificate } cryptographicVerification)
        {
            return null;
        }

        PkiCertificateMemory certificateCopy = CAdESSignatureFacts.Copy(
            verifiedCertificate.AsReadOnlyMemory(), PkiCertificateTags.X509Certificate, pool);
        var facts = new PAdESVerifiedSignatureFacts(level, certificateCopy);
        try
        {
            BoundProvenance? provenance = await BoundProvenance.TryBindByCertificateDigestAsync(
                outcome.BasicValidation.Signature.SigningCertificateReferences, cryptographicVerification, facts, pool, cancellationToken).ConfigureAwait(false);

            Verified<PAdESVerifiedSignatureFacts>? verified = provenance is null ? null : Verified<PAdESVerifiedSignatureFacts>.TryCreateBound(facts, provenance);
            if(verified is null)
            {
                facts.Dispose();
            }

            return verified;
        }
        catch
        {
            facts.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Re-walks a document's own discarded suffix — the bytes past <paramref name="claimedLength"/>, the newest
    /// ordinary signature's own <c>ByteRange.DocumentLength</c> — and fails closed unless every object it declares
    /// is either the one recognised DSS-catalog-extension shape <see cref="PdfIncrementalUpdateWriter.AppendValidationData"/>
    /// produces or genuinely new DSS/VRI/Document-Time-stamp/supporting material never before decided in the
    /// covered prefix, and no revision in the suffix restates a different trailer <c>/Root</c>.
    /// </summary>
    /// <param name="document">The whole document's bytes (untruncated).</param>
    /// <param name="claimedLength">The newest ordinary signature's own claimed coverage.</param>
    /// <param name="reason">Why the suffix was rejected, when this method returns <see langword="false"/>.</param>
    private static bool TryValidateDiscardedSuffix(ReadOnlyMemory<byte> document, int claimedLength, out string? reason)
    {
        reason = null;
        if(document.Length <= claimedLength)
        {
            return true;
        }

        ReadOnlySpan<byte> fullSpan = document.Span;
        ReadOnlySpan<byte> prefixSpan = fullSpan[..claimedLength];

        if(!PdfByteSurfaceReader.TryBuildObjectIndex(prefixSpan, out Dictionary<long, long> prefixObjectOffsets, out (long ObjectNumber, long Generation)? prefixRoot, out string? prefixError))
        {
            reason = $"The document's own covered prefix could not be re-indexed: {prefixError}";

            return false;
        }

        if(prefixRoot is not { } root)
        {
            reason = "The document's own covered prefix carries no trailer '/Root' entry.";

            return false;
        }

        if(!PdfByteSurfaceReader.TryLocateCatalog(document[..claimedLength], out PdfCatalogLocation? prefixCatalog, out string? catalogError))
        {
            reason = $"The document's own covered prefix's catalog could not be located: {catalogError}";

            return false;
        }

        if(!PdfByteSurfaceReader.TryLocateStartXref(fullSpan, out long fullStartXref))
        {
            reason = "The document's own cross-reference chain could not be walked: no 'startxref' keyword was found.";

            return false;
        }

        if(!PdfByteSurfaceReader.TryWalkXrefChainSections(fullSpan, fullStartXref, out List<PdfByteSurfaceReader.PdfXrefSection> sections, out string? sectionsError))
        {
            reason = $"The document's own cross-reference chain could not be walked: {sectionsError}";

            return false;
        }

        var suffixObjects = new Dictionary<long, long>();
        foreach(PdfByteSurfaceReader.PdfXrefSection section in sections)
        {
            if(section.Offset < claimedLength)
            {
                //Back inside the covered prefix -- every remaining section in the '/Prev' chain is prefix
                //material prefixObjectOffsets above already accounts for.
                break;
            }

            if(section.Root is { } sectionRoot && (sectionRoot.ObjectNumber != root.ObjectNumber || sectionRoot.Generation != root.Generation))
            {
                reason = "An incremental-update revision appended past the signature's own coverage declares a different trailer '/Root' than the covered prefix.";

                return false;
            }

            foreach((long objectNumber, long offset) in section.DeclaredObjects)
            {
                //Newest-wins within the suffix itself, mirroring TryWalkXrefChain's own merge semantics.
                suffixObjects.TryAdd(objectNumber, offset);
            }
        }

        if(!PdfByteSurfaceReader.TryBuildObjectIndex(fullSpan, out Dictionary<long, long> fullObjectOffsets, out _, out string? fullError))
        {
            reason = $"The document's own full cross-reference chain could not be re-indexed: {fullError}";

            return false;
        }

        foreach((long objectNumber, long offset) in suffixObjects)
        {
            bool wasAlreadyDecided = prefixObjectOffsets.ContainsKey(objectNumber);
            if(!wasAlreadyDecided)
            {
                if(offset < 0)
                {
                    //A freed object number the prefix never decided is inert: nothing resolvable to classify.
                    continue;
                }

                if(!PdfByteSurfaceReader.TryResolveObject(fullSpan, fullObjectOffsets, objectNumber, out PdfValue newValue, out string? newResolveError))
                {
                    reason = $"A new object appended past the signature's own coverage could not be resolved: {newResolveError}";

                    return false;
                }

                if(!IsLegitimateNewLtvObject(newValue))
                {
                    reason = $"An incremental-update revision appended past the signature's own coverage introduces object {objectNumber}, which is neither a DSS dictionary, a VRI dictionary, a Document Time-stamp candidate, nor a supporting DER stream (PA-6.3-k's own coverage boundary).";

                    return false;
                }

                continue;
            }

            //A redefinition of an object number the covered prefix already decided -- the shadow attack's own
            //shape -- is legitimate in exactly one case: the document catalog, rewritten to add its first '/DSS'
            //entry, byte-for-byte identical to PdfIncrementalUpdateWriter.AppendValidationData's own output.
            //Anything else redefining anything else is rejected outright.
            if(objectNumber != root.ObjectNumber || offset < 0)
            {
                reason = $"An incremental-update revision appended past the signature's own coverage redefines object {objectNumber}, already decided in the covered prefix.";

                return false;
            }

            if(!PdfByteSurfaceReader.TryResolveObject(fullSpan, fullObjectOffsets, objectNumber, out PdfValue newCatalogValue, out string? resolveError))
            {
                reason = $"The redefined document catalog could not be resolved: {resolveError}";

                return false;
            }

            if(!IsLegitimateDssCatalogRedefinition(fullSpan, prefixCatalog!, newCatalogValue, prefixObjectOffsets))
            {
                reason = "An incremental-update revision appended past the signature's own coverage redefines the document catalog outside the recognised DSS-append shape (PA-5.4.2.1-T1).";

                return false;
            }
        }

        return true;
    }


    /// <summary>Reports whether a genuinely new (never-before-decided) object appended past a signature's own coverage is recognisable LTV material: a DSS dictionary, a VRI dictionary, a new Document Time-stamp candidate, or a supporting DER stream (a certificate/CRL/OCSP-response/time-stamp-token blob).</summary>
    private static bool IsLegitimateNewLtvObject(PdfValue value)
    {
        if(value.Kind == PdfValueKind.Stream)
        {
            //An inert DER blob object -- never interpreted as anything but bytes when a DSS/VRI array references
            //it, and unreachable content when it is not (RP-1/RP-2's own targeted-reader boundary).
            return true;
        }

        if(value.Kind != PdfValueKind.Dictionary || value.Entries is null)
        {
            return false;
        }

        if(value.Entries.TryGetValue("Type", out PdfValue typeValue) && typeValue.Kind == PdfValueKind.Name &&
            (typeValue.Text == "DSS" || typeValue.Text == "VRI"))
        {
            return true;
        }

        //A genuine new Document Time-stamp candidate: the same {ByteRange, Contents} shape PdfByteSurfaceReader
        //itself discovers signature-shaped candidates by, discriminated to exactly PA-6.3-y's own SubFilter --
        //never a new ORDINARY signature, since this method's own caller already established the newest ordinary
        //(ETSI.CAdES.detached) signature in the WHOLE document is the one this lifecycle run is validating, so no
        //legitimate later one can exist past its own coverage.
        return value.Entries.ContainsKey("ByteRange") && value.Entries.ContainsKey("Contents") &&
            value.Entries.TryGetValue("SubFilter", out PdfValue subFilterValue) && subFilterValue.Kind == PdfValueKind.Name &&
            subFilterValue.Text == PdfSubFilter.EtsiRfc3161.Value;
    }


    /// <summary>
    /// Reports whether a redefined document-catalog object is byte-for-byte the one shape
    /// <see cref="PdfIncrementalUpdateWriter.AppendValidationData"/> ever produces: the prefix catalog's own raw
    /// entries text, copied verbatim, with exactly one <c>/DSS &lt;N&gt; 0 R</c> reference appended naming a
    /// genuinely new object number — never a redefinition PA-5.4.2.1-T1 does not sanction, and never reachable
    /// when the prefix catalog already carried a <c>DSS</c> entry (<see cref="PdfIncrementalUpdateWriter.AppendValidationData"/>'s
    /// own "first DSS revision only" invariant).
    /// </summary>
    private static bool IsLegitimateDssCatalogRedefinition(
        ReadOnlySpan<byte> fullDocument, PdfCatalogLocation prefixCatalog, PdfValue newCatalogValue,
        Dictionary<long, long> prefixObjectOffsets)
    {
        if(prefixCatalog.HasDssEntry || newCatalogValue.Kind != PdfValueKind.Dictionary)
        {
            return false;
        }

        ReadOnlySpan<byte> oldEntries = fullDocument.Slice(prefixCatalog.EntriesStart, prefixCatalog.EntriesEnd - prefixCatalog.EntriesStart);
        ReadOnlySpan<byte> newEntries = fullDocument.Slice(newCatalogValue.DictionaryContentStart, newCatalogValue.DictionaryContentEnd - newCatalogValue.DictionaryContentStart);

        if(newEntries.Length <= oldEntries.Length || !newEntries[..oldEntries.Length].SequenceEqual(oldEntries))
        {
            return false;
        }

        ReadOnlySpan<byte> tail = newEntries[oldEntries.Length..];
        int pos = 0;
        PdfValueParser.SkipWhitespaceAndComments(tail, ref pos);
        if(pos >= tail.Length || tail[pos] != (byte)'/' ||
            !PdfValueParser.TryParseValue(tail, ref pos, depth: 0, out PdfValue keyValue, out _) ||
            keyValue.Kind != PdfValueKind.Name || !string.Equals(keyValue.Text, "DSS", StringComparison.Ordinal))
        {
            return false;
        }

        if(!PdfValueParser.TryParseValue(tail, ref pos, depth: 0, out PdfValue dssReference, out _) || dssReference.Kind != PdfValueKind.Reference)
        {
            return false;
        }

        PdfValueParser.SkipWhitespaceAndComments(tail, ref pos);
        if(pos != tail.Length)
        {
            //Nothing else may follow -- exactly the one added '/DSS' key, matching AppendValidationData's own
            //fixed literal rendering exactly.
            return false;
        }

        //The referenced DSS object must itself be new suffix material -- never a covered-prefix object number --
        //its own shape (Type == "DSS") is independently validated when this method's own caller reaches it
        //through the normal new-object path, since the writer always declares it in the same cross-reference
        //section as the catalog rewrite.
        return !prefixObjectOffsets.ContainsKey(dssReference.Number);
    }


    /// <summary>Reports whether a located DSS dictionary carries at least one certificate, CRL or OCSP response (PA-6.3-T27's own B-LT cardinality, "&gt;= 1").</summary>
    private static bool HasValidationMaterial(PdfDssDictionary dss) =>
        dss.Certificates.Count > 0 || dss.CertificateRevocationLists.Count > 0 || dss.OcspResponses.Count > 0;


    /// <summary>Reports whether at least one located Document Time-stamp validated (PA-6.3-T30's own B-LTA cardinality, "&gt;= 1").</summary>
    private static bool HasAtLeastOneValidTimestamp(IReadOnlyList<PAdESDocTimeStampValidationResult>? docTimeStamps)
    {
        if(docTimeStamps is null)
        {
            return false;
        }

        for(int i = 0; i < docTimeStamps.Count; ++i)
        {
            if(docTimeStamps[i].IsValid)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Maps a PDF-side framework failure (PA-6.3-k/l/T12/T13, reached before the CMS-level engine ever ran) onto the process-level sub-indication vocabulary.</summary>
    private static SignatureValidationSubIndication MapPdfSideFailure(PAdESSignatureStatus status) => status switch
    {
        PAdESSignatureStatus.UnsupportedSubFilter or PAdESSignatureStatus.IncompleteByteRangeCoverage
            or PAdESSignatureStatus.MissingSigningTime or PAdESSignatureStatus.ProhibitedSigningTimeAttribute
            or PAdESSignatureStatus.Malformed or PAdESSignatureStatus.InvalidContentsPadding => SignatureValidationSubIndication.FormatFailure,
        PAdESSignatureStatus.InvalidSignature => SignatureValidationSubIndication.SignatureCryptographicFailure,
        PAdESSignatureStatus.MissingContentType or PAdESSignatureStatus.MissingSigningCertificate
            or PAdESSignatureStatus.SigningCertificateMismatch or PAdESSignatureStatus.UnsupportedHashAlgorithm
            => SignatureValidationSubIndication.SignatureConstraintsFailure,
        PAdESSignatureStatus.InvalidTimestamp or PAdESSignatureStatus.TimestampImprintMismatch
            => SignatureValidationSubIndication.SignatureConstraintsFailure,
        _ => SignatureValidationSubIndication.Custom
    };
}
