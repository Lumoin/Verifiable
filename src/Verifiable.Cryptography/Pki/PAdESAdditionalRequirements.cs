using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One additional requirement of Table 1's own lettered list a)-y) (clause 6.3, pp. 21-22 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see>), carrying the verbatim normative text and where its own obligation is
/// discharged — the established convention this library's other three bindings follow: enforce the structurally
/// checkable, disclose the caller-attested.
/// </summary>
/// <param name="Letter">The letter Table 1's own Requirements column names (e.g. <c>"d1"</c>/<c>"d2"</c> for the two sentences requirement d) states).</param>
/// <param name="Keyword">The RFC 2119 keyword tier, or <c>"DESCRIPTIVE"</c> for letter q), leg 2's own classification of its "can" phrasing as advisory rather than obligatory.</param>
/// <param name="Verbatim">The requirement's own text, quoted exactly from the PDF text layer (RP-5).</param>
/// <param name="EnforcementSite">
/// Where the obligation is discharged: a structural, fail-closed check this library performs (named by type and
/// member), reuse of the shipped CAdES surface unchanged (RP-3), or <c>"Disclosed"</c> when the obligation names
/// a fact only the caller can attest (a chain's full completeness, a caller's own duplication policy) — this
/// library carries the material the caller supplies without independently proving the caller supplied ALL of it.
/// </param>
[System.Diagnostics.DebuggerDisplay("PAdESAdditionalRequirement: {Letter}")]
public sealed record PAdESAdditionalRequirement(string Letter, string Keyword, string Verbatim, string EnforcementSite);


/// <summary>
/// The Table 1 lettered-requirement registry (PA-6.3-a..y, 30 letter-IDs across 25 letters) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 6.3. Data only — a documentation/audit surface over what
/// <see cref="PAdESSignatureCreation"/>, <see cref="PAdESSignatureValidation"/>, <see cref="PAdESSignatureAugmentation"/>
/// and <see cref="PAdESLifecycleValidation"/> already enforce or disclose, mirroring how <see cref="PAdESBaselineLevelTable"/>
/// documents Table 1's own grid without itself being a rule-evaluation engine.
/// </summary>
public static class PAdESAdditionalRequirements
{
    /// <summary>Every lettered requirement, in Table 1's own printed order (a) through y)).</summary>
    public static IReadOnlyList<PAdESAdditionalRequirement> All { get; } =
    [
        new("a", "shall", "The generator shall include the signing certificate in the SignedData.certificates field.",
            "PAdESSignatureCreation.SignAsync, via composed CAdESSignatureCreation.SignAsync (RP-3)."),
        new("b1", "should", "In order to facilitate path building, generators should include in the SignedData.certificates field all certificates not available to verifiers that can be used during path building.",
            "Disclosed: PAdESSigningRequest.AdditionalCertificates is the caller seam; which certificates satisfy this is a caller policy decision."),
        new("b2", "should", "When the signature is to be validated through a Trusted List as specified in ETSI TS 119 612, the generator should include all intermediary certificates forming a chain between the signer certificate and a CA present in the Trusted List, which are not available to verifiers.",
            "Disclosed: Trusted List cross-referencing is a separate charter; the generic AdditionalCertificates mechanism (b1) is what a caller uses."),
        new("c", "shall", "The content-type attribute shall have value id-data.",
            "PAdESSignatureCreation.SignAsync, via composed CAdESSignatureCreation.SignAsync (RP-3)."),
        new("d1", "may", "The commitment-type-indication attribute may be incorporated in the CMS signature only if the entry with the key Reason is not used.",
            "PAdESSignatureCreation.EnsureReasonNotRedundant, fail-closed at PAdESSignatureCreation.SignAsync."),
        new("d2", "shall not", "Otherwise the commitment-type-indication shall not be incorporated in the CMS signature.",
            "PAdESSignatureCreation.EnsureReasonNotRedundant, fail-closed at PAdESSignatureCreation.SignAsync."),
        new("e", "shall", "Generators shall use either the signing certificate or the signing-certificate v2 attribute, depending on the hash function, in accordance with ETSI EN 319 122-1.",
            "Composed CAdESSignatureCreation.SignAsync (RP-3): v2 is always emitted, v1 never."),
        new("f", "should", "Generators should use ESS signing-certificate v2 in preference to ESS signing-certificate in line with the guidance given in ETSI TS 119 312.",
            "Composed CAdESSignatureCreation.SignAsync (RP-3): v2 is always emitted, v1 never."),
        new("g", "shall", "The generator shall include the claimed UTC time of the signature as expressed in ISO 32000-1, clause 7.9.4 as content of this element.",
            "PdfIncrementalUpdateWriter.AppendPlaceholderSignature writes the M entry from PAdESSigningRequest.SigningTime."),
        new("h", "shall", "The Content key shall contain a DER-encoded SignedData object as specified in CMS (IETF RFC 5652) as the PDF signature. This CMS object forms a CAdES signature described in ETSI EN 319 122-1.",
            "The PA-4.1-01/PA-6.3-h join point: PAdESSignatureFacts.Seam composes CAdESSignatureFacts unchanged on exactly this reading."),
        new("i", "shall not", "Requirements specified in ISO 32000-1, clauses 12.8.3.2 (PKCS#1) and 12.8.3.3 (PKCS#7) shall not be used.",
            "Structural: PdfSubFilter.EtsiCAdESDetached is the one value PdfIncrementalUpdateWriter ever writes and PAdESSignatureValidation ever accepts."),
        new("j", "may", "A verifier may substitute a different signature handler, other than that specified in Filter, when verifying the signature, as long as it supports the specified SubFilter format.",
            "Structural: PAdESSignatureValidation never inspects Filter, only SubFilter."),
        new("k", "shall", "The ByteRange shall cover the entire file, including the Signature Dictionary but excluding the PDF Signature itself (the entry with key Contents).",
            "PAdESSignatureValidation.ValidateSignatureAsync (PAdESSignatureStatus.IncompleteByteRangeCoverage, the shadow-attack gate)."),
        new("l", "shall", "The Signature Dictionary shall contain a value of ETSI.CAdES.detached for the key SubFilter.",
            "PAdESSignatureValidation.ValidateSignatureAsync (PAdESSignatureStatus.UnsupportedSubFilter) and the writer's own fixed SubFilter."),
        new("m1", "shall not", "The entry with the key Reason shall not be used when the commitment-type-indication attribute is present in the CMS signature.",
            "PAdESSignatureCreation.EnsureReasonNotRedundant, fail-closed at PAdESSignatureCreation.SignAsync."),
        new("m2", "shall not", "The entry with the key Reason shall not be used if the signature-policy-identifier attribute is present in the CMS signature.",
            "PAdESSignatureCreation.EnsureReasonNotRedundant, fail-closed at PAdESSignatureCreation.SignAsync."),
        new("n", "shall", "The trusted time shall be provided either by a signature-time-stamp attribute or a document-time-stamp.",
            "PAdESSignatureCreation (signature-time-stamp disjunct) and PAdESSignatureAugmentation.AugmentToBLTAAsync (document-time-stamp disjunct)."),
        new("o", "shall", "The generator shall use DER encoding for any signature-time-stamp attribute.",
            "Composed CAdESSignatureAugmentation.AddSignatureTimestampAsync (RP-3)."),
        new("p", "may", "A PAdES-B-T signature may contain several signature-time-stamp or document-time-stamp attributes.",
            "Disclosed: no caller-facing multi-timestamp surface is built; permissive, no enforcement required."),
        new("q", "DESCRIPTIVE", "If it is anticipated to propagate PAdES-B-B signatures to a higher conformance level, they can reserve space for the signature-time-stamp attribute that will be added to the DER-encoded SignedData object as specified in ETSI EN 319 122-1. Alternatively a document-time-stamp, which covers the whole document including the signature value, can serve this purpose.",
            "Non-normative (no RFC 2119 keyword): PAdESSigningRequest.ContentsCapacityBytes already lets a caller reserve room."),
        new("r1", "should", "In situations different than those ones identified in the present clause requirements a) and b), applications should include certificate values within the DSS.",
            "Disclosed: PAdESBLTAugmentationRequest's own material lists are caller-supplied; which certificates satisfy this is a caller policy decision."),
        new("r2", "shall", "The full set of certificates, including the trust anchor when it is available in the form of a certificate, that have been used to validate the signature and which are not already present shall be included.",
            "Disclosed: PAdESSignatureAugmentation.AugmentToBLTAsync places exactly the material the caller supplies; completeness of the caller-attested set is not independently proven (no chain-building/trust-store walk is performed here)."),
        new("s", "should", "Duplication of certificate values within the signature should be avoided.",
            "Disclosed: caller policy; the SignedData.certificates-level instance of this concern is enforced by the composed CAdES surface (RP-3), but this letter's own DSS-relative reading is caller-attested."),
        new("t", "shall", "The full set of revocation data (CRL or OCSP responses) that have been used in the validation of the signer and CA certificates used in signature shall be included.",
            "Disclosed: PAdESSignatureAugmentation.AugmentToBLTAsync places exactly the material the caller supplies."),
        new("u", "shall", "The DER encoding shall be used for the certificate-values and the revocation-values.",
            "Structural: every carrier PdfDssPlacementRequest/PAdESBLTAugmentationRequest accepts is a PkiCertificateMemory of DER octets; PdfIncrementalUpdateWriter.AppendValidationData writes them verbatim, never re-encodes."),
        new("v", "should not", "The VRI dictionary should not be used. The inclusion of VRI dictionary entries is optional. All validation material referenced in VRI entries is also referenced in DSS entries.",
            "PAdESSignatureAugmentation.AugmentToBLTAsync places no VRI entry by default (PdfDssPlacementRequest.VriEntries left null) — the recommended reading (PA-5.4.2.3-14/-15/-16: prefer a subsequent document-time-stamp) honored as the default, not merely permitted."),
        new("w", "may", "PAdES-B-LTA signatures may have more than one document-time-stamp applied after the DSS and DSS/VRI.",
            "Disclosed: PAdESSignatureAugmentation.AugmentToBLTAAsync may be called repeatedly, chaining each call's own NextAnchor; permissive, no upper bound enforced."),
        new("x1", "shall", "Before generating and incorporating a document-time-stamp attribute, applications shall include all the validation material, which are not already in the signature, required for validating the signature.",
            "PAdESSignatureAugmentation.AugmentToBLTAAsync's own pre-billing gate: refuses fail-closed when the document carries no DSS (or an empty one) before contacting the Time-Stamping Authority."),
        new("x2", "should", "This validation material should be incorporated within DSS.",
            "PAdESSignatureAugmentation.AugmentToBLTAsync's own DSS-only placement — no alternative placement (e.g. inside a CMS unsigned attribute) exists in this library."),
        new("y", "shall", "The value of SubFilter shall be ETSI.RFC3161.",
            "Structural: PdfIncrementalUpdateWriter.AppendPlaceholderDocTimeStamp is the one writer of a Document Time-stamp dictionary and always fixes SubFilter to PdfSubFilter.EtsiRfc3161; PAdESDocTimeStampValidation.ValidateOneAsync discriminates candidates by exactly that value.")
    ];


    /// <summary>Finds every registered requirement sharing one letter's own root (e.g. <c>"d"</c> returns both <c>"d1"</c> and <c>"d2"</c>).</summary>
    /// <param name="letterRoot">The letter, without a numeric suffix (e.g. <c>"d"</c>, <c>"m"</c>, <c>"x"</c>).</param>
    /// <returns>Every matching requirement, in registry order.</returns>
    public static IReadOnlyList<PAdESAdditionalRequirement> FindByLetterRoot(string letterRoot)
    {
        ArgumentNullException.ThrowIfNull(letterRoot);

        List<PAdESAdditionalRequirement> matches = [];
        for(int i = 0; i < All.Count; ++i)
        {
            string letter = All[i].Letter;
            string root = letter.Length > 0 && char.IsDigit(letter[^1]) ? letter[..^1] : letter;
            if(string.Equals(root, letterRoot, StringComparison.Ordinal))
            {
                matches.Add(All[i]);
            }
        }

        return matches;
    }
}
