namespace Verifiable.Xml;

/// <summary>
/// The reason a XAdES-level processing operation — the clause 5.1.4.4.2.2 <c>Include</c> <c>URI</c>
/// dereference or the clause 5.1.4.4.2.3 <c>Include</c>-processing frame — was refused, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
/// <remarks>
/// A separate enumeration from <see cref="XmlSignatureProcessingFailure"/>: that type's own doc comment
/// scopes it to XMLDSIG sections 4.3.3 and 6.6, and XAdES is a different specification with its own clause
/// numbering — the same reasoning <see cref="XAdESReadFailure"/> already applies to structural reads applies
/// here to processing. This leaf's XAdES processing reuses the XMLDSIG reference-processing/canonicalization
/// PRIMITIVES (<see cref="XmlNodeTable.TryFindElementById"/>, <see cref="XmlNodeSet"/>,
/// <see cref="XmlReferenceProcessing"/>'s canonicalization-algorithm dispatch and
/// <see cref="XmlReferenceProcessing.TryComputeDigestInputForReference"/>) but reports its own refusals
/// through this type, bridging the two XMLDSIG-level members (<see cref="IncludeTargetIdNotFound"/>,
/// <see cref="DuplicateIncludeTargetId"/>) that genuinely originate one layer down.
/// </remarks>
public enum XAdESProcessingFailure
{
    /// <summary>
    /// A time-stamp container's <c>ds:CanonicalizationMethod</c> is absent when its message-imprint input is
    /// computed via the <c>Include</c> mechanism (clause 5.1.4.4.2.3 step 3). Clause 4.5 (XA-4.5-1/XA-4.5-2)
    /// makes the element generator-mandatory for every EN-conformant signature or augmentation, so its
    /// absence at verification time is a named refusal rather than an assumed default algorithm: the clause
    /// states no default to fall back to, and guessing one would silently accept a non-conformant signature.
    /// </summary>
    AbsentCanonicalizationMethod,

    /// <summary>
    /// An <c>Include</c>'s <c>URI</c> attribute (clause 5.1.4.4.2.1) has a non-empty non-fragment part — a
    /// reference to a data object outside the current document. Retrieving it would require network or
    /// filesystem access this leaf never performs; a caller-supplied retrieval seam is a future extension
    /// point, out of this leaf's own scope.
    /// </summary>
    NonSameDocumentIncludeUnresolved,

    /// <summary>
    /// An <c>Include</c>'s <c>URI</c> attribute has an empty non-fragment part (same-document) but its
    /// fragment is not a bare-name XPointer — the ONLY same-document form clause 5.1.4.4.2.1 permits for
    /// <c>Include</c> (XA-5.1.4.4.2.1-4), unlike the general XMLDSIG same-document reference, which
    /// additionally recognizes the null URI and the two scheme-based <c>#xpointer(...)</c> forms.
    /// </summary>
    UnsupportedIncludeUriForm,

    /// <summary>
    /// An <c>Include</c>'s bare-name XPointer fragment names no <c>Id</c>-typed attribute value present in
    /// the document — bridged from <see cref="XmlSignatureProcessingFailure.IdNotFound"/>.
    /// </summary>
    IncludeTargetIdNotFound,

    /// <summary>
    /// An <c>Include</c>'s bare-name XPointer fragment names more than one <c>Id</c>-typed attribute value in
    /// the document — bridged from <see cref="XmlSignatureProcessingFailure.DuplicateId"/>; ambiguous targets
    /// are how signature-wrapping attacks work, so a duplicate refuses rather than resolving to the first
    /// match.
    /// </summary>
    DuplicateIncludeTargetId,

    /// <summary>
    /// An <c>Include</c>'s <c>referencedData</c> attribute is present, but the element its <c>URI</c>
    /// identifies is not a <c>ds:Reference</c> element — clause 5.1.4.4.2.1's "If the object referenced by
    /// the URI attribute is not a ds:Reference element, the referencedData attribute shall not be present."
    /// </summary>
    ReferencedDataNotPermittedOnNonReferenceTarget,

    /// <summary>
    /// A time-stamp container's <c>ds:CanonicalizationMethod Algorithm</c> is not one of the six
    /// canonicalization identifiers clause 6.3(d) requires a validator to support.
    /// </summary>
    UnsupportedCanonicalizationMethod,

    /// <summary>
    /// A canonicalization algorithm's own parameter — the <c>InclusiveNamespaces PrefixList</c> a time-stamp
    /// container's <c>ds:CanonicalizationMethod</c> carries for the exclusive family — carries a token that
    /// is neither a namespace prefix nor the <c>#default</c> token, or exceeds the documented hardening
    /// length bound <see cref="XmlReferenceProcessing.MaximumPrefixListByteLength"/> states.
    /// </summary>
    InvalidCanonicalizationParameter,

    /// <summary>
    /// An <c>Include</c>'s <c>referencedData="true"</c> target, structurally named <c>ds:Reference</c>, does
    /// not itself read as a well-formed <c>ds:Reference</c> element — clause 5.1.4.4.2.3 step 2 requires
    /// processing it "according to the reference processing model of XMLDSIG clause 4.4.3.2", which assumes
    /// the element IS a genuine, well-formed reference. <see cref="XAdESProcessingError.InnerReadError"/>
    /// carries the structural read's own refusal.
    /// </summary>
    MalformedReferenceTarget,

    /// <summary>
    /// Processing an <c>Include</c>'s <c>referencedData="true"</c> target through the XMLDSIG
    /// reference-processing engine (<see cref="XmlReferenceProcessing"/>) itself refused — the target
    /// reference's own transform chain, dereference, or canonicalization failed.
    /// <see cref="XAdESProcessingError.InnerProcessingError"/> carries the engine's own refusal.
    /// </summary>
    ReferenceProcessingFailed,

    /// <summary>
    /// A caller passed an <see cref="XmlNodeTable"/> that is not the identical instance the
    /// <see cref="XmlSignature"/>, <see cref="XAdESQualifyingProperties"/> or <see cref="XAdESSignedProperties"/>
    /// argument was itself read from, to <see cref="XAdESQualifyingPropertiesDiscovery.TryDiscover"/>,
    /// <see cref="XAdESQualifyingPropertiesDiscovery.TryVerifyTargetBinding"/> or
    /// <see cref="XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding"/> — the
    /// table-identity guard this library requires: a caller holding two tables (a re-parse, a normalized copy)
    /// could otherwise retarget <c>Id</c> resolution to the wrong document.
    /// </summary>
    TableMismatch,

    /// <summary>
    /// More than one <c>QualifyingProperties</c> element is a direct child of the <c>ds:Object</c>(s) a
    /// <c>ds:Signature</c> carries — clause 4.4.1's "at most one instance of the <c>QualifyingProperties</c>
    /// element may occur" cardinality bound.
    /// </summary>
    MultipleQualifyingProperties,

    /// <summary>
    /// <c>QualifyingProperties</c> and/or <c>QualifyingPropertiesReference</c> instances are children of more
    /// than one distinct <c>ds:Object</c> element of the same <c>ds:Signature</c> — clause 4.4.1's "all
    /// instances ... shall occur within a single <c>ds:Object</c> element" rule.
    /// </summary>
    QualifyingContentScatteredAcrossMultipleObjects,

    /// <summary>
    /// The single, uniquely discovered <c>QualifyingProperties</c> element does not itself read as a
    /// well-formed instance of clause 4.3.1's <c>QualifyingPropertiesType</c>.
    /// <see cref="XAdESProcessingError.InnerQualifyingPropertiesReadError"/> carries the structural read's
    /// own refusal.
    /// </summary>
    MalformedQualifyingProperties,

    /// <summary>
    /// A discovered <c>QualifyingPropertiesReference</c> element does not itself read as a well-formed
    /// instance of clause 4.4.3's <c>QualifyingPropertiesReferenceType</c>.
    /// <see cref="XAdESProcessingError.InnerQualifyingPropertiesReadError"/> carries the structural read's
    /// own refusal.
    /// </summary>
    MalformedQualifyingPropertiesReference,

    /// <summary>
    /// A caller asked to resolve a <c>QualifyingPropertiesReference</c> (clause 4.4.3's indirect
    /// incorporation). This is a permanent, unconditional refusal: the referenced <c>QualifyingProperties</c>
    /// element lives outside the current document, retrieving it needs network or filesystem access this
    /// transport-agnostic library never performs, and clause 6.3 forbids indirect incorporation in every
    /// XAdES baseline level regardless — a recorded scope refusal, not a
    /// transient failure a retry could resolve.
    /// </summary>
    IndirectIncorporationNotSupported,

    /// <summary>
    /// <c>QualifyingProperties</c>'s <c>Target</c> attribute (clause 4.3.1) is not shaped as a URI with a
    /// bare-name XPointer fragment: it carries no <c>#</c> at all, or its fragment is not a well-formed
    /// <c>NCName</c> per <see cref="XmlReferenceDereferencer.IsNcNameFragment"/>.
    /// </summary>
    UnsupportedTargetUriForm,

    /// <summary>
    /// <c>QualifyingProperties</c>'s <c>Target</c> attribute (clause 4.3.1) carries a non-empty part before
    /// its <c>#</c> — XA-4.3.1-6's "If the XAdES signature envelops the <c>QualifyingProperties</c> element,
    /// its not-fragment part shall be empty," which every directly-incorporated <c>QualifyingProperties</c>
    /// this leaf discovers satisfies unconditionally, since direct incorporation (clause 4.4.1) always makes
    /// the <c>ds:Object</c> — and so the <c>QualifyingProperties</c> it contains — a descendant of its own
    /// <c>ds:Signature</c>.
    /// </summary>
    TargetNonFragmentPartNotEmpty,

    /// <summary>
    /// <c>QualifyingProperties</c>'s <c>Target</c> fragment names no <c>Id</c>-typed attribute value present
    /// in the document — bridged from <see cref="XmlSignatureProcessingFailure.IdNotFound"/>.
    /// </summary>
    TargetIdNotFound,

    /// <summary>
    /// <c>QualifyingProperties</c>'s <c>Target</c> fragment names more than one <c>Id</c>-typed attribute
    /// value in the document — bridged from <see cref="XmlSignatureProcessingFailure.DuplicateId"/>;
    /// ambiguous targets are how signature-wrapping attacks work, so a duplicate refuses rather than
    /// resolving to the first match.
    /// </summary>
    DuplicateTargetId,

    /// <summary>
    /// <c>QualifyingProperties</c>'s <c>Target</c> fragment resolves to an element other than the
    /// <c>ds:Signature</c> being processed — XA-4.3.1-4's "The <c>Target</c> attribute shall refer to the
    /// <c>Id</c> attribute of the corresponding <c>ds:Signature</c>," violated by a <c>Target</c> pointing at
    /// a different signature (a signature-wrapping shape this library names explicitly).
    /// </summary>
    TargetSignatureMismatch,

    /// <summary>
    /// No <c>ds:Reference</c> of the <c>ds:Signature</c>'s own <c>ds:SignedInfo</c> carries
    /// <c>Type="http://uri.etsi.org/01903#SignedProperties"</c> — clause 4.4.2's "a <c>ds:Reference</c>
    /// element shall be added ... shall include the <c>Type</c> attribute with its value set to" rule, with
    /// no such reference present.
    /// </summary>
    SignedPropertiesReferenceNotFound,

    /// <summary>
    /// More than one <c>ds:Reference</c> of the <c>ds:Signature</c>'s own <c>ds:SignedInfo</c> carries
    /// <c>Type="http://uri.etsi.org/01903#SignedProperties"</c> — an ambiguous discovery key clause 4.4.2
    /// assumes is unique; refused rather than picking the first match, the same ambiguity-is-a-wrapping-risk
    /// posture <see cref="DuplicateTargetId"/> and <see cref="XmlSignatureProcessingFailure.DuplicateId"/>
    /// already take.
    /// </summary>
    MultipleSignedPropertiesReferences,

    /// <summary>
    /// Dereferencing the <c>Type="http://uri.etsi.org/01903#SignedProperties"</c> reference's own <c>URI</c>
    /// through <see cref="XmlReferenceDereferencer"/> itself refused.
    /// <see cref="XAdESProcessingError.InnerProcessingError"/> carries the engine's own refusal.
    /// </summary>
    SignedPropertiesReferenceDereferenceFailed,

    /// <summary>
    /// The <c>Type="http://uri.etsi.org/01903#SignedProperties"</c> reference's <c>URI</c> dereferences to
    /// external octets rather than a same-document node-set — clause 4.4.2 always ties this reference to the
    /// <c>SignedProperties</c> element of the very same <c>QualifyingProperties</c> container the discovered
    /// <c>ds:Object</c> carries, which can only ever be a same-document target.
    /// </summary>
    SignedPropertiesReferenceTargetsExternalDocument,

    /// <summary>
    /// The <c>Type="http://uri.etsi.org/01903#SignedProperties"</c> reference's <c>URI</c> dereferences to a
    /// node-set other than exactly the <c>SignedProperties</c> element of the discovered
    /// <c>QualifyingProperties</c> container — the table/node-identity pin this library requires,
    /// extending the anti-wrapping discipline: a decoy <c>SignedProperties</c>-shaped element
    /// elsewhere in the document, sharing the target <c>Id</c> or reached via a different fragment form, must
    /// never be accepted as the signed qualifying properties.
    /// </summary>
    SignedPropertiesReferenceTargetMismatch,

    /// <summary>
    /// A <c>CommitmentTypeIndication</c>'s <c>ObjectReference</c> (clause 5.2.3) or a <c>DataObjectFormat</c>'s
    /// <c>ObjectReference</c> attribute (clause 5.2.4) is not shaped as a bare-name XPointer: it carries no
    /// <c>#</c> at all, or its fragment is not a well-formed <c>NCName</c> per
    /// <see cref="XmlReferenceDereferencer.IsNcNameFragment"/> — both clauses require the value to identify a
    /// <c>ds:Reference</c> element by its own <c>Id</c>, which only the bare-name form can express.
    /// </summary>
    UnsupportedObjectReferenceUriForm,

    /// <summary>
    /// An <c>ObjectReference</c>'s bare-name XPointer fragment names no <c>Id</c>-typed attribute value present
    /// in the document — bridged from <see cref="XmlSignatureProcessingFailure.IdNotFound"/>.
    /// </summary>
    ObjectReferenceTargetIdNotFound,

    /// <summary>
    /// An <c>ObjectReference</c>'s bare-name XPointer fragment names more than one <c>Id</c>-typed attribute
    /// value in the document — bridged from <see cref="XmlSignatureProcessingFailure.DuplicateId"/>; ambiguous
    /// targets are how signature-wrapping attacks work, so a duplicate refuses rather than resolving to the
    /// first match.
    /// </summary>
    DuplicateObjectReferenceTargetId,

    /// <summary>
    /// An <c>ObjectReference</c> resolves to an element that is not a <c>ds:Reference</c> — clause 5.2.3's
    /// "Each <c>ObjectReference</c> shall reference one <c>ds:Reference</c> element" and clause 5.2.4's
    /// identical requirement on <c>DataObjectFormat</c>'s <c>ObjectReference</c> attribute both name the
    /// target's element identity, not merely its <c>Id</c>.
    /// </summary>
    ObjectReferenceTargetNotReference,

    /// <summary>
    /// An <c>ObjectReference</c> resolves to a genuine <c>ds:Reference</c> element that is neither a direct
    /// child of the signature's own <c>ds:SignedInfo</c> nor a direct child of a <c>ds:Manifest</c> that is
    /// itself signed (referenced, directly, by a <c>ds:Reference</c> within that same <c>ds:SignedInfo</c>) —
    /// clause 5.2.3's "within the <c>ds:SignedInfo</c> element or within a signed <c>ds:Manifest</c> element"
    /// and clause 5.2.4's identical wording (via NOTE 8's clarification that the reference need not be a
    /// direct <c>ds:SignedInfo</c> child) both name this exact two-way allowlist.
    /// </summary>
    ObjectReferenceNotWithinSignedInfoOrSignedManifest,

    /// <summary>
    /// A <c>DataObjectFormat</c>'s <c>MimeType</c> child (clause 5.2.4) is present, and its <c>ObjectReference</c>
    /// resolves through a <c>ds:Reference</c> to a <c>ds:Object</c> within the same signature that itself carries
    /// a <c>MimeType</c> attribute, but the two values differ — clause 5.2.4's "then <c>DataObjectFormat</c>'s
    /// children <c>MimeType</c> and (and) <c>Encoding</c> shall have exactly the same values, if they are
    /// present."
    /// </summary>
    DataObjectFormatMimeTypeMismatch,

    /// <summary>
    /// A <c>DataObjectFormat</c>'s <c>Encoding</c> child (clause 5.2.4) is present, and its <c>ObjectReference</c>
    /// resolves through a <c>ds:Reference</c> to a <c>ds:Object</c> within the same signature that itself carries
    /// an <c>Encoding</c> attribute, but the two values differ — the same clause 5.2.4 consistency rule as
    /// <see cref="DataObjectFormatMimeTypeMismatch"/>, for the <c>Encoding</c> half of the pair.
    /// </summary>
    DataObjectFormatEncodingMismatch,

    /// <summary>
    /// Computing a message-imprint input over an ordered list of <c>ds:Reference</c> elements — the shared
    /// clause 5.2.8.1/5.2.8.2 steps a)-d) procedure
    /// (<see cref="XmlReferenceProcessing.TryComputeMessageImprintInputForReferences"/>) — itself refused: a
    /// reference's own dereference, transform chain, or clause-4.5 canonicalization failed.
    /// <see cref="XAdESProcessingError.InnerProcessingError"/> carries the engine's own refusal. Shared by
    /// <c>XAdESAllDataObjectsTimeStampImprint</c> and <c>XAdESIndividualDataObjectsTimeStampImprint</c>, and,
    /// and, by <c>XAdESArchiveTimeStampImprint</c>'s own step 3) over the same shared
    /// engine. The Annex A.1.5 imprint engines (<c>XAdESSigAndRefsTimeStampV2Imprint</c>,
    /// <c>XAdESRefsOnlyTimeStampV2Imprint</c>) never reach this engine and so never produce this failure: A.1.5.1/
    /// A.1.5.2 canonicalize whole qualifying-property (and <c>ds:SignatureValue</c>) node-sets directly, rather
    /// than processing a <c>ds:Reference</c> list's own dereference/transform-chain steps a)-d).
    /// </summary>
    MessageImprintReferenceProcessingFailed,

    /// <summary>
    /// An <c>IndividualDataObjectsTimeStamp</c>'s (clause 5.2.8.2) <c>Include</c> element resolves to the very
    /// <c>ds:Reference</c> that carries <c>Type="http://uri.etsi.org/01903#SignedProperties"</c> — "The set of
    /// <c>ds:Reference</c> elements processed shall not include the one referencing the <c>SignedProperties</c>
    /// element," the same exclusion clause 5.2.8.1 states for its own (implicitly, whole-<c>SignedInfo</c>)
    /// selection, restated here as its own sentence because clause 5.2.8.2's selection is explicit
    /// (<c>Include</c>-driven) and so can name the forbidden reference directly rather than merely skipping it.
    /// </summary>
    IndividualDataObjectsTimeStampIncludeTargetsSignedPropertiesReference,

    /// <summary>
    /// An <c>ArchiveTimeStamp</c> not-distributed message-imprint computation (clause 5.5.2.3 step 5) was asked
    /// to locate the property within a caller-supplied <c>UnsignedSignatureProperties</c> entry list, but no
    /// entry's element index matches the <c>ArchiveTimeStamp</c> instance itself — the caller paired an
    /// <c>ArchiveTimeStamp</c> with a container it is not actually a child of.
    /// </summary>
    ArchiveTimeStampNotFoundInUnsignedSignatureProperties,

    /// <summary>
    /// Retrieving and processing a <c>RenewedDigestsV2</c> validation candidate's detached signed data object
    /// through the XMLDSIG reference-processing engine (<see cref="XmlReferenceProcessing.TryComputeDigestInputForReference"/>)
    /// itself refused — XA-5.5.3-13 step 3)'s "if retrieval fails, notify that retrieval of the detached signed
    /// data object failed [and] continue with step 6)": a Result-shaped notification, not an exception.
    /// <see cref="XAdESProcessingError.InnerProcessingError"/> carries the engine's own refusal.
    /// </summary>
    RenewedDigestsV2DetachedObjectProcessingFailed,

    /// <summary>
    /// A <c>SigAndRefsTimeStampV2</c> not-distributed message-imprint computation (clause A.1.5.1.2) was asked
    /// to locate the property within a caller-supplied <c>UnsignedSignatureProperties</c> entry list, but no
    /// entry's element index matches the <c>SigAndRefsTimeStampV2</c> instance itself — the caller paired a
    /// <c>SigAndRefsTimeStampV2</c> with a container it is not actually a child of, the same shape
    /// <see cref="ArchiveTimeStampNotFoundInUnsignedSignatureProperties"/> guards for <c>ArchiveTimeStamp</c>.
    /// </summary>
    SigAndRefsTimeStampV2NotFoundInUnsignedSignatureProperties,

    /// <summary>
    /// A <c>RefsOnlyTimeStampV2</c> not-distributed message-imprint computation (clause A.1.5.2.2) was asked to
    /// locate the property within a caller-supplied <c>UnsignedSignatureProperties</c> entry list, but no
    /// entry's element index matches the <c>RefsOnlyTimeStampV2</c> instance itself — the same shape
    /// <see cref="SigAndRefsTimeStampV2NotFoundInUnsignedSignatureProperties"/> guards for its sibling property.
    /// </summary>
    RefsOnlyTimeStampV2NotFoundInUnsignedSignatureProperties,

    /// <summary>
    /// A <c>DataObjectFormat</c>'s <c>ObjectReference</c> resolves to a <c>ds:SignedInfo</c> reference clause
    /// 6.3 letter k) excludes from the per-signed-data-object requirement: the <c>SignedProperties</c>
    /// reference, or — when the signature is itself a countersignature per clause 5.2.7.1's convention — the
    /// reference carrying the <c>CountersignedSignature</c> marker. XA-6.3-k2's "it shall not include any
    /// <c>DataObjectFormat</c> signed property" for the countersigned-signature reference specifically.
    /// </summary>
    DataObjectFormatCoverageExcludedTarget,

    /// <summary>
    /// More than one <c>DataObjectFormat</c>'s <c>ObjectReference</c> resolves to the SAME <c>ds:SignedInfo</c>
    /// reference — clause 6.3 letter k)'s "one <c>DataObjectFormat</c> shall be generated for each signed data
    /// object" states a one-to-one binding, not a one-to-many.
    /// </summary>
    DataObjectFormatCoverageDuplicate,

    /// <summary>
    /// At least one <c>ds:SignedInfo</c> reference clause 6.3 letter k) requires a <c>DataObjectFormat</c> for
    /// — every reference other than <c>SignedProperties</c> and, when countersigning, the
    /// <c>CountersignedSignature</c>-marked reference — has no <c>DataObjectFormat</c> whose <c>ObjectReference</c>
    /// resolves to it.
    /// </summary>
    DataObjectFormatCoverageMissing,

    /// <summary>
    /// Clause 5.2.7.2's shall-contain-one rule: none of a <c>CounterSignature</c>'s embedded signature's own
    /// <c>ds:SignedInfo</c> references dereferences (bare-name XPointer, same-document) to the countersigned
    /// signature's own <c>ds:SignatureValue</c> element — "shall contain one <c>ds:Reference</c> element
    /// referencing the <c>ds:SignatureValue</c> element of the embedding and countersigned XAdES signature."
    /// Covers every shape that leaves no reference pointing at the right target alike: a dangling fragment, a
    /// reference resolving to a DIFFERENT element (the wrong <c>ds:SignatureValue</c>, or any other element),
    /// and a reference resolving to the countersignature's OWN <c>ds:SignatureValue</c> (self-referencing).
    /// <see cref="XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference"/>'s own refusal.
    /// </summary>
    CounterSignatureSignatureValueReferenceNotFound,

    /// <summary>
    /// More than one of a <c>CounterSignature</c>'s embedded signature's own <c>ds:SignedInfo</c> references
    /// dereferences to the countersigned signature's own <c>ds:SignatureValue</c> element — clause 5.2.7.2's
    /// "shall contain ONE <c>ds:Reference</c> element" read as an exact cardinality, the same
    /// ambiguity-is-a-wrapping-risk posture <see cref="MultipleSignedPropertiesReferences"/> and
    /// <see cref="DuplicateTargetId"/> already take: refused rather than picking the first match.
    /// <see cref="XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference"/>'s own refusal.
    /// </summary>
    CounterSignatureSignatureValueReferenceAmbiguous,

    /// <summary>
    /// A nested-countersignature chain walk (<see cref="XAdESCounterSignatureChain.TryWalk"/>, clause 5.2.7.2
    /// NOTE 2/NOTE 3's "arbitrarily long chains of explicit countersignatures") visited more
    /// <c>CounterSignature</c> occurrences than <see cref="XAdESCounterSignatureChain.MaximumChainNodeCount"/>
    /// permits — a documented hardening bound, since the clause states no numeric limit of its own and
    /// explicitly contemplates unbounded chains.
    /// </summary>
    CounterSignatureChainLimitExceeded,

    /// <summary>
    /// A nested-countersignature chain walk (<see cref="XAdESCounterSignatureChain.TryWalk"/>) encountered a
    /// <c>CounterSignature</c> occurrence that does not itself read structurally —
    /// <see cref="XAdESCounterSignature.TryRead"/>'s own refusal, carried in
    /// <see cref="XAdESProcessingError.InnerQualifyingPropertiesReadError"/>.
    /// </summary>
    CounterSignatureChainMalformedEntry,

    /// <summary>
    /// A DISTRIBUTED time-stamp container's <c>Include</c> element resolved (by bare-name XPointer, document-wide)
    /// to an element that is not itself an entry of the owning <c>UnsignedSignatureProperties</c> — clause
    /// 5.5.2.4 validation-time step 5's "retrieve the referenced unsigned qualifying property PRESENT IN THE
    /// XADES SIGNATURE" (<see cref="XAdESArchiveTimeStampImprint.TryComputeDistributedImprintInput"/>), and
    /// clause A.1.5.1.3 step 3/A.1.5.2.3's "take each LISTED UNSIGNED QUALIFYING PROPERTY" restricted to the
    /// five/four covered property types (<see cref="XAdESSigAndRefsTimeStampV2Imprint.TryComputeDistributedImprintInput"/>,
    /// <see cref="XAdESRefsOnlyTimeStampV2Imprint.TryComputeDistributedImprintInput"/>) — both restrictions
    /// their own not-distributed twins already enforce by construction (they iterate the container's own entry
    /// list), reproduced here as an explicit membership/identity check because <c>Include</c> resolution is
    /// document-wide by design (<see cref="XAdESIncludeUriProcessing"/>) and so, unguarded, would accept a
    /// same-<c>Id</c> element relocated OUTSIDE the signature's unsigned properties while a forged replacement
    /// occupies its former place — the imprint would then attest to material no longer in the signature.
    /// </summary>
    IncludeTargetNotAnUnsignedQualifyingProperty,

    /// <summary>
    /// An <c>IndividualDataObjectsTimeStamp</c>'s (clause 5.2.8.2) <c>Include</c> element resolves to a
    /// structurally well-formed <c>ds:Reference</c> that is neither a direct child of the signature's own
    /// <c>ds:SignedInfo</c> nor a direct child of a <c>ds:Manifest</c> that is itself signed — clause 5.2.8.2
    /// step 2's "Take all the <c>ds:Reference</c> elements WITHIN <c>ds:SignedInfo</c> OR WITHIN A SIGNED
    /// <c>ds:Manifest</c> which are referenced within the <c>Include</c> element," the same two-way allowlist
    /// <see cref="ObjectReferenceNotWithinSignedInfoOrSignedManifest"/> enforces for <c>ObjectReference</c>
    /// resolution — a <c>ds:Reference</c> sitting inside an UNSIGNED <c>ds:Manifest</c>, or inside a different
    /// <c>ds:Signature</c> entirely, satisfies neither arm.
    /// </summary>
    IndividualDataObjectsTimeStampIncludeTargetNotWithinSignedInfoOrSignedManifest,

    /// <summary>
    /// An <c>ArchiveTimeStamp</c> message-imprint computation's <c>qualifyingPropertiesObjectOrdinal</c> names a
    /// <c>ds:Object</c> (clause 5.5.2.3/5.5.2.4 step 6's excluded element) that does not itself carry a
    /// <c>QualifyingProperties</c> direct child — the ordinal decides which <c>ds:Object</c> is EXCLUDED from
    /// the imprint, so an ordinal derived from the wrong signature's discovery, or off by one, would silently
    /// compute the imprint over the wrong object set rather than refusing.
    /// </summary>
    QualifyingPropertiesObjectOrdinalDoesNotCarryQualifyingProperties
}
