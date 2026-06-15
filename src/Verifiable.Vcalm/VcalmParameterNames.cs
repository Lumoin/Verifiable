using Verifiable.Cryptography.Text;

namespace Verifiable.Vcalm;

/// <summary>
/// Well-known wire member NAMES for the W3C VCALM 1.0 verifier service
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for
/// Lifecycle Management</see>) — the §3.3.1 <c>/credentials/verify</c>, §3.3.2
/// <c>/presentations/verify</c>, and §3.3.3 <c>/challenges</c> request and response
/// bodies.
/// </summary>
/// <remarks>
/// These are the NAMES of request/response members (e.g. <c>verifiableCredential</c>,
/// <c>options</c>, <c>verified</c>), not their VALUES. They are UTF-8-first per the
/// library convention: each <c>XUtf8</c> span sits beside an interned string <c>X</c>
/// whose value is the span's UTF-8 decoding, swept by the well-known-constant guard.
/// </remarks>
public static class VcalmParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="VerifiableCredential"/>.</summary>
    public static ReadOnlySpan<byte> VerifiableCredentialUtf8 => "verifiableCredential"u8;

    /// <summary>
    /// The §3.3.1 request member carrying the credential to verify — either a JSON-LD
    /// Verifiable Credential or an <c>EnvelopedVerifiableCredential</c>; also the §3.3.1
    /// response echo member under <see cref="Credential"/> is distinct.
    /// </summary>
    public static readonly string VerifiableCredential = Utf8Constants.ToInternedString(VerifiableCredentialUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VerifiablePresentation"/>.</summary>
    public static ReadOnlySpan<byte> VerifiablePresentationUtf8 => "verifiablePresentation"u8;

    /// <summary>
    /// The §3.3.2 request member carrying the proofed (or enveloped) presentation to verify,
    /// and the response echo member returned when <see cref="ReturnPresentation"/> is set.
    /// </summary>
    public static readonly string VerifiablePresentation = Utf8Constants.ToInternedString(VerifiablePresentationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Presentation"/>.</summary>
    public static ReadOnlySpan<byte> PresentationUtf8 => "presentation"u8;

    /// <summary>
    /// The §3.3.2 alternate request member carrying an UNPROOFED JSON-LD presentation, and the
    /// §3.3.2 response <c>results.presentation</c> nesting member.
    /// </summary>
    public static readonly string Presentation = Utf8Constants.ToInternedString(PresentationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Options"/>.</summary>
    public static ReadOnlySpan<byte> OptionsUtf8 => "options"u8;

    /// <summary>The verify-options object member (§3.3.1 / §3.3.2 request).</summary>
    public static readonly string Options = Utf8Constants.ToInternedString(OptionsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ReturnResults"/>.</summary>
    public static ReadOnlySpan<byte> ReturnResultsUtf8 => "returnResults"u8;

    /// <summary>The §3.3.1 option requesting the verbose per-step <c>results</c> object.</summary>
    public static readonly string ReturnResults = Utf8Constants.ToInternedString(ReturnResultsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ReturnProblemDetails"/>.</summary>
    public static ReadOnlySpan<byte> ReturnProblemDetailsUtf8 => "returnProblemDetails"u8;

    /// <summary>The §3.3.1 option requesting the <c>problemDetails</c> array in the response.</summary>
    public static readonly string ReturnProblemDetails = Utf8Constants.ToInternedString(ReturnProblemDetailsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ReturnCredential"/>.</summary>
    public static ReadOnlySpan<byte> ReturnCredentialUtf8 => "returnCredential"u8;

    /// <summary>The §3.3.1 option requesting the verified credential be echoed in the response.</summary>
    public static readonly string ReturnCredential = Utf8Constants.ToInternedString(ReturnCredentialUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ReturnPresentation"/>.</summary>
    public static ReadOnlySpan<byte> ReturnPresentationUtf8 => "returnPresentation"u8;

    /// <summary>The §3.3.2 option requesting the verified presentation be echoed in the response.</summary>
    public static readonly string ReturnPresentation = Utf8Constants.ToInternedString(ReturnPresentationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Challenge"/>.</summary>
    public static ReadOnlySpan<byte> ChallengeUtf8 => "challenge"u8;

    /// <summary>
    /// The §3.3.2 option binding the presentation proof's challenge, the §3.3.3 response member
    /// carrying a minted challenge string, and the §3.3.2 <c>results.presentation.challenge</c>
    /// sub-result member.
    /// </summary>
    public static readonly string Challenge = Utf8Constants.ToInternedString(ChallengeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Domain"/>.</summary>
    public static ReadOnlySpan<byte> DomainUtf8 => "domain"u8;

    /// <summary>The §3.3.2 option binding the presentation proof's domain.</summary>
    public static readonly string Domain = Utf8Constants.ToInternedString(DomainUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Verified"/>.</summary>
    public static ReadOnlySpan<byte> VerifiedUtf8 => "verified"u8;

    /// <summary>
    /// The §3.3.1 / §3.3.2 response member: the overall boolean verification assertion (§3.8.1:
    /// false if any ERROR was detected, true otherwise), reused in every per-step result object.
    /// </summary>
    public static readonly string Verified = Utf8Constants.ToInternedString(VerifiedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Credential"/>.</summary>
    public static ReadOnlySpan<byte> CredentialUtf8 => "credential"u8;

    /// <summary>The §3.3.1 response echo member returned when <see cref="ReturnCredential"/> is set.</summary>
    public static readonly string Credential = Utf8Constants.ToInternedString(CredentialUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ProblemDetails"/>.</summary>
    public static ReadOnlySpan<byte> ProblemDetailsUtf8 => "problemDetails"u8;

    /// <summary>The §3.3.1 / §3.3.2 response array of RFC 9457 ProblemDetails objects.</summary>
    public static readonly string ProblemDetails = Utf8Constants.ToInternedString(ProblemDetailsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Results"/>.</summary>
    public static ReadOnlySpan<byte> ResultsUtf8 => "results"u8;

    /// <summary>The §3.3.1 / §3.3.2 verbose results object (emitted when <see cref="ReturnResults"/> is set).</summary>
    public static readonly string Results = Utf8Constants.ToInternedString(ResultsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ValidFrom"/>.</summary>
    public static ReadOnlySpan<byte> ValidFromUtf8 => "validFrom"u8;

    /// <summary>The §3.3.1 <c>results.validFrom</c> sub-result member.</summary>
    public static readonly string ValidFrom = Utf8Constants.ToInternedString(ValidFromUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ValidUntil"/>.</summary>
    public static ReadOnlySpan<byte> ValidUntilUtf8 => "validUntil"u8;

    /// <summary>The §3.3.1 <c>results.validUntil</c> sub-result member.</summary>
    public static readonly string ValidUntil = Utf8Constants.ToInternedString(ValidUntilUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialSchema"/>.</summary>
    public static ReadOnlySpan<byte> CredentialSchemaUtf8 => "credentialSchema"u8;

    /// <summary>The §3.3.1 <c>results.credentialSchema</c> sub-result array member.</summary>
    public static readonly string CredentialSchema = Utf8Constants.ToInternedString(CredentialSchemaUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialStatus"/>.</summary>
    public static ReadOnlySpan<byte> CredentialStatusUtf8 => "credentialStatus"u8;

    /// <summary>The §3.3.1 <c>results.credentialStatus</c> sub-result array member.</summary>
    public static readonly string CredentialStatus = Utf8Constants.ToInternedString(CredentialStatusUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Proof"/>.</summary>
    public static ReadOnlySpan<byte> ProofUtf8 => "proof"u8;

    /// <summary>The §3.3.1 / §3.3.2 <c>results.proof</c> sub-result array member.</summary>
    public static readonly string Proof = Utf8Constants.ToInternedString(ProofUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Input"/>.</summary>
    public static ReadOnlySpan<byte> InputUtf8 => "input"u8;

    /// <summary>The §3.3.1 per-step sub-result member carrying the verified input value.</summary>
    public static readonly string Input = Utf8Constants.ToInternedString(InputUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Value"/>.</summary>
    public static ReadOnlySpan<byte> ValueUtf8 => "value"u8;

    /// <summary>The §3.3.1 <c>results.credentialStatus[].value</c> integer status member.</summary>
    public static readonly string Value = Utf8Constants.ToInternedString(ValueUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Holder"/>.</summary>
    public static ReadOnlySpan<byte> HolderUtf8 => "holder"u8;

    /// <summary>The §3.3.2 <c>results.presentation.holder</c> sub-result member.</summary>
    public static readonly string Holder = Utf8Constants.ToInternedString(HolderUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Credentials"/>.</summary>
    public static ReadOnlySpan<byte> CredentialsUtf8 => "credentials"u8;

    /// <summary>The §3.3.2 <c>results.credentials</c> per-credential result array member.</summary>
    public static readonly string Credentials = Utf8Constants.ToInternedString(CredentialsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ProblemType"/>.</summary>
    public static ReadOnlySpan<byte> ProblemTypeUtf8 => "type"u8;

    /// <summary>The §3.8 ProblemDetails <c>type</c> member — a URL identifying the problem (MUST).</summary>
    public static readonly string ProblemType = Utf8Constants.ToInternedString(ProblemTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ProblemTitle"/>.</summary>
    public static ReadOnlySpan<byte> ProblemTitleUtf8 => "title"u8;

    /// <summary>The §3.8 ProblemDetails <c>title</c> member — a short human-readable string (SHOULD).</summary>
    public static readonly string ProblemTitle = Utf8Constants.ToInternedString(ProblemTitleUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ProblemDetail"/>.</summary>
    public static ReadOnlySpan<byte> ProblemDetailUtf8 => "detail"u8;

    /// <summary>The §3.8 ProblemDetails <c>detail</c> member — a longer human-readable string (SHOULD).</summary>
    public static readonly string ProblemDetail = Utf8Constants.ToInternedString(ProblemDetailUtf8);

    //VCALM 1.0 §3.2 issuer-service request / response members.

    /// <summary>The UTF-8 source literal of <see cref="MandatoryPointers"/>.</summary>
    public static ReadOnlySpan<byte> MandatoryPointersUtf8 => "mandatoryPointers"u8;

    /// <summary>
    /// The §3.2.1 <c>options.mandatoryPointers</c> array — the mandatory-reveal JSON pointers a
    /// selective-disclosure suite (ecdsa-sd-2023) bakes into the base proof.
    /// </summary>
    public static readonly string MandatoryPointers = Utf8Constants.ToInternedString(MandatoryPointersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialId"/>.</summary>
    public static ReadOnlySpan<byte> CredentialIdUtf8 => "credentialId"u8;

    /// <summary>
    /// The §3.2.1 <c>options.credentialId</c> member — a URI that identifies the issued credential
    /// in later APIs, auto-populated from <c>credential.id</c> when absent.
    /// </summary>
    public static readonly string CredentialId = Utf8Constants.ToInternedString(CredentialIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Issuer"/>.</summary>
    public static ReadOnlySpan<byte> IssuerUtf8 => "issuer"u8;

    /// <summary>The §3.2.1 <c>credential.issuer</c> member the instance matches against its configured identity.</summary>
    public static readonly string Issuer = Utf8Constants.ToInternedString(IssuerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Id"/>.</summary>
    public static ReadOnlySpan<byte> IdUtf8 => "id"u8;

    /// <summary>The §3.2.1 <c>credential.id</c> member.</summary>
    public static readonly string Id = Utf8Constants.ToInternedString(IdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Type"/>.</summary>
    public static ReadOnlySpan<byte> TypeUtf8 => "type"u8;

    /// <summary>The §C.3 <c>credentialStatus.type</c> member (e.g. <c>BitstringStatusListEntry</c>).</summary>
    public static readonly string Type = Utf8Constants.ToInternedString(TypeUtf8);

    //VCALM 1.0 Appendix C status-service request / response members.

    /// <summary>The UTF-8 source literal of <see cref="StatusPurpose"/>.</summary>
    public static ReadOnlySpan<byte> StatusPurposeUtf8 => "statusPurpose"u8;

    /// <summary>
    /// The §C.1 request member naming the new status list's purpose, and the §C.3
    /// <c>credentialStatus.statusPurpose</c> member (e.g. <c>revocation</c>, <c>suspension</c>).
    /// </summary>
    public static readonly string StatusPurpose = Utf8Constants.ToInternedString(StatusPurposeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusListIndex"/>.</summary>
    public static ReadOnlySpan<byte> StatusListIndexUtf8 => "statusListIndex"u8;

    /// <summary>The §C.3 <c>credentialStatus.statusListIndex</c> member — the bit position in the list.</summary>
    public static readonly string StatusListIndex = Utf8Constants.ToInternedString(StatusListIndexUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusListCredential"/>.</summary>
    public static ReadOnlySpan<byte> StatusListCredentialUtf8 => "statusListCredential"u8;

    /// <summary>The §C.3 <c>credentialStatus.statusListCredential</c> member — the status list's id / URL.</summary>
    public static readonly string StatusListCredential = Utf8Constants.ToInternedString(StatusListCredentialUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Status"/>.</summary>
    public static ReadOnlySpan<byte> StatusUtf8 => "status"u8;

    /// <summary>The §C.3 <c>status</c> boolean member — the new status (set / clear the bit).</summary>
    public static readonly string Status = Utf8Constants.ToInternedString(StatusUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IndexAllocator"/>.</summary>
    public static ReadOnlySpan<byte> IndexAllocatorUtf8 => "indexAllocator"u8;

    /// <summary>
    /// The §C.3 <c>indexAllocator</c> member — "For services to use which indexes are being
    /// used/assigned to VCs." Opaque to the library; threaded to the update seam.
    /// </summary>
    public static readonly string IndexAllocator = Utf8Constants.ToInternedString(IndexAllocatorUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EncodedList"/>.</summary>
    public static ReadOnlySpan<byte> EncodedListUtf8 => "encodedList"u8;

    /// <summary>
    /// The W3C Bitstring Status List <c>credentialSubject.encodedList</c> member — the Multibase
    /// base64url-encoded, GZIP-compressed bitstring of the §C.1 status-list credential subject.
    /// </summary>
    public static readonly string EncodedList = Utf8Constants.ToInternedString(EncodedListUtf8);

    //VCALM 1.0 §3.5 holder presentation request / response members.

    /// <summary>The UTF-8 source literal of <see cref="SelectivePointers"/>.</summary>
    public static ReadOnlySpan<byte> SelectivePointersUtf8 => "selectivePointers"u8;

    /// <summary>
    /// The §3.5.1 <c>options.selectivePointers</c> array — the JSON pointers specifying the
    /// selectively disclosed information of a derived credential ("Each item in the selectivePointers
    /// array MUST be a string.").
    /// </summary>
    public static readonly string SelectivePointers = Utf8Constants.ToInternedString(SelectivePointersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Cryptosuite"/>.</summary>
    public static ReadOnlySpan<byte> CryptosuiteUtf8 => "cryptosuite"u8;

    /// <summary>The §3.5.2 <c>options.cryptosuite</c> member — the cryptosuite of the presentation proof.</summary>
    public static readonly string Cryptosuite = Utf8Constants.ToInternedString(CryptosuiteUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VerificationMethod"/>.</summary>
    public static ReadOnlySpan<byte> VerificationMethodUtf8 => "verificationMethod"u8;

    /// <summary>
    /// The §3.5.2 <c>options.verificationMethod</c> member — the URI of the verification method used
    /// for the presentation proof ("If omitted, a default verification method will be used.").
    /// </summary>
    public static readonly string VerificationMethod = Utf8Constants.ToInternedString(VerificationMethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ProofPurpose"/>.</summary>
    public static ReadOnlySpan<byte> ProofPurposeUtf8 => "proofPurpose"u8;

    /// <summary>The §3.5.2 <c>options.proofPurpose</c> member — the purpose of the proof ("Default 'assertionMethod'.").</summary>
    public static readonly string ProofPurpose = Utf8Constants.ToInternedString(ProofPurposeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Created"/>.</summary>
    public static ReadOnlySpan<byte> CreatedUtf8 => "created"u8;

    /// <summary>
    /// The §3.5.2 <c>options.created</c> member — the date and time of the proof ("Default current
    /// system time.").
    /// </summary>
    public static readonly string Created = Utf8Constants.ToInternedString(CreatedUtf8);

    //VCALM 1.0 §3.4 verifiable-presentation-request (VPR) request members.

    /// <summary>The UTF-8 source literal of <see cref="Query"/>.</summary>
    public static ReadOnlySpan<byte> QueryUtf8 => "query"u8;

    /// <summary>
    /// The §3.4.1 REQUIRED top-level member: an array of one or more typed query maps, each of
    /// which MUST define a string <see cref="Type"/> ("The value MUST be one or more maps where
    /// each map MUST define a type property with an associated string value.").
    /// </summary>
    public static readonly string Query = Utf8Constants.ToInternedString(QueryUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Group"/>.</summary>
    public static ReadOnlySpan<byte> GroupUtf8 => "group"u8;

    /// <summary>
    /// The §3.4.5 query-level member carrying a grouping label: queries sharing a <see cref="Group"/>
    /// value are processed as an "AND" operation, queries with different or missing values as "OR".
    /// </summary>
    public static readonly string Group = Utf8Constants.ToInternedString(GroupUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialQuery"/>.</summary>
    public static ReadOnlySpan<byte> CredentialQueryUtf8 => "credentialQuery"u8;

    /// <summary>The §3.4.2 single object inside a <c>QueryByExample</c> query carrying the example, accepted issuers, cryptosuites and envelopes.</summary>
    public static readonly string CredentialQuery = Utf8Constants.ToInternedString(CredentialQueryUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Reason"/>.</summary>
    public static ReadOnlySpan<byte> ReasonUtf8 => "reason"u8;

    /// <summary>The §3.4.2 OPTIONAL human-readable explanation for why the credential is requested ("MAY be displayed to the holder").</summary>
    public static readonly string Reason = Utf8Constants.ToInternedString(ReasonUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Example"/>.</summary>
    public static ReadOnlySpan<byte> ExampleUtf8 => "example"u8;

    /// <summary>
    /// The §3.4.2 OPTIONAL example object (<c>@context</c>, <c>type</c>, optional
    /// <c>credentialSubject</c>) indicating which claims are needed; any included field is REQUIRED,
    /// an empty-string value means "field requested, any value".
    /// </summary>
    public static readonly string Example = Utf8Constants.ToInternedString(ExampleUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Context"/>.</summary>
    public static ReadOnlySpan<byte> ContextUtf8 => "@context"u8;

    /// <summary>The §3.4.2 <c>example.@context</c> member — the JSON-LD context of the requested credential.</summary>
    public static readonly string Context = Utf8Constants.ToInternedString(ContextUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialSubject"/>.</summary>
    public static ReadOnlySpan<byte> CredentialSubjectUtf8 => "credentialSubject"u8;

    /// <summary>The §3.4.2 <c>example.credentialSubject</c> member — the requested subject claims.</summary>
    public static readonly string CredentialSubject = Utf8Constants.ToInternedString(CredentialSubjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AcceptedIssuers"/>.</summary>
    public static ReadOnlySpan<byte> AcceptedIssuersUtf8 => "acceptedIssuers"u8;

    /// <summary>
    /// The §3.4.2 OPTIONAL array of issuers the verifier accepts. Each item is a URL string, an
    /// object with an <see cref="Id"/>, or an object with a <see cref="RecognizedIn"/> reference.
    /// </summary>
    public static readonly string AcceptedIssuers = Utf8Constants.ToInternedString(AcceptedIssuersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RecognizedIn"/>.</summary>
    public static ReadOnlySpan<byte> RecognizedInUtf8 => "recognizedIn"u8;

    /// <summary>
    /// The §3.4.2 <c>acceptedIssuers[].recognizedIn</c> member — an object with an <see cref="Id"/>
    /// URL and a <see cref="Type"/> of <c>VerifiableRecognitionCredential</c> pointing to a
    /// recognition credential listing the acceptable issuers.
    /// </summary>
    public static readonly string RecognizedIn = Utf8Constants.ToInternedString(RecognizedInUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AcceptedCryptosuites"/>.</summary>
    public static ReadOnlySpan<byte> AcceptedCryptosuitesUtf8 => "acceptedCryptosuites"u8;

    /// <summary>
    /// The §3.4.2 / §3.4.3 OPTIONAL array of accepted proof suites. Each element SHOULD be an
    /// object with a <see cref="Cryptosuite"/> property (a bare string is also accepted). Verifiers
    /// SHOULD include <c>ecdsa-sd-2023</c> / <c>bbs-2023</c> to signal selective-disclosure acceptance.
    /// </summary>
    public static readonly string AcceptedCryptosuites = Utf8Constants.ToInternedString(AcceptedCryptosuitesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AcceptedEnvelopes"/>.</summary>
    public static ReadOnlySpan<byte> AcceptedEnvelopesUtf8 => "acceptedEnvelopes"u8;

    /// <summary>
    /// The §3.4.2 OPTIONAL array of accepted envelope formats. Each element SHOULD be an object with
    /// a <see cref="MediaType"/> property (a bare string is also accepted).
    /// </summary>
    public static readonly string AcceptedEnvelopes = Utf8Constants.ToInternedString(AcceptedEnvelopesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MediaType"/>.</summary>
    public static ReadOnlySpan<byte> MediaTypeUtf8 => "mediaType"u8;

    /// <summary>The §3.4.2 <c>acceptedEnvelopes[].mediaType</c> member — an envelope media type (e.g. <c>application/jwt</c>).</summary>
    public static readonly string MediaType = Utf8Constants.ToInternedString(MediaTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AcceptedMethods"/>.</summary>
    public static ReadOnlySpan<byte> AcceptedMethodsUtf8 => "acceptedMethods"u8;

    /// <summary>
    /// The §3.4.3 OPTIONAL array of objects, each carrying a <see cref="Method"/> DID-method name
    /// (and MAY carry method-specific props), expressing which DID methods the verifier accepts.
    /// </summary>
    public static readonly string AcceptedMethods = Utf8Constants.ToInternedString(AcceptedMethodsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Method"/>.</summary>
    public static ReadOnlySpan<byte> MethodUtf8 => "method"u8;

    /// <summary>The §3.4.3 <c>acceptedMethods[].method</c> member — a DID-method name (e.g. <c>key</c>, <c>web</c>).</summary>
    public static readonly string Method = Utf8Constants.ToInternedString(MethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CapabilityQuery"/>.</summary>
    public static ReadOnlySpan<byte> CapabilityQueryUtf8 => "capabilityQuery"u8;

    /// <summary>
    /// The §3.4.4 array inside an <c>AuthorizationCapabilityQuery</c> query (editor-flagged as
    /// possibly-not-standardized) — each item carries a <see cref="ReferenceId"/>,
    /// <see cref="AllowedAction"/>, <see cref="Controller"/>, and <see cref="InvocationTarget"/>.
    /// </summary>
    public static readonly string CapabilityQuery = Utf8Constants.ToInternedString(CapabilityQueryUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ReferenceId"/>.</summary>
    public static ReadOnlySpan<byte> ReferenceIdUtf8 => "referenceId"u8;

    /// <summary>The §3.4.4 <c>capabilityQuery[].referenceId</c> member — a memorable correlation name.</summary>
    public static readonly string ReferenceId = Utf8Constants.ToInternedString(ReferenceIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AllowedAction"/>.</summary>
    public static ReadOnlySpan<byte> AllowedActionUtf8 => "allowedAction"u8;

    /// <summary>The §3.4.4 <c>capabilityQuery[].allowedAction</c> member — a single action string or an array of action strings.</summary>
    public static readonly string AllowedAction = Utf8Constants.ToInternedString(AllowedActionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Controller"/>.</summary>
    public static ReadOnlySpan<byte> ControllerUtf8 => "controller"u8;

    /// <summary>The §3.4.4 <c>capabilityQuery[].controller</c> member — the controller identifier (a DID).</summary>
    public static readonly string Controller = Utf8Constants.ToInternedString(ControllerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvocationTarget"/>.</summary>
    public static ReadOnlySpan<byte> InvocationTargetUtf8 => "invocationTarget"u8;

    /// <summary>The §3.4.4 <c>capabilityQuery[].invocationTarget</c> member — the opaque target object the capability is invoked against.</summary>
    public static readonly string InvocationTarget = Utf8Constants.ToInternedString(InvocationTargetUtf8);

    //VCALM 1.0 §3.6 workflows-and-exchanges request / response members.

    /// <summary>The UTF-8 source literal of <see cref="Expires"/>.</summary>
    public static ReadOnlySpan<byte> ExpiresUtf8 => "expires"u8;

    /// <summary>
    /// The §3.6.3 create-exchange request member and §3.6.6 state member — the date and time
    /// (an XML Schema <c>dateTimeStamp</c>) the exchange expires.
    /// </summary>
    public static readonly string Expires = Utf8Constants.ToInternedString(ExpiresUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Variables"/>.</summary>
    public static ReadOnlySpan<byte> VariablesUtf8 => "variables"u8;

    /// <summary>
    /// The §3.6.3 create-exchange request member and §3.6.6 state member — the variables object the
    /// workflow's templates are populated from, carrying the reserved <see cref="Results"/> object.
    /// </summary>
    public static readonly string Variables = Utf8Constants.ToInternedString(VariablesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OpenId"/>.</summary>
    public static ReadOnlySpan<byte> OpenIdUtf8 => "openId"u8;

    /// <summary>
    /// The §3.6.3 create-exchange request member enabling the exchange to be executed using OID4VCI /
    /// OID4VP in addition to the vcapi protocol.
    /// </summary>
    public static readonly string OpenId = Utf8Constants.ToInternedString(OpenIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Protocols"/>.</summary>
    public static ReadOnlySpan<byte> ProtocolsUtf8 => "protocols"u8;

    /// <summary>
    /// The §3.6.4 get-exchange-protocols response member — the object mapping protocol identifiers
    /// (<see cref="Vcapi"/>, <see cref="OpenId4Vp"/>, <see cref="OpenId4Vci"/>, <see cref="Interact"/>)
    /// to the URL that initiates the exchange with that protocol.
    /// </summary>
    public static readonly string Protocols = Utf8Constants.ToInternedString(ProtocolsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Vcapi"/>.</summary>
    public static ReadOnlySpan<byte> VcapiUtf8 => "vcapi"u8;

    /// <summary>The §3.6.4 <c>protocols.vcapi</c> member — "The URL to use when initiating a VCALM exchange."</summary>
    public static readonly string Vcapi = Utf8Constants.ToInternedString(VcapiUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OpenId4Vp"/>.</summary>
    public static ReadOnlySpan<byte> OpenId4VpUtf8 => "OID4VP"u8;

    /// <summary>The §3.6.4 <c>protocols.OID4VP</c> member — "The URL to use when initiating an OID4VP presentation."</summary>
    public static readonly string OpenId4Vp = Utf8Constants.ToInternedString(OpenId4VpUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OpenId4Vci"/>.</summary>
    public static ReadOnlySpan<byte> OpenId4VciUtf8 => "OID4VCI"u8;

    /// <summary>The §3.6.4 <c>protocols.OID4VCI</c> member — "The URL to use when initiating an OID4VCI issuance."</summary>
    public static readonly string OpenId4Vci = Utf8Constants.ToInternedString(OpenId4VciUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Interact"/>.</summary>
    public static ReadOnlySpan<byte> InteractUtf8 => "interact"u8;

    /// <summary>The §3.6.4 <c>protocols.interact</c> member — "A URL that can be used during exchange flows with a human in the loop."</summary>
    public static readonly string Interact = Utf8Constants.ToInternedString(InteractUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VerifiablePresentationRequest"/>.</summary>
    public static ReadOnlySpan<byte> VerifiablePresentationRequestUtf8 => "verifiablePresentationRequest"u8;

    /// <summary>
    /// The §3.6.5 vcapi-message member carrying a §3.4 Verifiable Presentation Request — the engine
    /// sends it to request a presentation from the holder, and a client MAY send it to request
    /// information from the engine.
    /// </summary>
    public static readonly string VerifiablePresentationRequest = Utf8Constants.ToInternedString(VerifiablePresentationRequestUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RedirectUrl"/>.</summary>
    public static ReadOnlySpan<byte> RedirectUrlUtf8 => "redirectUrl"u8;

    /// <summary>
    /// The §3.6.5 vcapi-message member carrying a URL the client can use to continue an interaction at
    /// another location; from the engine it also signals the exchange is complete.
    /// </summary>
    public static readonly string RedirectUrl = Utf8Constants.ToInternedString(RedirectUrlUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Sequence"/>.</summary>
    public static ReadOnlySpan<byte> SequenceUtf8 => "sequence"u8;

    /// <summary>The §3.6.6 state member — "A sequence number for the exchange. Set to 0 on creation."</summary>
    public static readonly string Sequence = Utf8Constants.ToInternedString(SequenceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Step"/>.</summary>
    public static ReadOnlySpan<byte> StepUtf8 => "step"u8;

    /// <summary>The §3.6.6 state member — "The current step in the exchange."</summary>
    public static readonly string Step = Utf8Constants.ToInternedString(StepUtf8);

    /// <summary>The UTF-8 source literal of <see cref="State"/>.</summary>
    public static ReadOnlySpan<byte> StateUtf8 => "state"u8;

    /// <summary>
    /// The §3.6.6 state member — the exchange status (<c>pending</c> | <c>active</c> | <c>complete</c> |
    /// <c>invalid</c>), "set to 'pending' on creation".
    /// </summary>
    public static readonly string State = Utf8Constants.ToInternedString(StateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LastError"/>.</summary>
    public static ReadOnlySpan<byte> LastErrorUtf8 => "lastError"u8;

    /// <summary>The §3.6.6 state member — a §3.8 ProblemDetails object describing the most recent error, when one occurred.</summary>
    public static readonly string LastError = Utf8Constants.ToInternedString(LastErrorUtf8);

    //VCALM 1.0 §3.6.1 / §3.6.2 workflow-configuration request / response members.

    /// <summary>The UTF-8 source literal of <see cref="InitialStep"/>.</summary>
    public static ReadOnlySpan<byte> InitialStepUtf8 => "initialStep"u8;

    /// <summary>The §3.6.1 REQUIRED <c>initialStep</c> member — the step an exchange on the workflow starts on.</summary>
    public static readonly string InitialStep = Utf8Constants.ToInternedString(InitialStepUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Steps"/>.</summary>
    public static ReadOnlySpan<byte> StepsUtf8 => "steps"u8;

    /// <summary>The §3.6.1 REQUIRED <c>steps</c> object — each STEP_NAME keying its step configuration.</summary>
    public static readonly string Steps = Utf8Constants.ToInternedString(StepsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialTemplates"/>.</summary>
    public static ReadOnlySpan<byte> CredentialTemplatesUtf8 => "credentialTemplates"u8;

    /// <summary>The §3.6.1 OPTIONAL <c>credentialTemplates</c> array — templates an issueRequests step evaluates.</summary>
    public static readonly string CredentialTemplates = Utf8Constants.ToInternedString(CredentialTemplatesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Template"/>.</summary>
    public static ReadOnlySpan<byte> TemplateUtf8 => "template"u8;

    /// <summary>The §3.6.1 <c>credentialTemplates[].template</c> / <c>stepTemplate.template</c> member — the verbatim template body.</summary>
    public static readonly string Template = Utf8Constants.ToInternedString(TemplateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Authorization"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationUtf8 => "authorization"u8;

    /// <summary>
    /// The §3.6.1 OPTIONAL <c>authorization</c> object — the OAuth2 / zcap authorization-scheme config.
    /// Modeled and round-tripped through §3.6.2; the field's enforcement is deferred.
    /// </summary>
    public static readonly string Authorization = Utf8Constants.ToInternedString(AuthorizationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CreateChallenge"/>.</summary>
    public static ReadOnlySpan<byte> CreateChallengeUtf8 => "createChallenge"u8;

    /// <summary>The §3.6.1 step <c>createChallenge</c> directive — the engine mints and binds a fresh anti-replay challenge for the step.</summary>
    public static readonly string CreateChallenge = Utf8Constants.ToInternedString(CreateChallengeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Callback"/>.</summary>
    public static ReadOnlySpan<byte> CallbackUtf8 => "callback"u8;

    /// <summary>The §3.6.1 step <c>callback</c> object — the §3.6.7 callback fired after the step executes (carries <see cref="Url"/>).</summary>
    public static readonly string Callback = Utf8Constants.ToInternedString(CallbackUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Url"/>.</summary>
    public static ReadOnlySpan<byte> UrlUtf8 => "url"u8;

    /// <summary>The §3.6.1 <c>callback.url</c> member — the capability URL that receives the §3.6.7 callback data.</summary>
    public static readonly string Url = Utf8Constants.ToInternedString(UrlUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IssueRequests"/>.</summary>
    public static ReadOnlySpan<byte> IssueRequestsUtf8 => "issueRequests"u8;

    /// <summary>The §3.6.1 step <c>issueRequests</c> array — each entry mints a credential from a named template.</summary>
    public static readonly string IssueRequests = Utf8Constants.ToInternedString(IssueRequestsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialTemplateId"/>.</summary>
    public static ReadOnlySpan<byte> CredentialTemplateIdUtf8 => "credentialTemplateId"u8;

    /// <summary>The §3.6.1 <c>issueRequests[].credentialTemplateId</c> member — names the credential template by id.</summary>
    public static readonly string CredentialTemplateId = Utf8Constants.ToInternedString(CredentialTemplateIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialTemplateIndex"/>.</summary>
    public static ReadOnlySpan<byte> CredentialTemplateIndexUtf8 => "credentialTemplateIndex"u8;

    /// <summary>The §3.6.1 <c>issueRequests[].credentialTemplateIndex</c> member — names the credential template by array index.</summary>
    public static readonly string CredentialTemplateIndex = Utf8Constants.ToInternedString(CredentialTemplateIndexUtf8);

    /// <summary>The UTF-8 source literal of <see cref="NextStep"/>.</summary>
    public static ReadOnlySpan<byte> NextStepUtf8 => "nextStep"u8;

    /// <summary>
    /// The §3.6.1 step <c>nextStep</c> member — the name of the LINEAR successor step. MUST NOT be
    /// present on the final step configuration.
    /// </summary>
    public static readonly string NextStep = Utf8Constants.ToInternedString(NextStepUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PresentationSchema"/>.</summary>
    public static ReadOnlySpan<byte> PresentationSchemaUtf8 => "presentationSchema"u8;

    /// <summary>
    /// The §3.6.1 step <c>presentationSchema</c> member — a JSON-Schema validation of the presented
    /// presentation. Modeled and round-tripped; enforcement is deferred (no JSON Schema package).
    /// </summary>
    public static readonly string PresentationSchema = Utf8Constants.ToInternedString(PresentationSchemaUtf8);

    //VCALM 1.0 §3.6.7 exchange-step-callback request members.

    /// <summary>The UTF-8 source literal of <see cref="Event"/>.</summary>
    public static ReadOnlySpan<byte> EventUtf8 => "event"u8;

    /// <summary>The §3.6.7 callback body's <c>event</c> object — the event information associated with the callback.</summary>
    public static readonly string Event = Utf8Constants.ToInternedString(EventUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Data"/>.</summary>
    public static ReadOnlySpan<byte> DataUtf8 => "data"u8;

    /// <summary>The §3.6.7 callback body's <c>event.data</c> object — the event data associated with the callback.</summary>
    public static readonly string Data = Utf8Constants.ToInternedString(DataUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ExchangeId"/>.</summary>
    public static ReadOnlySpan<byte> ExchangeIdUtf8 => "exchangeId"u8;

    /// <summary>
    /// The §3.6.7 callback body's <c>event.data.exchangeId</c> member — "A URL to the exchange state
    /// that can be used to retrieve the current state of the exchange."
    /// </summary>
    public static readonly string ExchangeId = Utf8Constants.ToInternedString(ExchangeIdUtf8);

    //VCALM 1.0 §3.7 initiating-interactions request / response members.

    /// <summary>The UTF-8 source literal of <see cref="Iuv"/>.</summary>
    public static ReadOnlySpan<byte> IuvUtf8 => "iuv"u8;

    /// <summary>
    /// The §3.7.1 interaction-URL query parameter NAME carrying the interaction URL version number,
    /// which MUST be <c>1</c> when using this version of the API ("contain an iuv query parameter
    /// encoding the interaction URL version number, which MUST be 1 when using this version").
    /// </summary>
    public static readonly string Iuv = Utf8Constants.ToInternedString(IuvUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InviteRequest"/>.</summary>
    public static ReadOnlySpan<byte> InviteRequestUtf8 => "inviteRequest"u8;

    /// <summary>
    /// The §3.7.4 <c>protocols.inviteRequest</c> member — the URL a local system POSTs an
    /// invitation-request to (§3.7.5), the holder-initiated interaction protocol entry.
    /// </summary>
    public static readonly string InviteRequest = Utf8Constants.ToInternedString(InviteRequestUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Purpose"/>.</summary>
    public static ReadOnlySpan<byte> PurposeUtf8 => "purpose"u8;

    /// <summary>
    /// The §3.7.5 inviteRequest body member — a human-readable description of the interaction the
    /// <see cref="Url"/> leads to (e.g. "Checkout at ShopCo").
    /// </summary>
    public static readonly string Purpose = Utf8Constants.ToInternedString(PurposeUtf8);
}
