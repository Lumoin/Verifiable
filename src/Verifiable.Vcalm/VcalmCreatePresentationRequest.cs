using System.Diagnostics;
using Verifiable.Core.Model.Credentials;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a VCALM 1.0 §3.5.2 <c>POST /presentations</c> request body.
/// The JSON-side parser (in <c>Verifiable.Json</c>) materializes this so the <c>Verifiable.Vcalm</c>
/// serialization firewall keeps <c>System.Text.Json</c> out of the library.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Presentation"/> is the §3.5.2 unproofed JSON-LD presentation to secure;
/// <see cref="Options"/> carries the §3.5.2 proof options (<c>challenge</c>, <c>domain</c>,
/// <c>verificationMethod</c>, <c>proofPurpose</c>, <c>created</c>, <c>type</c>, <c>cryptosuite</c>).
/// </para>
/// <para>
/// When <see cref="Failure"/> is not <see cref="VcalmParseFailure.None"/> the presentation and options
/// are unspecified; the endpoint maps the failure to the §2.4 / §3.5.2 HTTP outcome.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmCreatePresentationRequest Failure={Failure}")]
public sealed record VcalmCreatePresentationRequest
{
    /// <summary>The parsed unproofed presentation to secure, or <see langword="null"/> on a parse failure.</summary>
    public VerifiablePresentation? Presentation { get; init; }

    /// <summary>The parsed presentation id (<c>presentation.id</c>) the §3.5.3 / §3.5.4 store keys on, or <see langword="null"/>.</summary>
    public string? PresentationId { get; init; }

    /// <summary>The parsed §3.5.2 create-presentation options (§2.4 all-optional). Defaulted when absent.</summary>
    public VcalmCreatePresentationOptions Options { get; init; } = new();

    /// <summary>
    /// Whether the wire <c>presentation</c> object carries a <c>proof</c> member of any JSON kind, <c>null</c>
    /// included. The typed <see cref="Presentation"/> cannot say so for every shape, because a JSON <c>null</c>
    /// member is dropped when the presentation is read, so the parser records the member's presence from the raw
    /// JSON. This holder processes no embedded presentation proof (the
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-presentation">§3.5.2</see> schema: "The document MAY
    /// include an embedded proof."), so the endpoint refuses a request carrying one before any signing. A parse
    /// seam that leaves this <see langword="false"/> still meets the endpoint's check of the typed presentation.
    /// </summary>
    public bool HasProofMember { get; init; }

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.5.2 → HTTP 400).</summary>
    public static VcalmCreatePresentationRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-option parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmCreatePresentationRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };


    /// <summary>Creates the parse failure of a body that is not a JSON text (HTTP 400 / PARSING_ERROR).</summary>
    public static VcalmCreatePresentationRequest Unparseable() =>
        new() { Failure = VcalmParseFailure.Unparseable };
}


/// <summary>
/// The parsed <see href="https://www.w3.org/TR/vcalm-1.0/#create-presentation">§3.5.2</see> <c>options</c> object of a
/// <c>POST /presentations</c> request — the members that shape the produced Data Integrity proof.
/// <see href="https://www.w3.org/TR/vcalm-1.0/#options">§2.4</see>: every option is OPTIONAL; an absent member takes
/// its §3.5.2 default. <see cref="Challenge"/> and <see cref="Domain"/> are required by the Core presentation
/// signer (a presentation proof binds an anti-replay challenge + domain, VC-DM 2.0 §4.13); the §3.5.2
/// endpoint maps an absent challenge / domain to a 400. A present value the instance cannot produce is
/// refused under §2.4 ("Implementations MUST throw an error if an endpoint receives data, options, or
/// option values that it does not understand or know how to process."), never replaced by a default.
/// </summary>
[DebuggerDisplay("VcalmCreatePresentationOptions Challenge={Challenge} Domain={Domain}")]
public sealed record VcalmCreatePresentationOptions
{
    /// <summary>
    /// §3.5.2 <c>options.challenge</c>: "A challenge provided by the requesting party of the proof."
    /// <see langword="null"/> when absent — a §3.5.2 400, because a presentation proof binds a challenge. A
    /// present value made only of whitespace names a challenge this instance cannot bind a proof to, and is
    /// refused as an unusable option value rather than reaching the Core signer, which requires a non-blank
    /// challenge.
    /// </summary>
    public string? Challenge { get; init; }

    /// <summary>
    /// §3.5.2 <c>options.domain</c>: "The intended domain of validity for the proof." <see langword="null"/>
    /// when absent — a §3.5.2 400, because a presentation proof binds a domain. A present value made only of
    /// whitespace names a domain this instance cannot bind a proof to, and is refused as an unusable option
    /// value rather than reaching the Core signer, which requires a non-blank domain.
    /// </summary>
    public string? Domain { get; init; }

    /// <summary>
    /// §3.5.2 <c>options.verificationMethod</c>: "The URI of the verificationMethod used for the proof.
    /// If omitted, a default verification method will be used." <see langword="null"/> when absent, in
    /// which case the instance's configured default is used. The instance signs with the key of its
    /// configured default only, so the endpoint refuses any other value.
    /// </summary>
    public string? VerificationMethod { get; init; }

    /// <summary>
    /// §3.5.2 <c>options.created</c>: "The date and time of the proof (with a maximum accuracy in
    /// seconds). Default current system time." <see langword="null"/> when absent, in which case the
    /// instance's clock supplies the value. The endpoint accepts only a Data Integrity dateTimeStamp
    /// (<see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity §2.1</see>: "MUST be
    /// specified as an [XMLSCHEMA11-2] dateTimeStamp string") and refuses any other value, a value without
    /// a time zone included.
    /// </summary>
    public string? Created { get; init; }

    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-presentation">§3.5.2</see> <c>options.type</c>: "The type
    /// of the proof. Default 'DataIntegrityProof'." <see langword="null"/> when absent. The instance produces a
    /// <c>DataIntegrityProof</c> only, so the endpoint refuses any other value.
    /// </summary>
    public string? Type { get; init; }

    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-presentation">§3.5.2</see> <c>options.cryptosuite</c>:
    /// "The cryptosuite of the proof." <see langword="null"/> when absent. The instance signs under its configured
    /// cryptosuite only, so the endpoint refuses any other value.
    /// </summary>
    public string? Cryptosuite { get; init; }

    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-presentation">§3.5.2</see> <c>options.proofPurpose</c>:
    /// "The purpose of the proof. Default 'assertionMethod'." <see langword="null"/> when absent. The instance
    /// signs a presentation proof for <c>authentication</c> only, the purpose a presentation proof is verified
    /// under, so the endpoint refuses any other value.
    /// </summary>
    public string? ProofPurpose { get; init; }
}
