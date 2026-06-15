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

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.5.2 → HTTP 400).</summary>
    public static VcalmCreatePresentationRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-option parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmCreatePresentationRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}


/// <summary>
/// The parsed §3.5.2 <c>options</c> object of a <c>POST /presentations</c> request — the members that
/// shape the produced Data Integrity proof. §2.4: every option is OPTIONAL; an absent member takes its
/// §3.5.2 default. <see cref="Challenge"/> and <see cref="Domain"/> are required by the Core presentation
/// signer (a presentation proof binds an anti-replay challenge + domain, VC-DM 2.0 §4.13); the §3.5.2
/// endpoint maps an absent challenge / domain to a 400.
/// </summary>
[DebuggerDisplay("VcalmCreatePresentationOptions Challenge={Challenge} Domain={Domain}")]
public sealed record VcalmCreatePresentationOptions
{
    /// <summary>
    /// §3.5.2 <c>options.challenge</c>: "A challenge provided by the requesting party of the proof."
    /// <see langword="null"/> when absent — a §3.5.2 400, because a presentation proof binds a challenge.
    /// </summary>
    public string? Challenge { get; init; }

    /// <summary>
    /// §3.5.2 <c>options.domain</c>: "The intended domain of validity for the proof." <see langword="null"/>
    /// when absent — a §3.5.2 400, because a presentation proof binds a domain.
    /// </summary>
    public string? Domain { get; init; }

    /// <summary>
    /// §3.5.2 <c>options.verificationMethod</c>: "The URI of the verificationMethod used for the proof.
    /// If omitted, a default verification method will be used." <see langword="null"/> when absent, in
    /// which case the instance's configured default is used.
    /// </summary>
    public string? VerificationMethod { get; init; }

    /// <summary>
    /// §3.5.2 <c>options.created</c>: "The date and time of the proof (with a maximum accuracy in
    /// seconds). Default current system time." <see langword="null"/> when absent, in which case the
    /// instance's clock supplies the value.
    /// </summary>
    public string? Created { get; init; }
}
