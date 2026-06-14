using System.Diagnostics;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a VCALM 1.0 §3.3.2 <c>POST /presentations/verify</c>
/// request body. Mirrors <see cref="VcalmVerifyCredentialRequest"/>: the JSON-side parser
/// materializes it so the <c>Verifiable.Vcalm</c> serialization firewall keeps
/// <c>System.Text.Json</c> out of the library.
/// </summary>
/// <remarks>
/// <para>
/// §3.3.2 defines three request alternatives. Exactly one of the parsed members is populated:
/// <see cref="DataIntegrityPresentation"/> for a proofed embedded presentation
/// (<c>verifiablePresentation</c>), <see cref="UnproofedPresentation"/> for an UNPROOFED JSON-LD
/// presentation (the <c>presentation</c> member), or <see cref="EnvelopedPresentation"/> for an
/// <c>EnvelopedVerifiablePresentation</c> (the <c>data:</c>-URL secured form). A fourth, off-contract
/// shape — a <c>verifiablePresentation</c> member carrying neither a proof nor an envelope — populates
/// <see cref="UnsecuredVerifiablePresentation"/>, a §3.8.1 cryptographic ERROR rather than a valid
/// alternative.
/// </para>
/// <para>
/// <see cref="PresentationJson"/> is the verbatim JSON of the presentation member, echoed under
/// <c>verifiablePresentation</c> when <c>options.returnPresentation</c> is set. <see cref="Options"/>
/// carries the §3.3.2 <c>challenge</c> / <c>domain</c> / <c>returnPresentation</c> members.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmVerifyPresentationRequest Failure={Failure}")]
public sealed record VcalmVerifyPresentationRequest
{
    /// <summary>
    /// The parsed embedded-secured (proofed) presentation, or <see langword="null"/> for the
    /// unproofed / enveloped alternatives.
    /// </summary>
    public DataIntegritySecuredPresentation? DataIntegrityPresentation { get; init; }

    /// <summary>
    /// The parsed UNPROOFED JSON-LD presentation (the §3.3.2 <c>presentation</c> member), or
    /// <see langword="null"/> for the proofed / enveloped alternatives.
    /// </summary>
    public VerifiablePresentation? UnproofedPresentation { get; init; }

    /// <summary>
    /// A presentation supplied under the §3.3.2 <c>verifiablePresentation</c> member that carried
    /// NEITHER a Data Integrity proof NOR a <c>data:</c>-URL envelope — i.e. it is not a secured
    /// presentation at all. §3.3.2 reserves <c>verifiablePresentation</c> for the SECURED form (a
    /// proof or an <c>EnvelopedVerifiablePresentation</c>) and gives the separate <c>presentation</c>
    /// member to the unproofed form, so this is a §3.8.1 cryptographic ERROR (verified:false),
    /// mirroring a proof-less <c>verifiableCredential</c>. <see langword="null"/> for every other
    /// alternative.
    /// </summary>
    public VerifiablePresentation? UnsecuredVerifiablePresentation { get; init; }

    /// <summary>
    /// The parsed <c>EnvelopedVerifiablePresentation</c>, or <see langword="null"/> for the
    /// proofed / unproofed alternatives.
    /// </summary>
    public EnvelopedVerifiablePresentation? EnvelopedPresentation { get; init; }

    /// <summary>
    /// The verbatim JSON of the presentation member, for the §3.3.2 <c>options.returnPresentation</c>
    /// echo. <see langword="null"/> on a parse failure.
    /// </summary>
    public string? PresentationJson { get; init; }

    /// <summary>The parsed verify options (§2.4 all-optional). Defaulted when absent.</summary>
    public VcalmVerifyOptions Options { get; init; } = new();

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.3.2 → HTTP 400).</summary>
    public static VcalmVerifyPresentationRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-option parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmVerifyPresentationRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}
