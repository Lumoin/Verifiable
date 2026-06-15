using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.DataIntegrity;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a W3C VCALM 1.0 §3.6.5 vcapi protocol message — the JSON
/// object an exchange client POSTs to <c>POST /workflows/{localWorkflowId}/exchanges/{localExchangeId}</c>.
/// The JSON-side parser materializes it so the <c>Verifiable.Vcalm</c> serialization firewall keeps
/// <c>System.Text.Json</c> out of the library.
/// </summary>
/// <remarks>
/// <para>
/// §3.6: "Each message consists of a simple JSON object that includes zero or more of the following
/// properties and values: redirectUrl, verifiablePresentation, verifiablePresentationRequest." Plus
/// the §3.6.5 <c>referenceId</c> the client SHOULD echo when the engine previously sent one. The
/// simplest message — the one a client with nothing to request sends to initiate the exchange — is
/// the empty object <c>{}</c>, where every member here is <see langword="null"/> /
/// <see cref="VcalmParseFailure.None"/>.
/// </para>
/// <para>
/// §3.6: "Custom properties and values might also be included, but are expected to trigger errors in
/// implementations that do not recognize them." An unrecognized top-level member therefore yields
/// <see cref="VcalmParseFailure.Malformed"/> — the §2.4 strict-parse posture every VCALM body shares.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmExchangeMessage Failure={Failure}")]
public sealed record VcalmExchangeMessage
{
    /// <summary>
    /// The §3.6 <c>verifiablePresentation</c> member parsed as an embedded-secured (proofed)
    /// presentation, or <see langword="null"/> when the message carries no proofed presentation. The
    /// holder sends this to satisfy a presentation request the engine made.
    /// </summary>
    public DataIntegritySecuredPresentation? VerifiablePresentation { get; init; }

    /// <summary>
    /// The verbatim JSON of the message's <c>verifiablePresentation</c> member, preserved so the
    /// engine can store it byte-faithfully into <c>variables.results</c> (§3.6.6). <see langword="null"/>
    /// when the message carries no <c>verifiablePresentation</c>.
    /// </summary>
    public string? VerifiablePresentationJson { get; init; }

    /// <summary>
    /// The §3.6 <c>verifiablePresentationRequest</c> member parsed as a §3.4 verifiable presentation
    /// request, or <see langword="null"/> when the message carries none. A client MAY send this to
    /// request information from the engine before proceeding (§3.6.8 Examples 15 / 16).
    /// </summary>
    public VerifiablePresentationRequest? VerifiablePresentationRequest { get; init; }

    /// <summary>
    /// The §3.6 <c>redirectUrl</c> member, or <see langword="null"/> when the message carries none. A
    /// client MAY send an interaction URL inviting the engine to continue elsewhere (§3.6.5).
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "§3.6 redirectUrl is a verbatim wire string the engine passes through opaquely (it MAY be an interaction URL the client controls, e.g. ?iuv=1); promoting to System.Uri would force parsing a value the protocol treats as opaque and would lose the caller's exact percent-encoding shape.")]
    public string? RedirectUrl { get; init; }

    /// <summary>
    /// The §3.6.5 <c>referenceId</c> correlation value the client echoes (a <c>urn:uuid:</c> value the
    /// engine previously sent), or <see langword="null"/> when the message carries none.
    /// </summary>
    public string? ReferenceId { get; init; }

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>
    /// Whether the message is the empty <c>{}</c> initiating / completing message — it carries none of
    /// the §3.6 continuation members (a bare <see cref="ReferenceId"/> echo is not a continuation
    /// member). §3.6: a client with nothing to request sends <c>{}</c> to initiate.
    /// </summary>
    public bool IsEmpty =>
        VerifiablePresentation is null
        && VerifiablePresentationRequest is null
        && RedirectUrl is null;


    /// <summary>Creates a malformed-body / unrecognized-member parse failure (§3.6.5 → HTTP 400).</summary>
    public static VcalmExchangeMessage Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-member parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmExchangeMessage UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}
