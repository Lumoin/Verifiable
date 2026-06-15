using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a W3C VCALM 1.0 §3.6.3
/// <c>POST /workflows/{localWorkflowId}/exchanges</c> create-exchange request body. The JSON-side
/// parser materializes it so the <c>Verifiable.Vcalm</c> serialization firewall keeps
/// <c>System.Text.Json</c> out of the library.
/// </summary>
/// <remarks>
/// <para>
/// §3.6.3: the create-exchange body carries an OPTIONAL <c>expires</c> (the XML Schema
/// <c>dateTimeStamp</c> the exchange expires at), an OPTIONAL <c>variables</c> object (values the
/// workflow's templates are populated from), and an OPTIONAL <c>openId</c> object (enabling the
/// exchange to be executed using OID4VCI / OID4VP in addition to the vcapi protocol). All three are
/// optional, so the simplest create-exchange body is the empty object.
/// </para>
/// <para>
/// §2.4 strictness: a body that is not a JSON object, or carries a top-level member the engine does
/// not recognize, yields <see cref="VcalmParseFailure.Malformed"/> / <see cref="VcalmParseFailure.UnknownOption"/>
/// rather than being silently accepted. The reserved <c>variables.results</c> object the engine fills
/// during the exchange (§3.6) is verbatim-preserved as <see cref="VariablesJson"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmCreateExchangeRequest Failure={Failure}")]
public sealed record VcalmCreateExchangeRequest
{
    /// <summary>
    /// The §3.6.3 OPTIONAL <c>expires</c> — the verbatim XML Schema <c>dateTimeStamp</c> string the
    /// exchange expires at, or <see langword="null"/> when the request omits it (the engine then
    /// applies its default exchange lifetime).
    /// </summary>
    public string? Expires { get; init; }

    /// <summary>
    /// The §3.6.3 OPTIONAL <c>variables</c> object, verbatim, or <see langword="null"/> when the
    /// request omits it. Echoed back under <c>variables</c> in the §3.6.6 exchange state (alongside
    /// the engine-filled <c>results</c>).
    /// </summary>
    public string? VariablesJson { get; init; }

    /// <summary>
    /// The §3.6.3 OPTIONAL <c>openId</c> object, verbatim, or <see langword="null"/> when the request
    /// omits it. Carried so a deployment that layers OID4VP / OID4VCI execution on the exchange can
    /// read it; the vcapi participation path does not consume it.
    /// </summary>
    public string? OpenIdJson { get; init; }

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.6.3 → HTTP 400).</summary>
    public static VcalmCreateExchangeRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-member parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmCreateExchangeRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}
