using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a W3C VCALM 1.0 §3.6.7 exchange-step-callback request body —
/// the JSON object a workflow service POSTs to <c>POST /callbacks/{localCallbackId}</c> when an
/// exchange step fires its callback. The JSON-side parser materializes it so the
/// <c>Verifiable.Vcalm</c> serialization firewall keeps <c>System.Text.Json</c> out of the library.
/// </summary>
/// <remarks>
/// §3.6.7: the body is <c>{ event { data { exchangeId } } }</c>, where <c>exchangeId</c> is "A URL to
/// the exchange state that can be used to retrieve the current state of the exchange." A body that is
/// not this shape is the §3.6.7 400 ("Callback data was not received.").
/// </remarks>
[DebuggerDisplay("VcalmCallbackRequest ExchangeId={ExchangeId} Failure={Failure}")]
public sealed record VcalmCallbackRequest
{
    /// <summary>
    /// The §3.6.7 <c>event.data.exchangeId</c> — the URL to the exchange state. <see langword="null"/>
    /// when the body did not carry it (a §3.6.7 400).
    /// </summary>
    public string? ExchangeId { get; init; }

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.6.7 → HTTP 400 "Callback data was not received.").</summary>
    public static VcalmCallbackRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };
}
