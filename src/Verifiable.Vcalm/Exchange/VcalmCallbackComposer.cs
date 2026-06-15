using System.Diagnostics;
using System.Text;
using Verifiable.Server;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Composes the W3C VCALM 1.0 §3.6.7 exchange-step-callback request body — the
/// <c>{ event { data { exchangeId } } }</c> object the workflow service POSTs to a step's
/// <c>callback.url</c> capability URL when the step fires its callback. Built through
/// <see cref="JsonAppender"/> per the <c>Verifiable.Vcalm</c> serialization firewall (no
/// <c>System.Text.Json</c>); the actual HTTP POST is the application's, behind the
/// <see cref="DeliverVcalmCallbackDelegate"/> seam.
/// </summary>
[DebuggerDisplay("VcalmCallbackComposer")]
public static class VcalmCallbackComposer
{
    /// <summary>
    /// Composes the §3.6.7 callback body for <paramref name="exchangeId"/>. §3.6.7: the
    /// <c>event.data.exchangeId</c> is "A URL to the exchange state that can be used to retrieve the
    /// current state of the exchange."
    /// </summary>
    /// <param name="exchangeId">The exchange-state URL (or local exchange id) the callback references.</param>
    /// <returns>The verbatim <c>{event{data{exchangeId}}}</c> JSON body.</returns>
    public static string ComposeCallbackBody(string exchangeId)
    {
        ArgumentNullException.ThrowIfNull(exchangeId);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append("{\"");
            JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Event);
            sb.Append("\":{\"");
            JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Data);
            sb.Append("\":{");

            bool first = true;
            JsonAppender.AppendStringField(sb, VcalmParameterNames.ExchangeId, exchangeId, ref first);

            sb.Append("}}}");

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
