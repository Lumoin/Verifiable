using System.Diagnostics;
using System.Text;

namespace Verifiable.Vcalm;

/// <summary>
/// Hand-built response bodies for the W3C VCALM 1.0 §3.7.4 interaction protocols response — the
/// content-negotiated <c>{protocols:{…}}</c> JSON and the <c>text/html</c> human-directing fallback —
/// through <see cref="JsonAppender"/> per the <c>Verifiable.Vcalm</c> serialization firewall (no
/// <c>System.Text.Json</c>; the HTML is a fixed static document built as a string).
/// </summary>
[DebuggerDisplay("VcalmInteractionResponseWriter")]
public static class VcalmInteractionResponseWriter
{
    /// <summary>
    /// Writes the §3.7.4 <c>application/json</c> response: a single object carrying the
    /// <c>protocols</c> map (each present protocol identifier → its initiation URL). §3.7.4: "a single
    /// JSON object containing a protocols map MUST be returned where each key is a protocol identifier
    /// and each value is a URL that can be used to initiate the interaction." Only the protocols the
    /// coordinator resolved for the interaction are emitted; the §3.7.4 examples include the degenerate
    /// map carrying only <c>inviteRequest</c>.
    /// </summary>
    public static string BuildProtocolsResponse(VcalmInteractionProtocols protocols)
    {
        ArgumentNullException.ThrowIfNull(protocols);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            //§3.7.4: the response is a single object carrying the protocols map.
            sb.Append("{\"");
            JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Protocols);
            sb.Append("\":{");

            bool protocolsFirst = true;

            //§3.7.4 / §3.6.4-mirrored protocol identifiers, each emitted only when the coordinator
            //resolved a URL for it. inviteRequest (§3.7.5) and vcapi (§3.7.6) are the two the library
            //implements; OID4VP / OID4VCI / interact are ADVERTISED verbatim when the deployment offers
            //them (the §3.7.6 cross-protocol bridges are spec-deferred to "Appendix TBD").
            if(protocols.InviteRequestUrl is not null)
            {
                JsonAppender.AppendStringField(
                    sb, VcalmParameterNames.InviteRequest, protocols.InviteRequestUrl, ref protocolsFirst);
            }

            if(protocols.VcapiUrl is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.Vcapi, protocols.VcapiUrl, ref protocolsFirst);
            }

            if(protocols.OpenId4VpUrl is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.OpenId4Vp, protocols.OpenId4VpUrl, ref protocolsFirst);
            }

            if(protocols.OpenId4VciUrl is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.OpenId4Vci, protocols.OpenId4VciUrl, ref protocolsFirst);
            }

            if(protocols.InteractUrl is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.Interact, protocols.InteractUrl, ref protocolsFirst);
            }

            sb.Append("}}");

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// The §3.7.4 <c>text/html</c> fallback body: "When the interaction URL is fetched using any
    /// unrecognized Accept header, a text/html document MUST be returned with directions instructing a
    /// human being to use specific software that understands how to process interaction URLs." A fixed
    /// static document — the machine-readable protocols live in the §3.7.4 JSON path, so this page only
    /// has to point a person at suitable software.
    /// </summary>
    public static string BuildHumanDirectionHtml() =>
        "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head><meta charset=\"utf-8\"><title>Verifiable Credential Interaction</title></head>"
        + "<body>"
        + "<h1>Verifiable Credential Interaction</h1>"
        + "<p>This is a W3C VCALM 1.0 interaction URL. To proceed, open it with software that "
        + "understands how to process interaction URLs &mdash; for example a digital wallet or an "
        + "agent that supports the Verifiable Credential API for Lifecycle Management.</p>"
        + "<p>A machine-readable list of the protocols this interaction supports is available by "
        + "requesting this same URL with an <code>Accept: application/json</code> header.</p>"
        + "</body>"
        + "</html>";
}
