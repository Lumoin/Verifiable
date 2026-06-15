using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Hand-built JSON writers for the W3C VCALM 1.0 §3.6 exchange response bodies — the §3.6.4
/// protocols response, the §3.6.5 vcapi reply, and the §3.6.6 exchange-state response — through
/// <see cref="JsonAppender"/> per the <c>Verifiable.Vcalm</c> serialization firewall (no
/// <c>System.Text.Json</c>). Embedded verifiable presentations / presentation requests are emitted
/// with <see cref="JsonAppender.AppendRawField"/> from the verbatim JSON the engine composed or the
/// parser preserved, so they ride through byte-faithful.
/// </summary>
public static class VcalmExchangeResponseWriter
{
    /// <summary>
    /// Writes the §3.6.4 get-exchange-protocols response: the <c>protocols</c> object mapping each
    /// supported protocol identifier to its initiation URL. The §3.6.4 <c>vcapi</c> URL is REQUIRED
    /// (this engine always supports the vcapi protocol); the optional <c>OID4VP</c> / <c>OID4VCI</c> /
    /// <c>interact</c> URLs are emitted only when the deployment composed them.
    /// </summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The §3.6.4 protocols URLs are verbatim wire strings the deployment's endpoint-URI resolver composed (the OID4VP URL is itself a non-http openid4vp:// URI); they ride through to the response body unparsed, so System.Uri would force a round-trip that loses the resolver's exact shape.")]
    public static string BuildProtocolsResponse(
        string vcapiUrl,
        string? openId4VpUrl,
        string? openId4VciUrl,
        string? interactUrl)
    {
        ArgumentException.ThrowIfNullOrEmpty(vcapiUrl);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            //§3.6.4: the response is a single object carrying the protocols map.
            sb.Append("{\"");
            JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Protocols);
            sb.Append("\":{");

            bool protocolsFirst = true;
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Vcapi, vcapiUrl, ref protocolsFirst);

            if(openId4VpUrl is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.OpenId4Vp, openId4VpUrl, ref protocolsFirst);
            }

            if(openId4VciUrl is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.OpenId4Vci, openId4VciUrl, ref protocolsFirst);
            }

            if(interactUrl is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.Interact, interactUrl, ref protocolsFirst);
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
    /// Writes the §3.6.5 vcapi "request a presentation" reply: a <c>verifiablePresentationRequest</c>
    /// member carrying the verbatim §3.4 VPR JSON the engine composed, plus the optional §3.6.5
    /// <c>referenceId</c> correlation value. §3.6: "If the object includes verifiablePresentationRequest,
    /// then the exchange is not yet complete and some additional information is requested."
    /// </summary>
    public static string BuildPresentationRequestReply(string verifiablePresentationRequestJson, string? referenceId)
    {
        ArgumentException.ThrowIfNullOrEmpty(verifiablePresentationRequestJson);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendRawField(
                sb, VcalmParameterNames.VerifiablePresentationRequest, verifiablePresentationRequestJson, ref first);
            AppendOptionalReferenceId(sb, referenceId, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes the §3.6.5 vcapi "offer a presentation" reply: a <c>verifiablePresentation</c> member
    /// carrying the verbatim server-emitted presentation the engine offers (an issued credential wrapped
    /// in a presentation, §3.6.5 / §3.6.8), plus the optional <c>referenceId</c>. §3.6: "If a Verifiable
    /// Presentation is sent, an additional Verifiable Presentation Request may also be sent" — this
    /// engine offers the issued presentation as the completing reply.
    /// </summary>
    public static string BuildOfferedPresentationReply(string verifiablePresentationJson, string? referenceId)
    {
        ArgumentException.ThrowIfNullOrEmpty(verifiablePresentationJson);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendRawField(
                sb, VcalmParameterNames.VerifiablePresentation, verifiablePresentationJson, ref first);
            AppendOptionalReferenceId(sb, referenceId, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes a §3.6.6 <c>variables.results</c> step-result object — <c>{ verifiablePresentation : &lt;vp&gt; }</c>
    /// — from the verbatim presentation JSON the engine recorded at the step. The accumulated map stores
    /// each step's value in this shape so the §3.6.6 view emits it raw.
    /// </summary>
    public static string BuildStepPresentationResult(string verifiablePresentationJson)
    {
        ArgumentException.ThrowIfNullOrEmpty(verifiablePresentationJson);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendRawField(
                sb, VcalmParameterNames.VerifiablePresentation, verifiablePresentationJson, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes the §3.6.5 vcapi completion reply: the empty exchange-continuation object signalling the
    /// exchange is complete, carrying only the optional §3.6.5 <c>referenceId</c>. §3.6: "If that
    /// response object is empty, the exchange is complete and nothing is requested from nor offered to
    /// the exchange client."
    /// </summary>
    public static string BuildCompletionReply(string? referenceId)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            AppendOptionalReferenceId(sb, referenceId, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes the §3.6.5 vcapi redirect reply: a <c>redirectUrl</c> member plus the optional
    /// <c>referenceId</c>. §3.6: "If the object includes redirectUrl, the exchange is complete and the
    /// workflow service recommends that the client proceed to another place."
    /// </summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "§3.6 redirectUrl is a verbatim wire string the engine passes through opaquely; it rides through to the response body unparsed.")]
    public static string BuildRedirectReply(string redirectUrl, string? referenceId)
    {
        ArgumentException.ThrowIfNullOrEmpty(redirectUrl);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(sb, VcalmParameterNames.RedirectUrl, redirectUrl, ref first);
            AppendOptionalReferenceId(sb, referenceId, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes the §3.6.6 get-exchange-state response: the <c>id</c>, <c>sequence</c>, optional
    /// <c>expires</c>, optional <c>step</c>, <c>state</c>, optional <c>lastError</c> ProblemDetail, and
    /// the <c>variables</c> object carrying the reserved <c>results</c> (the per-step
    /// <c>verifiablePresentation</c>s the engine accepted) and the creator's <c>variables</c>.
    /// </summary>
    public static string BuildExchangeStateResponse(VcalmStoredExchange exchange)
    {
        ArgumentNullException.ThrowIfNull(exchange);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;

            JsonAppender.AppendStringField(sb, VcalmParameterNames.Id, exchange.ExchangeId, ref first);
            JsonAppender.AppendInt64Field(sb, VcalmParameterNames.Sequence, exchange.Sequence, ref first);

            if(exchange.Expires is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.Expires, exchange.Expires, ref first);
            }

            if(exchange.Step is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.Step, exchange.Step, ref first);
            }

            JsonAppender.AppendStringField(sb, VcalmParameterNames.State, StateText(exchange.State), ref first);

            if(exchange.LastError is { } lastError)
            {
                AppendLastError(sb, lastError, ref first);
            }

            AppendVariables(sb, exchange, ref first);

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    //§3.6.6 variables: { results { STEP_NAME { verifiablePresentation } }, <creator variables...> }.
    private static void AppendVariables(StringBuilder sb, VcalmStoredExchange exchange, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Variables);
        sb.Append("\":{");

        //results { STEP_NAME { verifiablePresentation } }.
        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Results);
        sb.Append("\":{");

        bool resultsFirst = true;
        foreach(KeyValuePair<string, string> stepResult in exchange.StepResults)
        {
            //§3.6.6: each STEP_NAME maps to the verbatim result object the engine recorded (already
            //shaped { verifiablePresentation : <vp> }); it rides through raw, byte-faithful.
            JsonAppender.AppendRawField(sb, stepResult.Key, stepResult.Value, ref resultsFirst);
        }

        sb.Append('}');

        sb.Append('}');
        first = false;
    }


    //§3.6.6 lastError: a §3.8 ProblemDetail { type, title?, detail? }.
    private static void AppendLastError(StringBuilder sb, VcalmProblemDetail lastError, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.LastError);
        sb.Append("\":{");

        bool errorFirst = true;
        JsonAppender.AppendStringField(sb, VcalmParameterNames.ProblemType, lastError.Type, ref errorFirst);
        if(lastError.Title is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.ProblemTitle, lastError.Title, ref errorFirst);
        }

        if(lastError.Detail is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.ProblemDetail, lastError.Detail, ref errorFirst);
        }

        sb.Append('}');
        first = false;
    }


    private static void AppendOptionalReferenceId(StringBuilder sb, string? referenceId, ref bool first)
    {
        if(referenceId is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.ReferenceId, referenceId, ref first);
        }
    }


    //§3.6.6 state values: the lower-case wire tokens pending | active | complete | invalid.
    private static string StateText(VcalmExchangeState state) => state switch
    {
        VcalmExchangeState.Pending => "pending",
        VcalmExchangeState.Active => "active",
        VcalmExchangeState.Complete => "complete",
        VcalmExchangeState.Invalid => "invalid",
        _ => "invalid"
    };
}
