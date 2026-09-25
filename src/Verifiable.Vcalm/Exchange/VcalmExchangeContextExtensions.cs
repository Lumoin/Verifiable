using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Typed <see cref="ExchangeContext"/> accessors for the W3C VCALM 1.0 exchange engine — the per-request
/// values an endpoint stages between <c>BuildInputAsync</c> and <c>BuildResponse</c> (the analogue of
/// the SIOP request-handle / request-object context slots). The §3.6 exchange engine stages its §3.6.3
/// create and §3.6.5 participate values here. Each value is keyed by an interned string under the
/// <c>vcalm.exchange.*</c> namespace, mirroring how the Server / OAuth layers key their context slots.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class VcalmExchangeContextExtensions
{
    /// <summary>The context key the §3.6 <c>VcalmExchangeId</c> accessor and its setter read and write under.</summary>
    private const string ExchangeIdKey = "vcalm.exchange.id";

    /// <summary>The context key the §3.6.5 <c>VcalmExchangeReply</c> accessor and its setter read and write under.</summary>
    private const string ReplyKey = "vcalm.exchange.reply";

    /// <summary>The context key the §3.6.5 <c>VcalmExchangeVcapiUrl</c> accessor and its setter read and write under.</summary>
    private const string VcapiUrlKey = "vcalm.exchange.vcapi_url";

    extension(ExchangeContext context)
    {
        /// <summary>The §3.6 <c>{localExchangeId}</c> the current request targets / minted.</summary>
        public string? VcalmExchangeId =>
            context.TryGetValue(ExchangeIdKey, out object? v) && v is string id ? id : null;

        /// <summary>Sets the §3.6 <c>{localExchangeId}</c> on the request context.</summary>
        public void SetVcalmExchangeId(string exchangeId)
        {
            ArgumentException.ThrowIfNullOrEmpty(exchangeId);
            context[ExchangeIdKey] = exchangeId;
        }


        /// <summary>The §3.6.5 vcapi reply the participate step staged for its response.</summary>
        public ServerHttpResponse? VcalmExchangeReply =>
            context.TryGetValue(ReplyKey, out object? v) && v is ServerHttpResponse r ? r : null;

        /// <summary>Sets the §3.6.5 vcapi reply on the request context.</summary>
        public void SetVcalmExchangeReply(ServerHttpResponse reply)
        {
            ArgumentNullException.ThrowIfNull(reply);
            context[ReplyKey] = reply;
        }


        /// <summary>The §3.6.5 vcapi participation URL composed for the §3.6.3 create response's Location header.</summary>
        [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
            Justification = "The vcapi URL is the verbatim string the deployment's endpoint-URI resolver composed; it rides through to the Location header unparsed.")]
        public string? VcalmExchangeVcapiUrl =>
            context.TryGetValue(VcapiUrlKey, out object? v) && v is string url ? url : null;

        /// <summary>Sets the §3.6.5 vcapi participation URL on the request context.</summary>
        [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
            Justification = "The vcapi URL is the verbatim string the deployment's endpoint-URI resolver composed; it is stored unparsed.")]
        public void SetVcalmExchangeVcapiUrl(string vcapiUrl)
        {
            ArgumentException.ThrowIfNullOrEmpty(vcapiUrl);
            context[VcapiUrlKey] = vcapiUrl;
        }
    }
}
