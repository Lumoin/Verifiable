using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Typed <see cref="ExchangeContext"/> accessors for the W3C VCALM 1.0 holder layer — the per-request
/// values an endpoint stages between <c>BuildInputAsync</c> and <c>BuildResponse</c> (the analogue of
/// the SIOP request-handle / request-object context slots). The §3.6 exchange engine stages the §3.6.3
/// create and §3.6.5 participate values here; the §3.4.3.2 holder anti-replay binding stages the
/// current communication channel's domain. Each value is keyed by an interned string under the
/// <c>vcalm.exchange.*</c> namespace, mirroring how the Server / OAuth layers key their context slots.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class VcalmExchangeContextExtensions
{
    private const string ExchangeIdKey = "vcalm.exchange.id";
    private const string ReplyKey = "vcalm.exchange.reply";
    private const string VcapiUrlKey = "vcalm.exchange.vcapi_url";
    private const string ChannelDomainKey = "vcalm.exchange.channel_domain";

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


        /// <summary>
        /// The §3.4.3.2 current communication channel's domain — the domain of the channel the holder
        /// is actually answering over (e.g. the TLS origin / verifier identity the wallet or channel
        /// adapter established when it received the presentation request). When present, the §3.5.2
        /// create-presentation path enforces that the request's <c>domain</c> (the verifier identity the
        /// presentation proof binds) matches it before signing — §3.4.3.2: "the holder MUST check that
        /// the domain value matches the domain of the verifier it is communicating with." A mismatch is
        /// a relayed / replayed request and the holder refuses fail-closed. When this slot is left unset
        /// the §3.5.2 stateless primitive signs the request's <c>domain</c> verbatim with no channel
        /// check; a conforming §3.4.3.2 holder deployment MUST populate it (via its channel adapter)
        /// before invoking create-presentation so the anti-replay binding is enforced.
        /// </summary>
        public string? CurrentChannelDomain =>
            context.TryGetValue(ChannelDomainKey, out object? v) && v is string domain ? domain : null;

        /// <summary>Sets the §3.4.3.2 current communication channel's domain on the request context.</summary>
        public void SetCurrentChannelDomain(string channelDomain)
        {
            ArgumentException.ThrowIfNullOrEmpty(channelDomain);
            context[ChannelDomainKey] = channelDomain;
        }
    }
}
