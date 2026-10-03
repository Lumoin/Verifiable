using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.OAuth;

/// <summary>
/// The check every client flow makes on the answer to a request that carried a credential, before it
/// reads that answer as the endpoint's: an HTTP status of the 3xx (Redirection) class is refused as an
/// <see cref="OAuthRedirectRefused"/>, recorded as an <see cref="OAuthEventNames.CredentialBearingRedirectRefused"/>
/// event on the current activity, and never followed.
/// </summary>
/// <remarks>
/// <para>
/// Every transport delegate that carries such a request performs a single hop and returns a 3xx answer
/// as received (<see cref="Verifiable.OAuth.AuthCode.SendFormPostDelegate"/>,
/// <see cref="Verifiable.OAuth.Client.SendJsonPostDelegate"/> and their siblings). The flow that receives
/// one sends nothing further: following it would re-send the credential to whatever origin the
/// <c>Location</c> field names, since <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.4.8">RFC
/// 9110 §15.4.8</see> says of a 307 that "the user agent MUST NOT change the request method if it performs
/// an automatic redirection to that URI".
/// </para>
/// <para>
/// A flow that answers in a <see cref="Verifiable.Core.Result{TValue, TError}"/> returns the refusal from
/// <see cref="Refuse"/>; a flow that reports a refused answer by throwing throws it from
/// <see cref="ThrowIfRedirection"/> as an <see cref="OAuthRedirectRefusedException"/>.
/// </para>
/// </remarks>
internal static class CredentialBearingRedirect
{
    /// <summary>The <see cref="DecisionSupport.Summary"/> of every redirect refusal.</summary>
    private static string RefusalSummary { get; } =
        "The endpoint answered a request carrying a credential with a redirect, which this client does not follow.";

    /// <summary>The <see cref="DecisionSupport.LikelyCause"/> of every redirect refusal.</summary>
    private static string RefusalLikelyCause { get; } =
        "The endpoint URL names a location that forwards its requests elsewhere, or the endpoint is not the server the metadata or the registration names.";

    /// <summary>The <see cref="DecisionSupport.ActionableGuidance"/> of every redirect refusal.</summary>
    private static string RefusalGuidance { get; } =
        "Name the endpoint that answers the request itself in the metadata or the registration; a request carrying a credential is sent to exactly one endpoint.";

    /// <summary>The <see cref="DecisionSupport.SpecificationReference"/> of every redirect refusal.</summary>
    private static string RefusalSpecificationReference { get; } = "RFC 9110 §15.4.8";


    /// <summary>
    /// Refuses <paramref name="response"/> when its status is of the 3xx (Redirection) class: records an
    /// <see cref="OAuthEventNames.CredentialBearingRedirectRefused"/> event carrying the endpoint, the
    /// status and the <c>Location</c> value, and answers the typed refusal.
    /// </summary>
    /// <param name="endpoint">The endpoint the credential-bearing request was sent to.</param>
    /// <param name="response">The endpoint's answer, as the single-hop transport returned it.</param>
    /// <returns>The refusal, or <see langword="null"/> when the status is not of the 3xx class.</returns>
    internal static OAuthRedirectRefused? Refuse(Uri endpoint, HttpResponseData response)
    {
        if(!response.IsRedirection)
        {
            return null;
        }

        string? location = response.Headers.TryGetSingle(WellKnownHttpHeaderNames.Location);
        ActivityTagsCollection tags = new()
        {
            [OAuthEventNames.RedirectRefusalEndpointTagName] = endpoint.ToString(),
            [OAuthEventNames.RedirectRefusalStatusCodeTagName] = response.StatusCode
        };

        if(location is not null)
        {
            tags[OAuthEventNames.RedirectRefusalLocationTagName] = location;
        }

        _ = (Activity.Current?.AddEvent(new ActivityEvent(OAuthEventNames.CredentialBearingRedirectRefused, tags: tags)));

        return new OAuthRedirectRefused(
            endpoint,
            response.StatusCode,
            location,
            new DecisionSupport(RefusalSummary)
            {
                LikelyCause = RefusalLikelyCause,
                ActionableGuidance = RefusalGuidance,
                SpecificationReference = RefusalSpecificationReference
            });
    }


    /// <summary>
    /// Throws an <see cref="OAuthRedirectRefusedException"/> carrying the refusal of
    /// <paramref name="response"/> when its status is of the 3xx (Redirection) class (see
    /// <see cref="Refuse"/>), for a flow that reports a refused answer by throwing.
    /// </summary>
    /// <param name="endpoint">The endpoint the credential-bearing request was sent to.</param>
    /// <param name="response">The endpoint's answer, as the single-hop transport returned it.</param>
    /// <exception cref="OAuthRedirectRefusedException">The status is of the 3xx class.</exception>
    internal static void ThrowIfRedirection(Uri endpoint, HttpResponseData response)
    {
        if(Refuse(endpoint, response) is OAuthRedirectRefused refusal)
        {
            throw new OAuthRedirectRefusedException(refusal);
        }
    }
}
