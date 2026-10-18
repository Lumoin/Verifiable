using System.Text.Json;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Wraps <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>'s
/// default validator so a real-wire test can inspect every presented <c>client_assertion</c>, at
/// the pushed request and the token request alike, in arrival order, without maintaining a
/// separate capture path in each test class that needs one.
/// </summary>
internal static class ClientAssertionRecorder
{
    /// <summary>
    /// Builds a <see cref="ValidateClientCredentialsDelegate"/> that appends the presented
    /// <c>client_assertion</c> form field to <paramref name="recordedAssertions"/>, in the order
    /// each request reaches the server, then delegates to
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
    /// with no explicit policy, so the default accepted set is the one
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 Section 2</see> requires
    /// a server to accept (the issuer identifier, token endpoint and pushed-authorization endpoint);
    /// a passing exchange proves the default server accepts exactly what the client sent.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-5">rfc7523bis-11
    /// Section 5</see> replaces that default under
    /// <see cref="ClientAssertionAudiencePolicy.IssuerIdentifierOnly"/>, a server's own opt-in this
    /// wrapper does not choose.
    /// </summary>
    /// <param name="recordedAssertions">The list every presented compact <c>client_assertion</c> is appended to.</param>
    public static ValidateClientCredentialsDelegate Wrap(List<string> recordedAssertions)
    {
        ArgumentNullException.ThrowIfNull(recordedAssertions);

        ValidateClientCredentialsDelegate inner = PrivateKeyJwtClientAuthentication.BuildValidator(
            additionalAcceptedAudiences: null,
            checkJtiReplayAsync: null,
            resolveJwksUriAsync: null,
            audiencePolicy: null);

        return async (request, fields, registration, context, cancellationToken) =>
        {
            if(fields.TryGetValue(OAuthRequestParameterNames.ClientAssertion, out string? assertion))
            {
                recordedAssertions.Add(assertion);
            }

            return await inner(request, fields, registration, context, cancellationToken).ConfigureAwait(false);
        };
    }


    /// <summary>
    /// Splits <paramref name="compactAssertion"/> into its three compact-JWS segments and returns
    /// the protected header's <c>typ</c> value alongside the payload's <c>aud</c> claim as decoded
    /// JSON, so a caller can assert both halves of the same assertion (<see
    /// href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">rfc7523bis-11
    /// Section 4</see>'s <c>aud</c> and <c>typ</c> rules) without decoding it twice through two
    /// separate paths.
    /// </summary>
    /// <param name="compactAssertion">The compact-serialised <c>private_key_jwt</c> assertion to decode.</param>
    /// <param name="pool">The memory pool the base64url decode step rents transient buffers from.</param>
    public static (string Typ, JsonElement Audience) DecodeTypAndAudience(string compactAssertion, BaseMemoryPool pool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactAssertion);
        ArgumentNullException.ThrowIfNull(pool);

        string[] segments = compactAssertion.Split('.');
        Assert.HasCount(3, segments);

        byte[] headerBytes = SecurityEventTestJson.DecodeSegment(segments[0], pool);
        using JsonDocument header = JsonDocument.Parse(headerBytes);
        string typ = header.RootElement.GetProperty(WellKnownJoseHeaderNames.Typ).GetString()!;

        using JsonDocument payload = JwtPayloadDecoding.DecodePayload(compactAssertion, pool);
        JsonElement audience = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud).Clone();

        return (typ, audience);
    }
}
