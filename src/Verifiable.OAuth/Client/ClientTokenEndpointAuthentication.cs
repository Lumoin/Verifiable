using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Per-call inputs for signing the <c>private_key_jwt</c> client assertion
/// <see cref="ClientTokenEndpointAuthentication.AttachClientAssertionAsync"/> attaches to a
/// token-endpoint request per
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 §2.2</see>. The signing
/// key itself is read from <see cref="ClientRegistration.AuthenticationKeyMaterial"/> — this record
/// carries only the pieces that vary independently of the registration (the <c>kid</c>, the wire
/// serialisers, and the assertion's validity window).
/// </summary>
[DebuggerDisplay("ClientAssertionOptions SigningKeyId={SigningKeyId}")]
public sealed record ClientAssertionOptions
{
    /// <summary>
    /// The <c>kid</c> header parameter value identifying
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>'s private key to the authorization
    /// server.
    /// </summary>
    public required string SigningKeyId { get; init; }

    /// <summary>Serialises the client-assertion protected header to UTF-8 JSON bytes.</summary>
    public required JwtHeaderSerializer HeaderSerializer { get; init; }

    /// <summary>Serialises the client-assertion payload claims to UTF-8 JSON bytes.</summary>
    public required JwtPayloadSerializer PayloadSerializer { get; init; }

    /// <summary>The validity window of the signed client assertion (RFC 7523 §3). Defaults to one minute.</summary>
    public TimeSpan ClientAssertionLifetime { get; init; } = TimeSpan.FromMinutes(1);
}


/// <summary>
/// Composes the <c>private_key_jwt</c> confidential-client authentication assertion
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 §2.2</see> defines,
/// shared by every client-side flow that authenticates a confidential client at a token endpoint:
/// the <see cref="Verifiable.OAuth.IdJag.IdJagFlowHandlers"/> mint (§4.3) and redeem (§4.4)
/// exchanges, and the <see cref="Verifiable.OAuth.AuthCode.AuthCodeFlowHandlers"/> authorization-code
/// token leg.
/// </summary>
[DebuggerDisplay("ClientTokenEndpointAuthentication")]
public static class ClientTokenEndpointAuthentication
{
    /// <summary>
    /// Adds the confidential-client authentication parameters — <c>client_id</c>,
    /// <c>client_assertion_type</c>, and a freshly-signed <c>private_key_jwt</c> <c>client_assertion</c>
    /// (RFC 7523 §2.2) bound to the token endpoint — to a token-endpoint request form.
    /// </summary>
    public static async ValueTask AttachClientAssertionAsync(
        OutgoingFormFields form,
        ClientRegistration registration,
        Uri tokenEndpoint,
        PrivateKeyMemory signingKey,
        string signingKeyId,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        TimeSpan clientAssertionLifetime,
        OAuthClientInfrastructure infrastructure,
        DateTimeOffset now,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(tokenEndpoint);
        ArgumentNullException.ThrowIfNull(infrastructure);

        string jti = await infrastructure.GenerateIdentifierAsync(
            WellKnownIdentifierPurposes.OAuthJti, context, cancellationToken).ConfigureAwait(false);

        string clientAssertion = await ClientAssertionSigning.SignAsync(
            registration.ClientId.Value,
            tokenEndpoint.OriginalString,
            jti,
            now,
            now.Add(clientAssertionLifetime),
            signingKey,
            signingKeyId,
            headerSerializer,
            payloadSerializer,
            infrastructure.Base64UrlEncoder,
            infrastructure.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        form[OAuthRequestParameterNames.ClientId] = registration.ClientId.Value;
        form[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
        form[OAuthRequestParameterNames.ClientAssertion] = clientAssertion;
    }
}
