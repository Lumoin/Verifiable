namespace Verifiable.OAuth.Client;

/// <summary>
/// Parses an RFC 7591 §2 client metadata document body into a typed
/// <see cref="ClientMetadata"/>. Used by RFC 7592 §2.1 read responses and
/// §2.2 update responses — both echo the registered metadata as a
/// standalone JSON document (without the issued identifier or token,
/// which only appear on §3.2.1 registration responses).
/// </summary>
/// <remarks>
/// <para>
/// Distinct from <see cref="ParseRegistrationResponseDelegate"/>, which
/// parses the §3.2.1 response carrying <c>client_id</c>,
/// <c>registration_access_token</c>, <c>registration_client_uri</c>, plus
/// the metadata.
/// </para>
/// <para>
/// The library does not pick a JSON serializer, and no default
/// implementation of this delegate is shipped. Applications supply their
/// own, following the shape of
/// <see cref="Verifiable.OAuth.OAuthResponseParsers.ParseParResponse"/> and
/// <see cref="Verifiable.OAuth.OAuthResponseParsers.ParseTokenResponse"/>.
/// </para>
/// </remarks>
/// <param name="documentBody">The JSON body returned by the AS.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<ClientMetadata> ParseClientMetadataDelegate(
    string documentBody,
    CancellationToken cancellationToken);
