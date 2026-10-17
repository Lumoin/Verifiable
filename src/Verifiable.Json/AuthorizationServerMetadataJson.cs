using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;

namespace Verifiable.Json;

/// <summary>
/// The complete-document JSON implementation of <see cref="ParseAuthorizationServerMetadataDelegate"/>.
/// </summary>
public static class AuthorizationServerMetadataJson
{
    /// <summary>Validates the original bytes without replacing malformed UTF-8 sequences.</summary>
    private static UTF8Encoding StrictUtf8 { get; } = new(false, true);


    /// <summary>
    /// Parses a complete UTF-8 JSON object. The issuer is a required JSON string and is unescaped
    /// before URI construction. All property names and strings, including unknown members, must
    /// decode without unpaired surrogates. Known endpoints, string arrays, and booleans are read
    /// from top-level members only; unknown members are otherwise ignored.
    /// </summary>
    /// <param name="document">The complete, original UTF-8 response body.</param>
    /// <returns>The document or a typed decoding failure; malformed input does not escape as an exception.</returns>
    public static Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> Parse(
        ReadOnlyMemory<byte> document)
    {
        try
        {
            _ = StrictUtf8.GetCharCount(document.Span);
        }
        catch(DecoderFallbackException)
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidUtf8, null);
        }

        try
        {
            using(JsonDocument parsed = JsonDocument.Parse(document))
            {
                JsonElement root = parsed.RootElement;
                if(!CanDecodeStrings(root))
                {
                    return Failure(AuthorizationServerMetadataUnreadableReason.UnpairedSurrogate, null);
                }

                if(root.ValueKind != JsonValueKind.Object)
                {
                    return Failure(AuthorizationServerMetadataUnreadableReason.NotObject, null);
                }

                return ReadMetadata(root);
            }
        }
        catch(JsonException)
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidJson, null);
        }
    }


    /// <summary>
    /// Forces System.Text.Json's deferred string decoding throughout the already parsed document.
    /// Parsing alone validates JSON syntax but does not unescape every string or property name.
    /// </summary>
    private static bool CanDecodeStrings(JsonElement element)
    {
        try
        {
            switch(element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach(JsonProperty property in element.EnumerateObject())
                    {
                        _ = property.Name;
                        if(!CanDecodeStrings(property.Value))
                        {
                            return false;
                        }
                    }

                    break;
                case JsonValueKind.Array:
                    foreach(JsonElement item in element.EnumerateArray())
                    {
                        if(!CanDecodeStrings(item))
                        {
                            return false;
                        }
                    }

                    break;
                case JsonValueKind.String:
                    _ = element.GetString();
                    break;
            }

            return true;
        }
        catch(InvalidOperationException)
        {
            //The complete JSON syntax and UTF-8 have already been validated. The remaining
            //string decoding failure is an unpaired UTF-16 surrogate in a Unicode escape.
            return false;
        }
    }


    /// <summary>Reads the known metadata members from a validated JSON object.</summary>
    private static Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> ReadMetadata(JsonElement body)
    {
        if(!body.TryGetProperty(AuthorizationServerMetadataParameterNames.Issuer, out JsonElement issuer))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.MissingIssuer,
                AuthorizationServerMetadataParameterNames.Issuer);
        }

        if(issuer.ValueKind != JsonValueKind.String)
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.IssuerNotString,
                AuthorizationServerMetadataParameterNames.Issuer);
        }

        if(!Uri.TryCreate(issuer.GetString(), UriKind.Absolute, out Uri? issuerUri))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidUri,
                AuthorizationServerMetadataParameterNames.Issuer);
        }

        (Uri? authorizationEndpoint, AuthorizationServerMetadataParseError? authorizationEndpointError) =
            ReadOptionalUri(body, AuthorizationServerMetadataParameterNames.AuthorizationEndpoint);
        if(authorizationEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(authorizationEndpointError);
        }

        (Uri? tokenEndpoint, AuthorizationServerMetadataParseError? tokenEndpointError) =
            ReadOptionalUri(body, AuthorizationServerMetadataParameterNames.TokenEndpoint);
        if(tokenEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(tokenEndpointError);
        }

        (Uri? pushedAuthorizationRequestEndpoint, AuthorizationServerMetadataParseError? pushedAuthorizationRequestEndpointError) =
            ReadOptionalUri(body, AuthorizationServerMetadataParameterNames.PushedAuthorizationRequestEndpoint);
        if(pushedAuthorizationRequestEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(pushedAuthorizationRequestEndpointError);
        }

        (Uri? revocationEndpoint, AuthorizationServerMetadataParseError? revocationEndpointError) =
            ReadOptionalUri(body, AuthorizationServerMetadataParameterNames.RevocationEndpoint);
        if(revocationEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(revocationEndpointError);
        }

        (Uri? introspectionEndpoint, AuthorizationServerMetadataParseError? introspectionEndpointError) =
            ReadOptionalUri(body, AuthorizationServerMetadataParameterNames.IntrospectionEndpoint);
        if(introspectionEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(introspectionEndpointError);
        }

        (Uri? jwksUri, AuthorizationServerMetadataParseError? jwksUriError) =
            ReadOptionalUri(body, AuthorizationServerMetadataParameterNames.JwksUri);
        if(jwksUriError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(jwksUriError);
        }

        (Uri? registrationEndpoint, AuthorizationServerMetadataParseError? registrationEndpointError) =
            ReadOptionalUri(body, AuthorizationServerMetadataParameterNames.RegistrationEndpoint);
        if(registrationEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(registrationEndpointError);
        }

        (Uri? endSessionEndpoint, AuthorizationServerMetadataParseError? endSessionEndpointError) =
            ReadOptionalUri(body, AuthorizationServerMetadataParameterNames.EndSessionEndpoint);
        if(endSessionEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(endSessionEndpointError);
        }

        (Uri? userInfoEndpoint, AuthorizationServerMetadataParseError? userInfoEndpointError) =
            ReadOptionalUri(body, OpenIdProviderMetadataParameterNames.UserinfoEndpoint);
        if(userInfoEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(userInfoEndpointError);
        }

        (Uri? deviceAuthorizationEndpoint, AuthorizationServerMetadataParseError? deviceAuthorizationEndpointError) =
            ReadOptionalUri(body, AuthorizationServerMetadataParameterNames.DeviceAuthorizationEndpoint);
        if(deviceAuthorizationEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(deviceAuthorizationEndpointError);
        }

        if(!TryReadStringArray(body, AuthorizationServerMetadataParameterNames.ResponseTypesSupported, out List<string> responseTypesSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.ResponseTypesSupported);
        }

        if(!TryReadStringArray(body, AuthorizationServerMetadataParameterNames.GrantTypesSupported, out List<string> grantTypesSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.GrantTypesSupported);
        }

        if(!TryReadStringArray(body, AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported, out List<string> tokenEndpointAuthMethodsSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported);
        }

        if(!TryReadStringArray(body, AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported, out List<string> tokenEndpointAuthSigningAlgValuesSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported);
        }

        if(!TryReadStringArray(body, AuthorizationServerMetadataParameterNames.ScopesSupported, out List<string> scopesSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.ScopesSupported);
        }

        if(!TryReadStringArray(body, AuthorizationServerMetadataParameterNames.CodeChallengeMethodsSupported, out List<string> codeChallengeMethodsSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.CodeChallengeMethodsSupported);
        }

        if(!TryReadStringArray(body, OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported, out List<string> idTokenSigningAlgValuesSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported);
        }

        if(!TryReadStringArray(body, AuthorizationServerMetadataParameterNames.RequestObjectSigningAlgValuesSupported, out List<string> requestObjectSigningAlgValuesSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.RequestObjectSigningAlgValuesSupported);
        }

        if(!TryReadStringArray(body, AuthorizationServerMetadataParameterNames.DpopSigningAlgValuesSupported, out List<string> dpopSigningAlgValuesSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.DpopSigningAlgValuesSupported);
        }

        if(!TryReadBoolean(body, AuthorizationServerMetadataParameterNames.RequirePushedAuthorizationRequests, out bool requirePushedAuthorizationRequests))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.RequirePushedAuthorizationRequests);
        }

        if(!TryReadBoolean(body, AuthorizationServerMetadataParameterNames.AuthorizationResponseIssParameterSupported, out bool authorizationResponseIssParameterSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.AuthorizationResponseIssParameterSupported);
        }

        if(!TryReadBoolean(body, AuthorizationServerMetadataParameterNames.RequireSignedRequestObject, out bool requireSignedRequestObject))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.RequireSignedRequestObject);
        }

        if(!TryReadBoolean(body, AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported, out bool clientIdMetadataDocumentSupported))
        {
            return Failure(AuthorizationServerMetadataUnreadableReason.InvalidMemberType, AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported);
        }

        return Result.Success<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(
            new AuthorizationServerMetadata
            {
                Issuer = issuerUri,
                AuthorizationEndpoint = authorizationEndpoint,
                TokenEndpoint = tokenEndpoint,
                PushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint,
                RevocationEndpoint = revocationEndpoint,
                IntrospectionEndpoint = introspectionEndpoint,
                JwksUri = jwksUri,
                RegistrationEndpoint = registrationEndpoint,
                EndSessionEndpoint = endSessionEndpoint,
                UserInfoEndpoint = userInfoEndpoint,
                DeviceAuthorizationEndpoint = deviceAuthorizationEndpoint,
                ResponseTypesSupported = responseTypesSupported,
                GrantTypesSupported = grantTypesSupported,
                //RFC 8414 §2 gives an omitted list a meaning of its own, client_secret_basic alone, which a list stated empty does
                //not have, so the omission is kept as such.
                TokenEndpointAuthMethodsSupported = body.TryGetProperty(AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported, out _)
                    ? tokenEndpointAuthMethodsSupported
                    : null,
                TokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported,
                ScopesSupported = scopesSupported,
                CodeChallengeMethodsSupported = codeChallengeMethodsSupported,
                IdTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported,
                RequestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported,
                DpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported,
                RequirePushedAuthorizationRequests = requirePushedAuthorizationRequests,
                AuthorizationResponseIssParameterSupported = authorizationResponseIssParameterSupported,
                RequireSignedRequestObject = requireSignedRequestObject,
                ClientIdMetadataDocumentSupported = clientIdMetadataDocumentSupported
            });
    }


    /// <summary>Reads an optional endpoint URI and identifies a malformed member by its well-known name.</summary>
    private static (Uri? Value, AuthorizationServerMetadataParseError? Error) ReadOptionalUri(
        JsonElement body, string memberName)
    {
        if(!body.TryGetProperty(memberName, out JsonElement value))
        {
            return (null, null);
        }

        if(value.ValueKind != JsonValueKind.String)
        {
            return (null, new AuthorizationServerMetadataParseError(
                AuthorizationServerMetadataUnreadableReason.InvalidMemberType, memberName));
        }

        if(Uri.TryCreate(value.GetString(), UriKind.Absolute, out Uri? uri))
        {
            return (uri, null);
        }

        return (null, new AuthorizationServerMetadataParseError(
            AuthorizationServerMetadataUnreadableReason.InvalidUri, memberName));
    }


    /// <summary>Reads a supported-values list; an absent member yields an empty list.</summary>
    private static bool TryReadStringArray(JsonElement body, string memberName, out List<string> values)
    {
        values = [];
        if(!body.TryGetProperty(memberName, out JsonElement array))
        {
            return true;
        }

        if(array.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach(JsonElement element in array.EnumerateArray())
        {
            if(element.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            values.Add(element.GetString()!);
        }

        return true;
    }


    /// <summary>Reads an optional boolean; an absent member yields false.</summary>
    private static bool TryReadBoolean(JsonElement body, string memberName, out bool value)
    {
        value = false;
        if(!body.TryGetProperty(memberName, out JsonElement element))
        {
            return true;
        }

        if(element.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            return false;
        }

        value = element.GetBoolean();

        return true;
    }


    /// <summary>Constructs a typed parse failure without retaining response text.</summary>
    private static Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> Failure(
        AuthorizationServerMetadataUnreadableReason reason, string? memberName) =>
        Result.Failure<AuthorizationServerMetadata, AuthorizationServerMetadataParseError>(
            new AuthorizationServerMetadataParseError(reason, memberName));
}
