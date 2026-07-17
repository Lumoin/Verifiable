using System.Diagnostics;
using Verifiable.Core;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.WellKnown;

namespace Verifiable.OAuth.JwtBearer;

/// <summary>
/// Per-call inputs for <see cref="JwtBearerRequestBuilder.Build(JwtBearerBuilderOptions)"/> — the
/// client side of an <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.1">RFC 7523 §2.1</see>
/// JWT Bearer authorization-grant request.
/// </summary>
[DebuggerDisplay("JwtBearerBuilderOptions HasScope={Scope != null}")]
public sealed record JwtBearerBuilderOptions
{
    /// <summary>The single JWT presented as the authorization grant (RFC 7523 §2.1 <c>assertion</c>, REQUIRED — "MUST contain a single JWT"). Confidential.</summary>
    public required string Assertion { get; init; }

    /// <summary>The requested scope (RFC 7523 §2.1 / RFC 6749 §3.3 <c>scope</c>, OPTIONAL).</summary>
    public string? Scope { get; init; }

    /// <summary>
    /// Additional form fields merged onto the request beyond the RFC 7523 §2.1 core parameter set —
    /// the composable seam a deployment uses to build a vendor-specific token-request recipe (for
    /// example, an identity provider's own on-behalf-of-style parameter) without the library naming
    /// that vendor or parameter anywhere in <c>src/**</c>. A name that collides with
    /// <see cref="JwtBearerRequestBuilder.ReservedParameterNames"/> is rejected via
    /// <see cref="ReservedParameterNameCollision"/> rather than silently overwriting a core or
    /// client-authentication parameter. <see langword="null"/> or empty adds nothing.
    /// </summary>
    public IReadOnlyDictionary<string, string>? AdditionalParameters { get; init; }
}


/// <summary>
/// Builds the body of an <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.1">RFC 7523 §2.1</see>
/// JWT Bearer authorization-grant request as an <see cref="OutgoingFormFields"/>.
/// </summary>
/// <remarks>
/// Static and allocation-light: no I/O. Client authentication is OPTIONAL for this grant (RFC 7523
/// §2.1: "the 'client_id' is only needed when a form of client authentication that relies on the
/// parameter is used"; §3.1) and, when used, is a separate composable step via
/// <see cref="OutgoingFormFieldsClientAuthExtensions.WithClientSecretPost"/>,
/// <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/>, or
/// <see cref="ClientAssertionSigning"/> — never forced by this builder. The caller hands the
/// resulting <see cref="OutgoingFormFields"/> to <see cref="OAuthClientInfrastructure.SendFormPostAsync"/>;
/// no percent-encoding happens here (the transport delegate owns
/// <c>application/x-www-form-urlencoded</c> wire encoding).
/// </remarks>
public static class JwtBearerRequestBuilder
{
    /// <summary>
    /// The parameter names <see cref="JwtBearerBuilderOptions.AdditionalParameters"/> MUST NOT
    /// collide with: the grant's own RFC 7523 §2.1 parameters (<c>grant_type</c>, <c>assertion</c>,
    /// <c>scope</c>) and the client-authentication parameters a caller attaches as a separate step —
    /// RFC 6749 §2.3.1 body-parameter authentication (<c>client_id</c>, <c>client_secret</c>) and
    /// RFC 7523 §2.2 <c>private_key_jwt</c> authentication (<c>client_assertion</c>,
    /// <c>client_assertion_type</c>). Ordinal comparison.
    /// </summary>
    public static IReadOnlyCollection<string> ReservedParameterNames { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        OAuthRequestParameterNames.GrantType,
        OAuthRequestParameterNames.Assertion,
        OAuthRequestParameterNames.Scope,
        OAuthRequestParameterNames.ClientId,
        OAuthRequestParameterNames.ClientSecret,
        OAuthRequestParameterNames.ClientAssertion,
        OAuthRequestParameterNames.ClientAssertionType
    };


    /// <summary>
    /// Composes <paramref name="options"/> into the RFC 7523 §2.1 request body, or a
    /// <see cref="TokenRequestBuilderError"/> when <see cref="JwtBearerBuilderOptions.AdditionalParameters"/>
    /// carries a name in <see cref="ReservedParameterNames"/>.
    /// </summary>
    /// <param name="options">The per-call JWT Bearer grant inputs.</param>
    public static Result<OutgoingFormFields, TokenRequestBuilderError> Build(JwtBearerBuilderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(options.AdditionalParameters is not null)
        {
            foreach(string name in options.AdditionalParameters.Keys)
            {
                if(ReservedParameterNames.Contains(name))
                {
                    return Result.Failure<OutgoingFormFields, TokenRequestBuilderError>(
                        new ReservedParameterNameCollision(name));
                }
            }
        }

        OutgoingFormFields form = new(capacity: 3 + (options.AdditionalParameters?.Count ?? 0))
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.Assertion] = options.Assertion
        };

        if(!string.IsNullOrEmpty(options.Scope))
        {
            form[OAuthRequestParameterNames.Scope] = options.Scope;
        }

        if(options.AdditionalParameters is not null)
        {
            foreach((string name, string value) in options.AdditionalParameters)
            {
                form[name] = value;
            }
        }

        return Result.Success<OutgoingFormFields, TokenRequestBuilderError>(form);
    }
}
