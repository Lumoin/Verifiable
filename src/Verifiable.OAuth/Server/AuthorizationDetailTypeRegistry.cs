using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The per-request facts a <see cref="AuthorizationDetailHandler"/> needs to shape-validate one
/// authorization details object beyond the object's own contents.
/// </summary>
/// <remarks>
/// The library resolves these facts once per request and passes them to every handler so a
/// handler stays a pure function of the parsed object plus the deployment context, with no
/// reach back into the server.
/// </remarks>
[DebuggerDisplay("AuthorizationDetailValidationContext RequiredLocation={RequiredLocation}")]
public readonly record struct AuthorizationDetailValidationContext
{
    /// <summary>
    /// The location an authorization details object MUST carry in its <c>locations</c> common
    /// field, or <see langword="null"/> when the deployment imposes none. For
    /// <c>openid_credential</c> this is the OID4VCI 1.0 §5.1.1 / §6.1.1 Credential Issuer
    /// Identifier, required only when the Credential Issuer metadata declares
    /// <c>authorization_servers</c>.
    /// </summary>
    public string? RequiredLocation { get; init; }
}


/// <summary>
/// Shape-validates one parsed RFC 9396 authorization details object of the type the handler is
/// registered for. The return value is <see langword="null"/> when the object is acceptable, or
/// the <c>error_description</c> text for an <c>invalid_authorization_details</c> response
/// otherwise (RFC 9396 §5: an unknown field, a field of the wrong type, an invalid field value,
/// or a missing required field). A handler validating its type strictly composes this from
/// <see cref="AuthorizationDetailStrictFieldValidation.ForFields"/>, which enforces those abort
/// causes from a declared set of known fields; a handler with a lenient profile (the built-in
/// <c>openid_credential</c>, never invalid due to unknown fields per OID4VCI 1.0 §5.1.1) writes
/// its own check instead.
/// </summary>
/// <param name="detail">The parsed authorization details object, guaranteed to carry the handler's <c>type</c>.</param>
/// <param name="validation">The per-request deployment facts.</param>
/// <returns><see langword="null"/> when acceptable; the error description otherwise.</returns>
public delegate string? ValidateAuthorizationDetailShapeDelegate(
    AuthorizationDetail detail,
    AuthorizationDetailValidationContext validation);


/// <summary>
/// The behavior the <see cref="AuthorizationDetailTypeRegistry"/> dispatches for one RFC 9396
/// authorization details <c>type</c>: how an object of that type is shape-validated.
/// </summary>
/// <remarks>
/// One handler is registered per <c>type</c> value. The built-in <c>openid_credential</c>
/// handler (<see cref="Oid4Vci.OpenIdCredentialAuthorizationDetailHandler"/>) reproduces the
/// OID4VCI 1.0 §5.1.1 profile. Deployments register additional handlers to support further
/// types; each type they support is advertised in the AS metadata
/// <c>authorization_details_types_supported</c>.
/// </remarks>
[DebuggerDisplay("AuthorizationDetailHandler Type={Type}")]
public sealed record AuthorizationDetailHandler
{
    /// <summary>
    /// The RFC 9396 §2 <c>type</c> value this handler processes. Compared ordinally per
    /// RFC 9396 §12 ("All string comparisons ... are to be done as defined by [RFC8259]. No
    /// additional transformation or normalization is to be done").
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// Shape-validates an object of <see cref="Type"/>. Returns <see langword="null"/> when the
    /// object is acceptable, or the <c>invalid_authorization_details</c> error description
    /// otherwise.
    /// </summary>
    public required ValidateAuthorizationDetailShapeDelegate ValidateShape { get; init; }
}


/// <summary>
/// Routes a parsed RFC 9396 authorization details object to the handler registered for its
/// <c>type</c>, the generic dispatch the AS uses in place of a hardcoded single-type check
/// (RFC 9396 §5/§7). Mirrors the codebase's other type-keyed registries
/// (<see cref="OAuthActionExecutor"/>, <c>ProofFunctionRegistry</c>): a handler is registered
/// per <c>type</c>, and an object whose <c>type</c> has no registered handler is refused with
/// <c>invalid_authorization_details</c>.
/// </summary>
/// <remarks>
/// One registry instance hangs off each
/// <see cref="AuthorizationServerIntegration.AuthorizationDetailTypes"/>, pre-populated with the
/// built-in <c>openid_credential</c> handler. The set of
/// <see cref="RegisteredTypes"/> is what the AS metadata advertises as
/// <c>authorization_details_types_supported</c> (RFC 9396 §10).
/// </remarks>
[DebuggerDisplay("AuthorizationDetailTypeRegistry({handlers.Count} types)")]
public sealed class AuthorizationDetailTypeRegistry
{
    //Keyed by the RFC 9396 §2 type value, compared ordinally (RFC 9396 §12).
    private readonly Dictionary<string, AuthorizationDetailHandler> handlers =
        new(StringComparer.Ordinal);

    //The type values in registration order — the deterministic order RegisteredTypes
    //advertises; Dictionary enumeration order carries no such guarantee.
    private readonly List<string> registrationOrder = [];


    /// <summary>
    /// Registers <paramref name="handler"/> for its <see cref="AuthorizationDetailHandler.Type"/>.
    /// </summary>
    /// <param name="handler">The handler to register.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when a handler is already registered for the handler's <c>type</c>.
    /// </exception>
    public void Register(AuthorizationDetailHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        if(!handlers.TryAdd(handler.Type, handler))
        {
            throw new ArgumentException(
                $"A handler is already registered for authorization details type '{handler.Type}'.",
                nameof(handler));
        }

        registrationOrder.Add(handler.Type);
    }


    /// <summary>
    /// Whether a handler is registered for <paramref name="type"/>.
    /// </summary>
    /// <param name="type">The RFC 9396 §2 <c>type</c> value.</param>
    /// <returns><see langword="true"/> when a handler is registered; otherwise <see langword="false"/>.</returns>
    public bool IsRegistered(string type)
    {
        ArgumentNullException.ThrowIfNull(type);

        return handlers.ContainsKey(type);
    }


    /// <summary>
    /// The registered <c>type</c> values, the set advertised as
    /// <c>authorization_details_types_supported</c> (RFC 9396 §10). Ordered by registration so
    /// the built-in <c>openid_credential</c> leads and the advertisement is deterministic.
    /// </summary>
    public IReadOnlyList<string> RegisteredTypes => [.. registrationOrder];


    /// <summary>
    /// Shape-validates <paramref name="detail"/> against the handler for its <see cref="AuthorizationDetail.Type"/>.
    /// A <c>type</c> with no registered handler yields the RFC 9396 §5 unknown-type error;
    /// otherwise the handler's own verdict is returned.
    /// </summary>
    /// <param name="detail">The parsed authorization details object.</param>
    /// <param name="validation">The per-request deployment facts.</param>
    /// <returns><see langword="null"/> when the object is acceptable; the error description otherwise.</returns>
    public string? ValidateShape(
        AuthorizationDetail detail,
        AuthorizationDetailValidationContext validation)
    {
        ArgumentNullException.ThrowIfNull(detail);

        //RFC 9396 §5: "The AS MUST refuse to process any unknown authorization details type."
        if(!handlers.TryGetValue(detail.Type, out AuthorizationDetailHandler? handler))
        {
            return $"Authorization details type '{detail.Type}' is not supported.";
        }

        return handler.ValidateShape(detail, validation);
    }
}
