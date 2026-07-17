namespace Verifiable.OAuth;

/// <summary>
/// Discriminated union of validation failures a client-side token-request builder
/// (<see cref="TokenExchange.TokenExchangeRequestBuilder"/>, <see cref="JwtBearer.JwtBearerRequestBuilder"/>)
/// can produce when composing an outgoing request. These are build-time, client-side rejections — the
/// request never leaves the caller — distinct from <see cref="OAuthParseError"/>, which describes a
/// failure to parse a response the wire already returned.
/// </summary>
public abstract record TokenRequestBuilderError;


/// <summary>
/// A <c>resource</c> parameter value failed the client-side well-formedness checks
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see> place on the client:
/// an absolute URI with no fragment component. This is distinct from the authorization server's own
/// <c>invalid_target</c> policy decision (RFC 8693 §2.2.2), which runs only after a well-formed request
/// reaches the token endpoint.
/// </summary>
/// <param name="Value">The resource value that failed the check, exactly as supplied.</param>
/// <param name="Reason">The specific well-formedness rule <paramref name="Value"/> failed.</param>
public sealed record InvalidResourceParameter(string Value, string Reason): TokenRequestBuilderError;


/// <summary>
/// An entry in an open additional-parameters seam (<see cref="JwtBearer.JwtBearerBuilderOptions.AdditionalParameters"/>)
/// used a name reserved by the grant's own core parameters or by client-authentication parameters a
/// caller attaches as a separate step. Rejected rather than silently overwritten so a vendor-specific
/// parameter can never mask or corrupt a core wire value.
/// </summary>
/// <param name="ParameterName">The reserved name the additional-parameters seam attempted to set.</param>
public sealed record ReservedParameterNameCollision(string ParameterName): TokenRequestBuilderError;
