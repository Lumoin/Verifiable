namespace Verifiable.OAuth.Client;

/// <summary>The reason a metadata document could not be decoded.</summary>
public enum AuthorizationServerMetadataUnreadableReason
{
    /// <summary>The complete document is not syntactically valid JSON.</summary>
    InvalidJson,

    /// <summary>The body contains invalid UTF-8 bytes.</summary>
    InvalidUtf8,

    /// <summary>A JSON string or property name contains an unpaired surrogate escape.</summary>
    UnpairedSurrogate,

    /// <summary>The top-level JSON value is not an object.</summary>
    NotObject,

    /// <summary>The top-level object has no issuer member.</summary>
    MissingIssuer,

    /// <summary>The issuer member is not a JSON string.</summary>
    IssuerNotString,

    /// <summary>A URI-valued member is not an absolute URI.</summary>
    InvalidUri,

    /// <summary>A known optional member has the wrong JSON type.</summary>
    InvalidMemberType
}


/// <summary>A metadata decoding failure; no exception message is needed to classify it.</summary>
/// <param name="Reason">The typed decoding failure.</param>
/// <param name="MemberName">The well-known member name, or null for a document-wide failure.</param>
public sealed record AuthorizationServerMetadataParseError(
    AuthorizationServerMetadataUnreadableReason Reason,
    string? MemberName);
