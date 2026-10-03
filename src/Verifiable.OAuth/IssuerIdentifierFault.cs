namespace Verifiable.OAuth;

/// <summary>
/// The first rule <see cref="IssuerIdentifier.Parse"/> refuses, in reader order. A refusal
/// carries no accepted issuer or comparison key.
/// </summary>
public enum IssuerIdentifierFault
{
    /// <summary>The original spelling is null or empty.</summary>
    Empty,

    /// <summary>The original spelling cannot be read as an absolute URI.</summary>
    AbsoluteUri,

    /// <summary>
    /// The URI reader would have to repair the original spelling: it holds a white-space or
    /// control character, or it is not a well-formed URI under <see cref="Uri.IsWellFormedOriginalString"/>.
    /// </summary>
    OriginalSyntax,

    /// <summary>The URL does not use the HTTPS scheme required by RFC 8414 section 2.</summary>
    Scheme,

    /// <summary>A query component, including an empty query, is present.</summary>
    Query,

    /// <summary>A fragment component, including an empty fragment, is present.</summary>
    Fragment
}
