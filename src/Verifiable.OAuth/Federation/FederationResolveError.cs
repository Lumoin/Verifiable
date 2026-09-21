namespace Verifiable.OAuth.Federation;

/// <summary>
/// The reason an application's <see cref="Server.ResolveSubjectTrustChainDelegate"/> could not
/// produce a <see cref="ResolveResponseContribution"/> for the <c>federation_resolve_endpoint</c>.
/// The library maps each reason to the
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>
/// error code and HTTP status it assigns.
/// </summary>
public enum FederationResolveError
{
    /// <summary>
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>:
    /// "The endpoint cannot serve the requested subject. The HTTP response status code SHOULD be
    /// 404 (Not Found)."
    /// </summary>
    InvalidSubject,

    /// <summary>
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>:
    /// "The Trust Anchor cannot be found or used. The HTTP response status code SHOULD be 404
    /// (Not Found)."
    /// </summary>
    InvalidTrustAnchor,

    /// <summary>
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>:
    /// "The Trust Chain cannot be validated. The HTTP response status code SHOULD be 400 (Bad
    /// Request)."
    /// </summary>
    InvalidTrustChain,

    /// <summary>
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>:
    /// "Metadata or Metadata Policy values are invalid or conflict. The HTTP response status code
    /// SHOULD be 400 (Bad Request)."
    /// </summary>
    InvalidMetadata,

    /// <summary>
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>:
    /// "The requested Entity Identifier cannot be found. The HTTP response status code SHOULD be
    /// 404 (Not Found)."
    /// </summary>
    NotFound
}
