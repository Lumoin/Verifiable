using System.Text.RegularExpressions;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// Contains regular expression patterns for validating DID URLs according to the W3C DID 1.0 specification.
    /// These patterns implement the ABNF rules defined in sections 3.1 and 3.2 of the specification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The patterns in this class correspond to the following ABNF rules from the W3C DID specification:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>DID Syntax:</strong> <see href="https://www.w3.org/TR/did-1.0/#did-syntax">Section 3.1</see>
    /// - <c>did = "did:" method-name ":" method-specific-id</c>.
    /// </description></item>
    /// <item><description>
    /// <strong>DID URL Syntax:</strong> <see href="https://www.w3.org/TR/did-1.0/#did-url-syntax">Section 3.2</see>
    /// - <c>did-url = did path-abempty [ "?" query ] [ "#" fragment ]</c>.
    /// </description></item>
    /// <item><description>
    /// <strong>Relative DID URLs:</strong> <see href="https://www.w3.org/TR/did-1.0/#relative-did-urls">Section 3.2.2</see>
    /// - Fragment-only references like "#key-1" used in verification relationships.
    /// </description></item>
    /// </list>
    /// </remarks>
    public static partial class DidUrlRegex
    {
        /// <summary>
        /// Validates complete DID URLs according to the ABNF rule: did-url = did path-abempty [ "?" query ] [ "#" fragment ].
        /// </summary>
        /// <remarks>
        /// <para>
        /// This pattern validates absolute DID URLs that must start with the "did:" scheme and include
        /// a method name and method-specific identifier. Optional components include path, query parameters,
        /// and fragment identifiers as defined in RFC 3986.
        /// </para>
        /// <para>
        /// Capture groups:
        /// </para>
        /// <list type="number">
        /// <item><description>Method name (e.g., "example" from "did:example:123").</description></item>
        /// <item><description>Method-specific identifier (e.g., "123" from "did:example:123").</description></item>
        /// <item><description>Path component (optional, e.g., "/path").</description></item>
        /// <item><description>Query component (optional, e.g., "service=files").</description></item>
        /// <item><description>Fragment component (optional, e.g., "key-1").</description></item>
        /// </list>
        /// <para>
        /// Reference: <see href="https://www.w3.org/TR/did-1.0/#did-url-syntax">W3C DID 1.0 Section 3.2</see>
        /// </para>
        /// </remarks>
        [GeneratedRegex(@"^did:([a-z0-9]+):((?:[a-zA-Z0-9._-]|%[0-9a-fA-F]{2})+(?::(?:[a-zA-Z0-9._-]|%[0-9a-fA-F]{2})+)*)(/[^?#]*)?(\?[^#]*)?(#.*)?$")]
        public static partial Regex AbsoluteDidUrl();


        /// <summary>
        /// Validates fragment-only references used in relative DID URLs as defined in Section 3.2.2.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This pattern validates relative DID URL references that consist only of a fragment identifier,
        /// commonly used in verification relationships within DID documents. These references are resolved
        /// against the base DID of the containing document.
        /// </para>
        /// <para>
        /// Capture groups:
        /// </para>
        /// <list type="number">
        /// <item><description>Fragment content (e.g., "key-1" from "#key-1").</description></item>
        /// </list>
        /// <para>
        /// Example uses in DID documents:
        /// </para>
        /// <list type="bullet">
        /// <item><description>Authentication: "#key-1" → resolves to "did:example:123#key-1".</description></item>
        /// <item><description>Service references: "#agent" → resolves to "did:example:123#agent".</description></item>
        /// </list>
        /// <para>
        /// Reference: <see href="https://www.w3.org/TR/did-1.0/#relative-did-urls">W3C DID 1.0 Section 3.2.2</see>.
        /// </para>
        /// </remarks>
        [GeneratedRegex("^#(.+)$")]
        public static partial Regex FragmentReference();


        /// <summary>
        /// Validates either absolute DID URLs or fragment-only references, providing unified validation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This pattern combines validation for both absolute DID URLs and relative fragment references,
        /// allowing flexible parsing in contexts where either format may be encountered (such as
        /// verification relationships in DID documents).
        /// </para>
        /// <para>
        /// Capture groups for absolute DID URLs:
        /// </para>
        /// <list type="number">
        /// <item><description>Method name.</description></item>
        /// <item><description>Method-specific identifier.</description></item>
        /// <item><description>Path component (optional).</description></item>
        /// <item><description>Query component (optional).</description></item>
        /// <item><description>Fragment component from absolute URL (optional).</description></item>
        /// </list>
        /// <para>
        /// Capture groups for fragment references:
        /// </para>
        /// <list type="number">
        /// <item><description>Fragment content (when input is fragment-only).</description></item>
        /// </list>
        /// <para>
        /// References:
        /// <see href="https://www.w3.org/TR/did-1.0/#did-url-syntax">W3C DID 1.0 Section 3.2</see> and
        /// <see href="https://www.w3.org/TR/did-1.0/#relative-did-urls">Section 3.2.2</see>.
        /// </para>
        /// </remarks>
        [GeneratedRegex("^(?:did:([a-z0-9]+):((?:[a-zA-Z0-9]|\\.|-|_|%[0-9a-fA-F]{2})+)(\\/[^?#]*)?(\\?[^#]*)?(?:#(.*))?|(#(.+)))$")]
        public static partial Regex AnyDidUrl();
    }
}
