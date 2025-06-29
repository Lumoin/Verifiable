using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;


namespace Verifiable.Core.Did
{
    /// <summary>
    /// Represents a parsed DID URL according to the W3C DID 1.0 specification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A DID URL is a network location identifier for a specific resource that can be used to retrieve
    /// representations of DID subjects, verification methods, services, specific parts of a DID document,
    /// or other resources. This class provides immutable access to all components of a DID URL including
    /// the base DID, path, query parameters, and fragment identifier.
    /// </para>
    /// <para>
    /// DID URLs can take several forms:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>Absolute DID URLs:</strong> Complete URLs like "did:example:123#key-1" that include
    /// the full DID identifier plus optional components.
    /// </description></item>
    /// <item><description>
    /// <strong>Relative fragment references:</strong> Fragment-only references like "#key-1" that
    /// are resolved against a base DID within the same document.
    /// </description></item>
    /// </list>
    /// <para>
    /// The class supports both parsing modes through explicit methods (<see cref="ParseAbsolute"/>,
    /// <see cref="ParseFragment"/>) and a unified parser (<see cref="Parse"/>) for flexible usage
    /// in different contexts.
    /// </para>
    /// <para>
    /// Reference: <see href="https://www.w3.org/TR/did-1.0/#did-url-syntax">W3C DID 1.0 Section 3.2</see>
    /// </para>
    /// </remarks>
    [DebuggerDisplay("DidUrl({ToString(),nq})")]
    public sealed class DidUrl: IEquatable<DidUrl>
    {
        /// <summary>
        /// The DID method name (e.g., "example" from "did:example:123").
        /// </summary>
        /// <remarks>
        /// <para>
        /// The method name identifies the specific DID method being used and determines the rules
        /// for creating, reading, updating, and deleting the DID. This value is null for relative
        /// fragment references that do not include a complete DID.
        /// </para>
        /// <para>
        /// According to the ABNF specification, method names must consist of lowercase letters
        /// (a-z) and digits (0-9) only.
        /// </para>
        /// <para>
        /// Reference: <see href="https://www.w3.org/TR/did-1.0/#did-syntax">W3C DID 1.0 Section 3.1</see>
        /// </para>
        /// </remarks>
        public string? Method { get; }

        /// <summary>
        /// The method-specific identifier portion of the DID (e.g., "123" from "did:example:123").
        /// </summary>
        /// <remarks>
        /// <para>
        /// The method-specific identifier is unique within the scope of the DID method and identifies
        /// a specific DID subject. The format and constraints for this identifier are defined by
        /// the specific DID method specification. This value is null for relative fragment references.
        /// </para>
        /// <para>
        /// Valid characters include alphanumeric characters (A-Z, a-z, 0-9), periods (.), hyphens (-),
        /// underscores (_), and percent-encoded characters.
        /// </para>
        /// <para>
        /// Reference: <see href="https://www.w3.org/TR/did-1.0/#did-syntax">W3C DID 1.0 Section 3.1</see>
        /// </para>
        /// </remarks>
        public string? MethodSpecificId { get; }

        /// <summary>
        /// The path component of the DID URL (e.g., "/path" from "did:example:123/path").
        /// </summary>
        /// <remarks>
        /// <para>
        /// The path component is identical to a generic URI path and conforms to the path-abempty
        /// ABNF rule in RFC 3986, section 3.3. Path semantics can be specified by DID methods,
        /// which may enable DID controllers to further specialize those semantics.
        /// </para>
        /// <para>
        /// This property includes the leading forward slash when present. It is null when no path
        /// component is specified in the DID URL.
        /// </para>
        /// <para>
        /// Reference: <see href="https://www.w3.org/TR/did-1.0/#did-url-syntax">W3C DID 1.0 Section 3.2</see>
        /// </para>
        /// </remarks>
        public string? Path { get; }

        /// <summary>
        /// The query component of the DID URL without the leading question mark (e.g., "service=files" from "did:example:123?service=files").
        /// </summary>
        /// <remarks>
        /// <para>
        /// The query component is identical to a generic URI query and conforms to the query ABNF
        /// rule in RFC 3986, section 3.4. DID parameters are encoded in the query component and
        /// become part of the identifier for a resource.
        /// </para>
        /// <para>
        /// Common DID parameters include:
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>service</c> - Identifies a service from the DID document by service ID</description></item>
        /// <item><description><c>relativeRef</c> - A relative URI reference to a resource at a service endpoint</description></item>
        /// <item><description><c>versionId</c> - Identifies a specific version of a DID document</description></item>
        /// <item><description><c>versionTime</c> - Identifies a version timestamp of a DID document</description></item>
        /// <item><description><c>hl</c> - A resource hash for integrity protection</description></item>
        /// </list>
        /// <para>
        /// This property does not include the leading question mark. It is null when no query
        /// component is specified in the DID URL.
        /// </para>
        /// <para>
        /// Reference: <see href="https://www.w3.org/TR/did-1.0/#did-parameters">W3C DID 1.0 Section 3.2.1</see>
        /// </para>
        /// </remarks>
        public string? Query { get; }

        /// <summary>
        /// The fragment component of the DID URL without the leading hash symbol (e.g., "key-1" from "did:example:123#key-1" or "#key-1").
        /// </summary>
        /// <remarks>
        /// <para>
        /// The fragment component is used as a method-independent reference into a DID document
        /// or external resource. It conforms to the fragment ABNF rule in RFC 3986, section 3.5.
        /// Fragments are commonly used to reference verification methods, services, or other
        /// resources within a DID document.
        /// </para>
        /// <para>
        /// Common fragment patterns include:
        /// </para>
        /// <list type="bullet">
        /// <item><description>Verification method references: "key-1", "public-key-0"</description></item>
        /// <item><description>Service references: "agent", "messaging"</description></item>
        /// <item><description>JSON Pointer references: "verificationMethod/0"</description></item>
        /// </list>
        /// <para>
        /// This property does not include the leading hash symbol. It is null when no fragment
        /// component is specified in the DID URL.
        /// </para>
        /// <para>
        /// Reference: <see href="https://www.w3.org/TR/did-1.0/#did-url-syntax">W3C DID 1.0 Section 3.2</see>
        /// </para>
        /// </remarks>
        public string? Fragment { get; }

        /// <summary>
        /// Indicates whether this DID URL represents a relative fragment reference (e.g., "#key-1").
        /// </summary>
        /// <remarks>
        /// <para>
        /// Relative DID URLs are URL values in a DID document that do not start with the complete
        /// DID syntax. They are expected to reference resources in the same DID document and are
        /// commonly used in verification relationships to reduce storage size and improve readability.
        /// </para>
        /// <para>
        /// When this property is true, the <see cref="Method"/> and <see cref="MethodSpecificId"/>
        /// properties will be null, and only the <see cref="Fragment"/> property will contain a value.
        /// </para>
        /// <para>
        /// Relative DID URLs can be resolved to absolute DID URLs using the <see cref="Resolve"/>
        /// method with an appropriate base DID.
        /// </para>
        /// <para>
        /// Reference: <see href="https://www.w3.org/TR/did-1.0/#relative-did-urls">W3C DID 1.0 Section 3.2.2</see>
        /// </para>
        /// </remarks>
        public bool IsRelative { get; }

        /// <summary>
        /// Indicates whether this DID URL represents an absolute DID URL with complete method and identifier information.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Absolute DID URLs contain the complete DID syntax including method name and method-specific
        /// identifier, and may optionally include path, query, and fragment components.
        /// </para>
        /// <para>
        /// When this property is true, the <see cref="Method"/> and <see cref="MethodSpecificId"/>
        /// properties will contain valid values representing the DID components.
        /// </para>
        /// </remarks>
        public bool IsAbsolute => !IsRelative;

        /// <summary>
        /// Gets the base DID without path, query, or fragment components (e.g., "did:example:123").
        /// </summary>
        /// <remarks>
        /// <para>
        /// The base DID consists of the scheme ("did"), method name, and method-specific identifier.
        /// This property returns null for relative fragment references that do not contain complete
        /// DID information.
        /// </para>
        /// <para>
        /// This property is useful when you need to extract just the core DID identifier without
        /// any additional URL components for operations like document resolution or controller validation.
        /// </para>
        /// </remarks>
        public string? BaseDid => IsAbsolute ? $"did:{Method}:{MethodSpecificId}" : null;

        /// <summary>
        /// Initializes a new instance of the <see cref="DidUrl"/> class with the specified components.
        /// </summary>
        /// <param name="method">The DID method name.</param>
        /// <param name="methodSpecificId">The method-specific identifier.</param>
        /// <param name="path">The path component (optional).</param>
        /// <param name="query">The query component (optional).</param>
        /// <param name="fragment">The fragment component (optional).</param>
        /// <remarks>
        /// This constructor is used for creating absolute DID URLs. All parameters are stored as-is
        /// without validation. Use the static parsing methods for input validation.
        /// </remarks>
        private DidUrl(string method, string methodSpecificId, string? path = null, string? query = null, string? fragment = null)
        {
            Method = method;
            MethodSpecificId = methodSpecificId;
            Path = path;
            Query = query;
            Fragment = fragment;
            IsRelative = false;
        }


        /// <summary>
        /// Initializes a new instance of the <see cref="DidUrl"/> class for a relative fragment reference.
        /// </summary>
        /// <param name="fragment">The fragment component without the leading hash symbol.</param>
        /// <remarks>
        /// This constructor is used for creating relative DID URL references that consist only of
        /// a fragment identifier. The resulting instance will have <see cref="IsRelative"/> set to true.
        /// </remarks>
        private DidUrl(string fragment)
        {
            Fragment = fragment;
            IsRelative = true;
        }


        /// <summary>
        /// Parses an absolute DID URL string and returns a <see cref="DidUrl"/> instance.
        /// </summary>
        /// <param name="input">The absolute DID URL string to parse.</param>
        /// <returns>A <see cref="DidUrl"/> instance representing the parsed URL.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="input"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="input"/> is not a valid absolute DID URL.</exception>
        /// <remarks>
        /// <para>
        /// This method strictly validates that the input is a complete DID URL that starts with
        /// the "did:" scheme and includes a valid method name and method-specific identifier.
        /// Fragment-only references like "#key-1" will cause this method to throw an exception.
        /// </para>
        /// <para>
        /// For safe parsing without exceptions, use <see cref="TryParseAbsolute"/> instead.
        /// For parsing that accepts both absolute URLs and fragment references, use <see cref="Parse"/>.
        /// </para>
        /// <para>
        /// Valid input examples:
        /// </para>
        /// <list type="bullet">
        /// <item><description>"did:example:123"</description></item>
        /// <item><description>"did:example:123#key-1"</description></item>
        /// <item><description>"did:example:123/path?service=files#key-1"</description></item>
        /// </list>
        /// </remarks>
        public static DidUrl ParseAbsolute(string input)
        {
            ArgumentNullException.ThrowIfNull(input, nameof(input));

            if(TryParseAbsolute(input, out DidUrl? result))
            {
                return result;
            }

            throw new ArgumentException($"Input '{input}' is not a valid absolute DID URL.", nameof(input));
        }


        /// <summary>
        /// Parses a fragment-only DID reference string and returns a <see cref="DidUrl"/> instance.
        /// </summary>
        /// <param name="input">The fragment reference string to parse (e.g., "#key-1").</param>
        /// <returns>A <see cref="DidUrl"/> instance representing the parsed fragment reference.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="input"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="input"/> is not a valid fragment reference.</exception>
        /// <remarks>
        /// <para>
        /// This method strictly validates that the input is a fragment-only reference that starts
        /// with the "#" symbol. Complete DID URLs like "did:example:123" will cause this method
        /// to throw an exception.
        /// </para>
        /// <para>
        /// For safe parsing without exceptions, use <see cref="TryParseFragment"/> instead.
        /// For parsing that accepts both absolute URLs and fragment references, use <see cref="Parse"/>.
        /// </para>
        /// <para>
        /// Valid input examples:
        /// </para>
        /// <list type="bullet">
        /// <item><description>"#key-1"</description></item>
        /// <item><description>"#agent"</description></item>
        /// <item><description>"#verificationMethod/0"</description></item>
        /// </list>
        /// </remarks>
        public static DidUrl ParseFragment(string input)
        {
            ArgumentNullException.ThrowIfNull(input, nameof(input));

            if(TryParseFragment(input, out DidUrl? result))
            {
                return result;
            }

            throw new ArgumentException($"Input '{input}' is not a valid fragment reference.", nameof(input));
        }


        /// <summary>
        /// Parses a DID URL string that can be either an absolute DID URL or a fragment reference.
        /// </summary>
        /// <param name="input">The DID URL string to parse.</param>
        /// <returns>A <see cref="DidUrl"/> instance representing the parsed URL.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="input"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="input"/> is not a valid DID URL or fragment reference.</exception>
        /// <remarks>
        /// <para>
        /// This method provides flexible parsing that accepts both absolute DID URLs and relative
        /// fragment references. It automatically determines the type of input and creates the
        /// appropriate <see cref="DidUrl"/> instance.
        /// </para>
        /// <para>
        /// For safe parsing without exceptions, use <see cref="TryParse"/> instead.
        /// For strict validation of specific formats, use <see cref="ParseAbsolute"/> or <see cref="ParseFragment"/>.
        /// </para>
        /// <para>
        /// Valid input examples:
        /// </para>
        /// <list type="bullet">
        /// <item><description>"did:example:123" (absolute)</description></item>
        /// <item><description>"did:example:123#key-1" (absolute with fragment)</description></item>
        /// <item><description>"#key-1" (relative fragment)</description></item>
        /// </list>
        /// </remarks>
        public static DidUrl Parse(string input)
        {
            ArgumentNullException.ThrowIfNull(input, nameof(input));

            if(TryParse(input, out DidUrl? result))
            {
                return result;
            }

            throw new ArgumentException($"Input '{input}' is not a valid DID URL or fragment reference.", nameof(input));
        }


        /// <summary>
        /// Attempts to parse an absolute DID URL string.
        /// </summary>
        /// <param name="input">The absolute DID URL string to parse.</param>
        /// <param name="result">When this method returns, contains the parsed <see cref="DidUrl"/> if successful; otherwise, null.</param>
        /// <returns>True if the parsing was successful; otherwise, false.</returns>
        /// <remarks>
        /// <para>
        /// This method provides safe parsing of absolute DID URLs without throwing exceptions.
        /// It validates that the input conforms to the complete DID URL syntax including the
        /// "did:" scheme, method name, and method-specific identifier.
        /// </para>
        /// <para>
        /// Fragment-only references like "#key-1" will return false and set result to null.
        /// </para>
        /// </remarks>
        public static bool TryParseAbsolute(string? input, [NotNullWhen(true)] out DidUrl? result)
        {
            result = null;

            if(string.IsNullOrEmpty(input))
            {
                return false;
            }

            var match = DidUrlRegex.AbsoluteDidUrl().Match(input);
            if(!match.Success)
            {
                return false;
            }

            string method = match.Groups[1].Value;
            string methodSpecificId = match.Groups[2].Value;
            string? path = match.Groups[3].Success ? match.Groups[3].Value : null;
            string? query = match.Groups[4].Success ? match.Groups[4].Value[1..] : null; //Remove leading '?'.
            string? fragment = match.Groups[5].Success ? match.Groups[5].Value[1..] : null; //Remove leading '#'.
            result = new DidUrl(method, methodSpecificId, path, query, fragment);

            return true;
        }


        /// <summary>
        /// Attempts to parse a fragment-only DID reference string.
        /// </summary>
        /// <param name="input">The fragment reference string to parse.</param>
        /// <param name="result">When this method returns, contains the parsed <see cref="DidUrl"/> if successful; otherwise, null.</param>
        /// <returns>True if the parsing was successful; otherwise, false.</returns>
        /// <remarks>
        /// <para>
        /// This method provides safe parsing of fragment-only references without throwing exceptions.
        /// It validates that the input starts with "#" and contains valid fragment content.
        /// </para>
        /// <para>
        /// Complete DID URLs like "did:example:123" will return false and set result to null.
        /// </para>
        /// </remarks>
        public static bool TryParseFragment(string? input, [NotNullWhen(true)] out DidUrl? result)
        {
            result = null;

            if(string.IsNullOrEmpty(input))
            {
                return false;
            }

            var match = DidUrlRegex.FragmentReference().Match(input);
            if(!match.Success)
            {
                return false;
            }

            string fragment = match.Groups[1].Value;
            result = new DidUrl(fragment);
            return true;
        }


        /// <summary>
        /// Attempts to parse a DID URL string that can be either an absolute DID URL or a fragment reference.
        /// </summary>
        /// <param name="input">The DID URL string to parse.</param>
        /// <param name="result">When this method returns, contains the parsed <see cref="DidUrl"/> if successful; otherwise, null.</param>
        /// <returns>True if the parsing was successful; otherwise, false.</returns>
        /// <remarks>
        /// <para>
        /// This method provides safe, flexible parsing that accepts both absolute DID URLs and
        /// relative fragment references without throwing exceptions. It automatically determines
        /// the type of input and creates the appropriate <see cref="DidUrl"/> instance.
        /// </para>
        /// </remarks>
        public static bool TryParse(string? input, [NotNullWhen(true)] out DidUrl? result)
        {
            //Try absolute first, then fragment
            if(TryParseAbsolute(input, out result))
            {
                return true;
            }

            return TryParseFragment(input, out result);
        }


        /// <summary>
        /// Resolves a relative DID URL reference against a base DID to create an absolute DID URL.
        /// </summary>
        /// <param name="baseDid">The base DID to resolve against.</param>
        /// <returns>A new <see cref="DidUrl"/> instance representing the resolved absolute URL.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="baseDid"/> is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when this instance is not a relative reference or when the base DID is not absolute.</exception>
        /// <remarks>
        /// <para>
        /// This method implements the resolution algorithm specified in RFC 3986 Section 5 for
        /// resolving relative DID URL references. The base DID provides the scheme ("did"),
        /// method name, and method-specific identifier, while the relative reference provides
        /// the fragment identifier.
        /// </para>
        /// <para>
        /// Example resolution:
        /// </para>
        /// <list type="bullet">
        /// <item><description>Base DID: "did:example:123"</description></item>
        /// <item><description>Relative reference: "#key-1"</description></item>
        /// <item><description>Result: "did:example:123#key-1"</description></item>
        /// </list>
        /// <para>
        /// Reference: <see href="https://www.w3.org/TR/did-1.0/#relative-did-urls">W3C DID 1.0 Section 3.2.2</see>
        /// </para>
        /// </remarks>
        public DidUrl Resolve(DidUrl baseDid)
        {
            ArgumentNullException.ThrowIfNull(baseDid, nameof(baseDid));

            if(!IsRelative)
            {
                throw new InvalidOperationException("Cannot resolve an absolute DID URL. Only relative references can be resolved.");
            }

            if(baseDid.IsRelative)
            {
                throw new InvalidOperationException("Base DID must be an absolute DID URL, not a relative reference.");
            }

            //For fragment-only references, append the fragment to the base DID
            return new DidUrl(baseDid.Method!, baseDid.MethodSpecificId!, baseDid.Path, baseDid.Query, Fragment);
        }

        /// <summary>
        /// Parses the query component and returns a dictionary of DID parameters.
        /// </summary>
        /// <returns>A dictionary containing the parsed query parameters, or an empty dictionary if no query component exists.</returns>
        /// <remarks>
        /// <para>
        /// This method parses the query string using standard URL query parameter parsing rules.
        /// Parameter names and values are URL-decoded automatically. Duplicate parameter names
        /// will result in only the last value being retained.
        /// </para>
        /// <para>
        /// Common DID parameters that may be present include:
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>service</c> - Service identifier</description></item>
        /// <item><description><c>relativeRef</c> - Relative URI reference</description></item>
        /// <item><description><c>versionId</c> - Version identifier</description></item>
        /// <item><description><c>versionTime</c> - Version timestamp</description></item>
        /// <item><description><c>hl</c> - Hash link for integrity</description></item>
        /// </list>
        /// </remarks>
        public Dictionary<string, string> GetParameters()
        {
            if(string.IsNullOrEmpty(Query))
            {
                return new Dictionary<string, string>();
            }

            var parameters = new Dictionary<string, string>();
            var querySpan = Query.AsSpan();

            while(!querySpan.IsEmpty)
            {
                //Find the next parameter boundary.
                int ampersandIndex = querySpan.IndexOf('&');
                ReadOnlySpan<char> pairSpan = ampersandIndex == -1
                    ? querySpan
                    : querySpan[..ampersandIndex];

                //Process this parameter.
                if(!pairSpan.IsEmpty)
                {
                    int equalsIndex = pairSpan.IndexOf('=');
                    if(equalsIndex == -1)
                    {
                        //Parameter without value.
                        string key = Uri.UnescapeDataString(pairSpan.ToString());
                        parameters[key] = string.Empty;
                    }
                    else
                    {
                        //Parameter with value.
                        string key = Uri.UnescapeDataString(pairSpan[..equalsIndex].ToString());
                        string value = Uri.UnescapeDataString(pairSpan[(equalsIndex + 1)..].ToString());
                        parameters[key] = value;
                    }
                }

                //Move to the next parameter.
                if(ampersandIndex == -1)
                {
                    break;
                }
                querySpan = querySpan[(ampersandIndex + 1)..];
            }

            return parameters;
        }


        /// <summary>
        /// Gets the value of a specific DID parameter from the query component.
        /// </summary>
        /// <param name="parameterName">The name of the parameter to retrieve.</param>
        /// <returns>The parameter value if found; otherwise, null.</returns>
        /// <remarks>
        /// <para>
        /// This method provides convenient access to individual DID parameters without needing
        /// to parse the entire query string. Parameter names are case-sensitive.
        /// </para>
        /// </remarks>
        public string? GetParameter(string parameterName)
        {
            ArgumentNullException.ThrowIfNull(parameterName, nameof(parameterName));

            var parameters = GetParameters();
            return parameters.TryGetValue(parameterName, out string? value) ? value : null;
        }


        /// <summary>
        /// Returns the canonical string representation of this DID URL.
        /// </summary>
        /// <returns>The complete DID URL as a string.</returns>
        /// <remarks>
        /// <para>
        /// For absolute DID URLs, this returns the complete URL including all components.
        /// For relative fragment references, this returns just the fragment with the leading "#".
        /// </para>
        /// <para>
        /// The returned string can be parsed back into a <see cref="DidUrl"/> instance using
        /// the <see cref="Parse"/> method.
        /// </para>
        /// </remarks>
        public override string ToString()
        {
            if(IsRelative)
            {
                return $"#{Fragment}";
            }

            var builder = new StringBuilder();
            builder.Append($"did:{Method}:{MethodSpecificId}");

            if(!string.IsNullOrEmpty(Path))
            {
                builder.Append(Path);
            }

            if(!string.IsNullOrEmpty(Query))
            {
                builder.Append($"?{Query}");
            }

            if(!string.IsNullOrEmpty(Fragment))
            {
                builder.Append($"#{Fragment}");
            }

            return builder.ToString();
        }


        /// <summary>
        /// Implicitly converts a <see cref="DidUrl"/> to its string representation.
        /// </summary>
        /// <param name="didUrl">The DID URL to convert.</param>
        /// <returns>The string representation of the DID URL, or null if the input is null.</returns>
        /// <remarks>
        /// <para>
        /// This operator enables seamless use of <see cref="DidUrl"/> instances in string contexts
        /// such as string interpolation, concatenation, and method calls that expect strings.
        /// </para>
        /// </remarks>
        public static implicit operator string?(DidUrl? didUrl) => didUrl?.ToString();


        /// <summary>
        /// Explicitly converts a string to a <see cref="DidUrl"/> instance.
        /// </summary>
        /// <param name="input">The string to convert.</param>
        /// <returns>A <see cref="DidUrl"/> instance representing the parsed string.</returns>
        /// <exception cref="ArgumentException">Thrown when the input string is not a valid DID URL or fragment reference.</exception>
        /// <remarks>
        /// <para>
        /// This operator requires explicit casting to ensure intentional conversion from strings
        /// to <see cref="DidUrl"/> instances. For safe conversion without exceptions, use the
        /// <see cref="TryParse"/> method instead.
        /// </para>
        /// </remarks>
        public static explicit operator DidUrl(string input) => Parse(input);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(DidUrl? other)
        {
            if(other is null)
            {
                return false;
            }

            if(ReferenceEquals(this, other))
            {
                return true;
            }

            return string.Equals(Method, other.Method, StringComparison.Ordinal)
                && string.Equals(MethodSpecificId, other.MethodSpecificId, StringComparison.Ordinal)
                && string.Equals(Path, other.Path, StringComparison.Ordinal)
                && string.Equals(Query, other.Query, StringComparison.Ordinal)
                && string.Equals(Fragment, other.Fragment, StringComparison.Ordinal)
                && IsRelative == other.IsRelative;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? obj) => obj is DidUrl other && Equals(other);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(DidUrl? left, DidUrl? right)
        {
            if(left is null)
            {
                return right is null;
            }

            return left.Equals(right);
        }

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(DidUrl? left, DidUrl? right) => !(left == right);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Method);
            hash.Add(MethodSpecificId);
            hash.Add(Path);
            hash.Add(Query);
            hash.Add(Fragment);
            hash.Add(IsRelative);

            return hash.ToHashCode();
        }
    }
}