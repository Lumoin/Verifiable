using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.OAuth;

/// <summary>
/// An authorization server issuer identifier accepted from its original spelling under
/// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 section 2</see>:
/// an HTTPS URL with no query or fragment. Equality follows RFC 8414 section 3.3 and
/// RFC 9207 section 2.4's ordinal comparison of that spelling, without URI normalization.
/// </summary>
[DebuggerDisplay("IssuerIdentifier {OriginalString,nq}")]
public sealed class IssuerIdentifier : IEquatable<IssuerIdentifier>
{
    /// <summary>The accepted issuer exactly as supplied to <see cref="Parse"/>.</summary>
    public string OriginalString { get; }


    /// <summary>
    /// The ordinal comparison key, identical to <see cref="OriginalString"/>. Scheme and host
    /// case, explicit default ports, percent triplets, paths and trailing slashes are significant.
    /// </summary>
    public string ComparisonKey => OriginalString;


    /// <summary>Constructs an issuer only after its original spelling has passed the grammar.</summary>
    /// <param name="originalString">The accepted original spelling.</param>
    private IssuerIdentifier(string originalString)
    {
        OriginalString = originalString;
    }


    /// <summary>
    /// Parses the original spelling as an absolute, well-formed HTTPS URL without a query or
    /// fragment. The library's URI reader admits Unicode; the spelling is preserved without
    /// normalization. Spelling that <see cref="Uri"/> would repair, such as a raw space,
    /// backslash or malformed percent triplet, is refused by
    /// <see cref="Uri.IsWellFormedOriginalString"/> before the scheme and component checks.
    /// </summary>
    /// <param name="issuer">The original spelling, before any URI normalization.</param>
    /// <returns>The accepted identifier, or the first failing rule in the documented order.</returns>
    public static Result<IssuerIdentifier, IssuerIdentifierFault> Parse(string? issuer)
    {
        if(string.IsNullOrEmpty(issuer))
        {
            return Result.Failure<IssuerIdentifier, IssuerIdentifierFault>(IssuerIdentifierFault.Empty);
        }

        if(!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? parsed))
        {
            return Result.Failure<IssuerIdentifier, IssuerIdentifierFault>(IssuerIdentifierFault.AbsoluteUri);
        }

        //The URI reader trims surrounding white space before it reads, and its well-formedness check
        //reads what it kept, so a spelling with a space or a control character anywhere is refused
        //here: RFC 3986 section 2 admits neither, and the accepted spelling is compared ordinally.
        if(ContainsWhiteSpaceOrControl(issuer) || !parsed.IsWellFormedOriginalString())
        {
            return Result.Failure<IssuerIdentifier, IssuerIdentifierFault>(IssuerIdentifierFault.OriginalSyntax);
        }

        if(!string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            return Result.Failure<IssuerIdentifier, IssuerIdentifierFault>(IssuerIdentifierFault.Scheme);
        }

        if(parsed.Query.Length != 0)
        {
            return Result.Failure<IssuerIdentifier, IssuerIdentifierFault>(IssuerIdentifierFault.Query);
        }

        if(parsed.Fragment.Length != 0)
        {
            return Result.Failure<IssuerIdentifier, IssuerIdentifierFault>(IssuerIdentifierFault.Fragment);
        }

        return Result.Success<IssuerIdentifier, IssuerIdentifierFault>(new IssuerIdentifier(issuer));
    }


    /// <summary>Whether the spelling holds a white-space or control character anywhere.</summary>
    /// <param name="spelling">The original spelling.</param>
    /// <returns><see langword="true"/> when one is found.</returns>
    private static bool ContainsWhiteSpaceOrControl(string spelling)
    {
        foreach(char character in spelling)
        {
            if(char.IsWhiteSpace(character) || char.IsControl(character))
            {
                return true;
            }
        }

        return false;
    }


    /// <inheritdoc/>
    public bool Equals(IssuerIdentifier? other) =>
        other is not null && string.Equals(ComparisonKey, other.ComparisonKey, StringComparison.Ordinal);


    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is IssuerIdentifier other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(ComparisonKey);


    /// <inheritdoc/>
    public override string ToString() => OriginalString;


    /// <summary>Determines whether two accepted issuers have the same comparison key.</summary>
    public static bool operator ==(IssuerIdentifier? left, IssuerIdentifier? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two accepted issuers have different comparison keys.</summary>
    public static bool operator !=(IssuerIdentifier? left, IssuerIdentifier? right) => !(left == right);
}
