using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Dcql;

/// <summary>
/// The identifier of a DCQL Credential Query — the <c>id</c> field of an entry in the DCQL
/// query's <c>credentials</c> list, validated per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
/// OID4VP 1.0 §6.1</see>: "id: REQUIRED. A string identifying the Credential in the response
/// and, if provided, the constraints in credential_sets. The value MUST be a non-empty string
/// consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the
/// Authorization Request, the same id MUST NOT be present more than once."
/// </summary>
/// <remarks>
/// The same identifier keys the matched presentation array in the <c>vp_token</c> response per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">
/// OID4VP 1.0 §8.1</see>. It is minted once a candidate string is known to satisfy §6.1's
/// character class and threaded through every carrier that keys per-query data — the constructor
/// enforces §6.1 for a caller that already knows its input is valid, while <see cref="TryCreate"/>
/// answers <see langword="false"/> for wire input that might not be.
/// </remarks>
[DebuggerDisplay("Value={Value}")]
public sealed record CredentialQueryId
{
    /// <summary>The validated identifier string, unique to a query within one Authorization Request.</summary>
    public string Value { get; }

    /// <summary>
    /// Constructs a <see cref="CredentialQueryId"/> from a candidate value already known to be
    /// non-empty and composed only of §6.1's allowed characters — a caller-defect boundary, not a
    /// wire boundary; wire input goes through <see cref="TryCreate"/> instead.
    /// </summary>
    /// <param name="value">The candidate identifier value.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="value"/> is empty or contains a character outside <c>[A-Za-z0-9_-]</c>, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OID4VP 1.0 §6.1</see>.
    /// </exception>
    public CredentialQueryId(string value)
    {
        if(!IsValidValue(value))
        {
            throw new ArgumentException(
                "The value MUST be a non-empty string consisting of alphanumeric, underscore (_), " +
                "or hyphen (-) characters, per OID4VP 1.0 §6.1.",
                nameof(value));
        }

        Value = value;
    }

    /// <summary>
    /// Attempts to construct a <see cref="CredentialQueryId"/> from wire input, answering
    /// <see langword="false"/> rather than throwing when the candidate does not satisfy §6.1.
    /// </summary>
    /// <param name="value">The candidate identifier value, possibly <see langword="null"/>.</param>
    /// <param name="id">The constructed identifier when the candidate is valid; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> satisfies §6.1; otherwise <see langword="false"/>.</returns>
    public static bool TryCreate(string? value, [NotNullWhen(true)] out CredentialQueryId? id)
    {
        if(!IsValidValue(value))
        {
            id = null;

            return false;
        }

        id = new CredentialQueryId(value);

        return true;
    }

    /// <summary>Reports the bare identifier value, so it round-trips into wire text and log/error messages unchanged.</summary>
    /// <returns><see cref="Value"/>.</returns>
    public override string ToString() => Value;

    /// <summary>Checks a candidate value against §6.1's non-empty, alphanumeric/underscore/hyphen character class.</summary>
    /// <param name="value">The candidate identifier value.</param>
    /// <returns><see langword="true"/> when every character is allowed and the value is non-empty; otherwise <see langword="false"/>.</returns>
    private static bool IsValidValue([NotNullWhen(true)] string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        foreach(char character in value)
        {
            bool isAllowed = (character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9')
                || character == '_'
                || character == '-';

            if(!isAllowed)
            {
                return false;
            }
        }

        return true;
    }
}
