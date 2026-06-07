using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// A Subject Identifier — a JSON object that identifies a principal by a set of
/// members interpreted according to its <c>format</c>, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9493">RFC 9493</see> and the
/// additional formats in OpenID Shared Signals Framework 1.0 §3.5.
/// </summary>
/// <remarks>
/// <para>
/// A Subject Identifier appears both as the top-level <c>sub_id</c> claim of a
/// Security Event Token and as the <c>subject</c> member of an individual event.
/// The <see cref="Format"/> selects which <see cref="Members"/> are required;
/// <see cref="IsValidForKnownFormat"/> checks those requirements for the formats
/// this library recognizes.
/// </para>
/// <para>
/// Factory methods construct the well-formed identifier for each format. Use
/// <see cref="FromWireObject"/> to project a parsed JSON object (a
/// <c>Dictionary&lt;string, object&gt;</c> as produced by the JSON layer) into a
/// <see cref="SubjectIdentifier"/>, and <see cref="ToWireObject"/> for the
/// reverse, which embeds the <c>format</c> member ready for serialization.
/// </para>
/// </remarks>
public sealed record SubjectIdentifier
{
    /// <summary>The value of the <c>format</c> member — see <see cref="SubjectIdentifierFormats"/>.</summary>
    public required string Format { get; init; }

    /// <summary>
    /// The members of the identifier other than <c>format</c> (for example <c>email</c>,
    /// or the <c>iss</c>/<c>sub</c> pair). Keyed by member name; values are the parsed
    /// JSON values (string, array, nested object) for that member.
    /// </summary>
    public required IReadOnlyDictionary<string, object> Members { get; init; }


    /// <summary>Creates an <c>account</c> Subject Identifier from an <c>acct</c> URI.</summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "RFC 9493 §3.2.1 carries the acct URI as an opaque JSON string member, not a System.Uri.")]
    public static SubjectIdentifier Account(string acctUri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(acctUri);

        return Single(SubjectIdentifierFormats.Account, SubjectIdentifierMemberNames.Uri, acctUri);
    }


    /// <summary>Creates an <c>email</c> Subject Identifier.</summary>
    public static SubjectIdentifier Email(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        return Single(SubjectIdentifierFormats.Email, SubjectIdentifierMemberNames.Email, email);
    }


    /// <summary>Creates an <c>iss_sub</c> Subject Identifier from an issuer and subject.</summary>
    public static SubjectIdentifier IssuerSubject(string iss, string sub)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(iss);
        ArgumentException.ThrowIfNullOrWhiteSpace(sub);

        return new SubjectIdentifier
        {
            Format = SubjectIdentifierFormats.IssuerSubject,
            Members = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [SubjectIdentifierMemberNames.Iss] = iss,
                [SubjectIdentifierMemberNames.Sub] = sub
            }
        };
    }


    /// <summary>Creates an <c>opaque</c> Subject Identifier from an opaque string id.</summary>
    public static SubjectIdentifier Opaque(string id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        return Single(SubjectIdentifierFormats.Opaque, SubjectIdentifierMemberNames.Id, id);
    }


    /// <summary>Creates a <c>phone_number</c> Subject Identifier.</summary>
    public static SubjectIdentifier PhoneNumber(string phoneNumber)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(phoneNumber);

        return Single(SubjectIdentifierFormats.PhoneNumber, SubjectIdentifierMemberNames.PhoneNumber, phoneNumber);
    }


    /// <summary>Creates a <c>did</c> Subject Identifier from a DID or DID URL.</summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "RFC 9493 §3.2.6 carries the DID URL as an opaque JSON string; a DID URL is not necessarily a System.Uri.")]
    public static SubjectIdentifier Did(string url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);

        return Single(SubjectIdentifierFormats.DecentralizedIdentifier, SubjectIdentifierMemberNames.Url, url);
    }


    /// <summary>Creates a <c>uri</c> Subject Identifier.</summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "RFC 9493 §3.2.7 carries the URI as an opaque JSON string member, not a System.Uri.")]
    public static SubjectIdentifier Uri(string uri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uri);

        return Single(SubjectIdentifierFormats.Uri, SubjectIdentifierMemberNames.Uri, uri);
    }


    /// <summary>Creates a <c>jwt_id</c> Subject Identifier identifying a JWT by issuer and <c>jti</c>.</summary>
    public static SubjectIdentifier JwtId(string iss, string jti)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(iss);
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);

        return new SubjectIdentifier
        {
            Format = SubjectIdentifierFormats.JwtId,
            Members = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [SubjectIdentifierMemberNames.Iss] = iss,
                [SubjectIdentifierMemberNames.Jti] = jti
            }
        };
    }


    /// <summary>Creates a <c>saml_assertion_id</c> Subject Identifier.</summary>
    public static SubjectIdentifier SamlAssertionId(string issuer, string assertionId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(assertionId);

        return new SubjectIdentifier
        {
            Format = SubjectIdentifierFormats.SamlAssertionId,
            Members = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [SubjectIdentifierMemberNames.Issuer] = issuer,
                [SubjectIdentifierMemberNames.AssertionId] = assertionId
            }
        };
    }


    /// <summary>
    /// Creates an <c>ip-addresses</c> Subject Identifier from one or more IP-address strings.
    /// </summary>
    public static SubjectIdentifier IpAddresses(IReadOnlyList<string> ipAddresses)
    {
        ArgumentNullException.ThrowIfNull(ipAddresses);
        if(ipAddresses.Count == 0)
        {
            throw new ArgumentException("At least one IP address is required.", nameof(ipAddresses));
        }

        //Project to List<object> to match the wire dictionary's JSON converter,
        //which writes IList<object> arrays but not the variance-incompatible IList<string>.
        var addresses = new List<object>(ipAddresses.Count);
        foreach(string address in ipAddresses)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(address);
            addresses.Add(address);
        }

        return new SubjectIdentifier
        {
            Format = SubjectIdentifierFormats.IpAddresses,
            Members = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [SubjectIdentifierMemberNames.IpAddresses] = addresses
            }
        };
    }


    /// <summary>
    /// Creates an <c>aliases</c> Subject Identifier grouping several other Subject
    /// Identifiers that all refer to the same subject.
    /// </summary>
    public static SubjectIdentifier Aliases(IReadOnlyList<SubjectIdentifier> identifiers)
    {
        ArgumentNullException.ThrowIfNull(identifiers);
        if(identifiers.Count == 0)
        {
            throw new ArgumentException("At least one identifier is required.", nameof(identifiers));
        }

        var wire = new List<object>(identifiers.Count);
        foreach(SubjectIdentifier identifier in identifiers)
        {
            ArgumentNullException.ThrowIfNull(identifier);
            wire.Add(identifier.ToWireObject());
        }

        return new SubjectIdentifier
        {
            Format = SubjectIdentifierFormats.Aliases,
            Members = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [SubjectIdentifierMemberNames.Identifiers] = wire
            }
        };
    }


    /// <summary>
    /// Creates a <c>complex</c> Subject Identifier from named Simple Subject Members
    /// (for example <c>user</c>, <c>device</c>, <c>tenant</c> — see
    /// <see cref="ComplexSubjectMemberNames"/>), each itself a Subject Identifier
    /// describing the same Subject Principal (SSF §3.3).
    /// </summary>
    public static SubjectIdentifier Complex(IReadOnlyDictionary<string, SubjectIdentifier> members)
    {
        ArgumentNullException.ThrowIfNull(members);
        if(members.Count == 0)
        {
            throw new ArgumentException("A complex subject requires at least one member.", nameof(members));
        }

        var wire = new Dictionary<string, object>(members.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, SubjectIdentifier> member in members)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(member.Key);
            ArgumentNullException.ThrowIfNull(member.Value);
            wire[member.Key] = member.Value.ToWireObject();
        }

        return new SubjectIdentifier
        {
            Format = SubjectIdentifierFormats.Complex,
            Members = wire
        };
    }


    /// <summary>
    /// Enumerates the named Simple Subject Members of a Complex Subject, each projected
    /// back into a <see cref="SubjectIdentifier"/>. Yields nothing when this identifier
    /// is not a <see cref="SubjectIdentifierFormats.Complex"/> subject or a member is not
    /// a well-formed Subject Identifier object.
    /// </summary>
    public IEnumerable<KeyValuePair<string, SubjectIdentifier>> EnumerateComplexMembers()
    {
        if(!SubjectIdentifierFormats.IsComplex(Format))
        {
            yield break;
        }

        foreach(KeyValuePair<string, object> member in Members)
        {
            if(member.Value is IReadOnlyDictionary<string, object> nested && FromWireObject(nested) is SubjectIdentifier parsed)
            {
                yield return new KeyValuePair<string, SubjectIdentifier>(member.Key, parsed);
            }
        }
    }


    /// <summary>
    /// Projects a parsed JSON object into a <see cref="SubjectIdentifier"/>. Returns
    /// <see langword="null"/> when the object has no string <c>format</c> member, which a
    /// conforming Subject Identifier MUST carry (RFC 9493 §3).
    /// </summary>
    /// <param name="obj">The parsed subject-identifier object (member name to value).</param>
    public static SubjectIdentifier? FromWireObject(IReadOnlyDictionary<string, object> obj)
    {
        ArgumentNullException.ThrowIfNull(obj);

        if(!obj.TryGetValue(SubjectIdentifierMemberNames.Format, out object? formatValue) || formatValue is not string format || string.IsNullOrEmpty(format))
        {
            return null;
        }

        var members = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> member in obj)
        {
            if(!string.Equals(member.Key, SubjectIdentifierMemberNames.Format, StringComparison.Ordinal))
            {
                members[member.Key] = member.Value;
            }
        }

        return new SubjectIdentifier
        {
            Format = SubjectIdentifierFormats.GetCanonicalizedValue(format),
            Members = members
        };
    }


    /// <summary>
    /// Produces the wire object for this identifier: a fresh dictionary containing the
    /// <c>format</c> member plus all of <see cref="Members"/>, ready for JSON serialization.
    /// </summary>
    public Dictionary<string, object> ToWireObject()
    {
        var obj = new Dictionary<string, object>(Members.Count + 1, StringComparer.Ordinal)
        {
            [SubjectIdentifierMemberNames.Format] = Format
        };

        foreach(KeyValuePair<string, object> member in Members)
        {
            obj[member.Key] = member.Value;
        }

        return obj;
    }


    /// <summary>
    /// Whether this identifier satisfies the required-member rules of its
    /// <see cref="Format"/> for the formats this library recognizes. An
    /// <em>unrecognized</em> format returns <see langword="false"/> — the caller
    /// decides whether to tolerate formats it does not understand, but this method
    /// asserts conformance only for known ones (fail-closed).
    /// </summary>
    public bool IsValidForKnownFormat()
    {
        if(SubjectIdentifierFormats.IsEmail(Format))
        {
            return HasNonEmptyString(SubjectIdentifierMemberNames.Email);
        }

        if(SubjectIdentifierFormats.IsAccount(Format) || SubjectIdentifierFormats.IsUri(Format))
        {
            return HasNonEmptyString(SubjectIdentifierMemberNames.Uri);
        }

        if(SubjectIdentifierFormats.IsIssuerSubject(Format))
        {
            return HasNonEmptyString(SubjectIdentifierMemberNames.Iss) && HasNonEmptyString(SubjectIdentifierMemberNames.Sub);
        }

        if(SubjectIdentifierFormats.IsOpaque(Format))
        {
            return HasNonEmptyString(SubjectIdentifierMemberNames.Id);
        }

        if(SubjectIdentifierFormats.IsPhoneNumber(Format))
        {
            return HasNonEmptyString(SubjectIdentifierMemberNames.PhoneNumber);
        }

        if(SubjectIdentifierFormats.IsDecentralizedIdentifier(Format))
        {
            return HasNonEmptyString(SubjectIdentifierMemberNames.Url);
        }

        if(SubjectIdentifierFormats.IsJwtId(Format))
        {
            return HasNonEmptyString(SubjectIdentifierMemberNames.Iss) && HasNonEmptyString(SubjectIdentifierMemberNames.Jti);
        }

        if(SubjectIdentifierFormats.IsSamlAssertionId(Format))
        {
            return HasNonEmptyString(SubjectIdentifierMemberNames.Issuer) && HasNonEmptyString(SubjectIdentifierMemberNames.AssertionId);
        }

        if(SubjectIdentifierFormats.IsIpAddresses(Format))
        {
            return HasNonEmptyList(SubjectIdentifierMemberNames.IpAddresses);
        }

        if(SubjectIdentifierFormats.IsAliases(Format))
        {
            return HasNonEmptyList(SubjectIdentifierMemberNames.Identifiers);
        }

        if(SubjectIdentifierFormats.IsComplex(Format))
        {
            return IsValidComplex();
        }

        return false;
    }


    //A complex subject is valid when it has at least one named member and every
    //member is itself a well-formed, known-format Subject Identifier (SSF §3.3).
    private bool IsValidComplex()
    {
        bool any = false;
        foreach(KeyValuePair<string, object> member in Members)
        {
            if(member.Value is not IReadOnlyDictionary<string, object> nested || FromWireObject(nested) is not SubjectIdentifier parsed || !parsed.IsValidForKnownFormat())
            {
                return false;
            }

            any = true;
        }

        return any;
    }


    private static SubjectIdentifier Single(string format, string memberName, string value) =>
        new()
        {
            Format = format,
            Members = new Dictionary<string, object>(StringComparer.Ordinal) { [memberName] = value }
        };


    private bool HasNonEmptyString(string memberName) =>
        Members.TryGetValue(memberName, out object? value) && value is string s && !string.IsNullOrEmpty(s);


    private bool HasNonEmptyList(string memberName) =>
        Members.TryGetValue(memberName, out object? value) && value is System.Collections.IEnumerable enumerable && HasAny(enumerable);


    private static bool HasAny(System.Collections.IEnumerable enumerable)
    {
        foreach(object? _ in enumerable)
        {
            return true;
        }

        return false;
    }
}
