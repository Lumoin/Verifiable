using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// A Subject Identifier — a JSON object that identifies a principal by a set of
/// members interpreted according to its <c>format</c>, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9493">RFC 9493</see> and the
/// additional formats in
/// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5">OpenID Shared Signals Framework 1.0 Section 3.5</see>.
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
    /// Creates a <c>saml-nameid</c> Subject Identifier from a SAML issuer and a SAML Assertion Subject
    /// &lt;NameID&gt; value, carrying the two members
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>
    /// requires and none of the optional ones.
    /// </summary>
    public static SubjectIdentifier SamlNameId(string issuer, string nameId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(nameId);

        return new SubjectIdentifier
        {
            Format = SubjectIdentifierFormats.SamlNameId,
            Members = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [SubjectIdentifierMemberNames.Issuer] = issuer,
                [SubjectIdentifierMemberNames.NameId] = nameId
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
    /// Identifiers that all refer to the same subject. The factory does not check its elements: an identifier
    /// built from an element of the <c>aliases</c> or the <c>complex</c> format is one
    /// <see cref="IsValidForKnownFormat"/> and <see cref="IsWellFormed"/> refuse.
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
    /// describing the same Subject Principal
    /// (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3">OpenID Shared Signals Framework 1.0 Section 3.3</see>).
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
    /// conforming Subject Identifier MUST carry
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>).
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
    /// <c>format</c> member, whose value is always <see cref="Format"/>, plus every entry of
    /// <see cref="Members"/> other than one named <c>format</c>, ready for JSON serialization.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see> reserves the
    /// <c>format</c> member for the name of the identifier's Identifier Format, so a <see cref="Members"/>
    /// entry of that name never reaches the wire.
    /// </summary>
    public Dictionary<string, object> ToWireObject()
    {
        var obj = new Dictionary<string, object>(Members.Count + 1, StringComparer.Ordinal)
        {
            [SubjectIdentifierMemberNames.Format] = Format
        };

        foreach(KeyValuePair<string, object> member in Members)
        {
            if(!string.Equals(member.Key, SubjectIdentifierMemberNames.Format, StringComparison.Ordinal))
            {
                obj[member.Key] = member.Value;
            }
        }

        return obj;
    }


    /// <summary>
    /// Whether this identifier satisfies the member rules of its <see cref="Format"/> for the
    /// formats this library recognizes. An <em>unrecognized</em> format returns
    /// <see langword="false"/>: the caller decides whether to tolerate formats it does not
    /// understand, but this method asserts conformance only for known ones (fail-closed).
    /// <see cref="IsWellFormed"/> reads the same rules and admits a format the catalog does not know.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST NOT contain any members prohibited or not described by its Identifier Format and
    /// MUST contain all members required by its Identifier Format." An identifier of a format of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2">RFC 9493 Section 3.2</see>, of the
    /// <see cref="SubjectIdentifierFormats.SamlNameId"/> format, or of the <c>jwt_id</c> and
    /// <c>saml_assertion_id</c> formats carries exactly the members its format describes
    /// (<see cref="HasDescribedMembers"/>): each REQUIRED member a non-empty JSON string, as
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.3">RFC 9493 Section 3.2.3</see> states
    /// for <c>iss_sub</c>, "Both the "iss" member and the "sub" member are REQUIRED and MUST NOT be null or
    /// empty.", and each OPTIONAL member of the SAML NameID format a JSON string when present
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>).
    /// A non-empty REQUIRED member of the <c>saml-nameid</c> format is this library's reading, after the
    /// pattern of RFC 9493's formats ("REQUIRED and MUST NOT be null or empty"), and no sentence of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>,
    /// which describes <c>issuer</c> and
    /// <c>nameid</c> each as "A JSON string containing" its value; the same reading holds the REQUIRED
    /// members of <c>jwt_id</c> and <c>saml_assertion_id</c> non-empty.
    /// </para>
    /// <para>
    /// The formats of
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5">OpenID Shared Signals Framework 1.0 Section 3.5</see>
    /// carry exactly their members:
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.1">Section 3.5.1</see>,
    /// "Subject Identifiers of this type MUST contain the following members:" <c>iss</c> and <c>jti</c>;
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.2">Section 3.5.2</see>,
    /// "Subject Identifiers of this format MUST contain the following members:" <c>issuer</c> and
    /// <c>assertion_id</c>; and
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.3">Section 3.5.3</see>,
    /// the one member <c>ip-addresses</c>, "The value MUST be in the format of an array of strings"
    /// (<see cref="IsValidIpAddresses"/>). An <c>aliases</c> identifier is checked by
    /// <see cref="IsValidAliases"/> and a <c>complex</c> subject of
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3">Section 3.3</see>
    /// by <see cref="IsValidComplex"/>. No identifier of any format carries a <see cref="Members"/> entry
    /// named <c>format</c>: <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>
    /// reserves that member for the name of the Identifier Format.
    /// </para>
    /// <para>
    /// This method checks the members present, their JSON types, that no member is one the format does not
    /// describe, and the reserved <c>format</c> member. It does not check the rules on a member's value; those
    /// are the caller's to enforce:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// Account, <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.1">RFC 9493 Section 3.2.1</see>:
    /// the <c>uri</c> member's value "is the "acct" URI for the subject".
    /// </description></item>
    /// <item><description>
    /// Email, <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.2">RFC 9493 Section 3.2.2</see>:
    /// the <c>email</c> member is "formatted as an "addr-spec" as defined in Section 3.4.1 of [RFC5322]", and
    /// "The value of the "email" member MUST identify a mailbox to which email may be delivered, in accordance
    /// with [RFC5321]."
    /// </description></item>
    /// <item><description>
    /// Issuer and Subject, <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.3">RFC 9493 Section 3.2.3</see>:
    /// "These members MUST follow the formats of the "iss" member and "sub" member defined by [RFC7519],
    /// respectively."
    /// </description></item>
    /// <item><description>
    /// Phone Number, <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.5">RFC 9493 Section 3.2.5</see>:
    /// the <c>phone_number</c> member holds the full telephone number "formatted according to E.164 [E164]".
    /// </description></item>
    /// <item><description>
    /// Decentralized Identifier, <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.6">RFC 9493 Section 3.2.6</see>:
    /// "The value of the "url" member MUST be a valid DID URL and MAY be a bare DID."
    /// </description></item>
    /// <item><description>
    /// URI, <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.7">RFC 9493 Section 3.2.7</see>:
    /// the format identifies a subject "using a URI as defined in [RFC3986]", and the <c>uri</c> member's
    /// value "is a URI for the subject being identified".
    /// </description></item>
    /// <item><description>
    /// JWT ID, <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.1">OpenID Shared Signals Framework 1.0 Section 3.5.1</see>:
    /// <c>iss</c> is "The "iss" (issuer) claim of the JWT being identified" and <c>jti</c> is "The "jti" (JWT
    /// token ID) claim of the JWT being identified".
    /// </description></item>
    /// <item><description>
    /// SAML Assertion ID, <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.2">OpenID Shared Signals Framework 1.0 Section 3.5.2</see>:
    /// <c>issuer</c> is "The "Issuer" value of the SAML assertion being identified" and <c>assertion_id</c>
    /// is "The "ID" value of the SAML assertion being identified".
    /// </description></item>
    /// <item><description>
    /// IP Addresses, <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.3">OpenID Shared Signals Framework 1.0 Section 3.5.3</see>:
    /// each string of the array is one "which represents the [RFC4001] string representation of an IP
    /// address."
    /// </description></item>
    /// </list>
    /// </remarks>
    public bool IsValidForKnownFormat() => CheckKnownFormat() is true;


    /// <summary>
    /// Whether this identifier is well formed: its <see cref="Format"/> names a format (it is not blank) and,
    /// for a format the catalog knows (<see cref="SubjectIdentifierFormats.IsKnown"/>), the member rules
    /// <see cref="IsValidForKnownFormat"/> describes hold. An identifier of a format the catalog does not know
    /// is well formed and carried opaque.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST conform to a specific Identifier Format and MUST contain a "format" member whose value
    /// is the name of that Identifier Format." and "Every Identifier Format MUST have a unique name registered
    /// in the IANA "Security Event Identifier Formats" registry established in Section 8.1 or a
    /// Collision-Resistant Name as defined in [RFC7519]." A blank value names no format; a name the catalog
    /// does not know may be a Collision-Resistant Name, whose members this library cannot judge.
    /// </para>
    /// <para>
    /// A writer of an identifier reads it to refuse one that is not well formed before it reaches the wire; a
    /// reader reads it to tell a malformed claim from a usable one.
    /// </para>
    /// <para>
    /// The answer is the one of <see cref="CheckKnownFormat"/>, which holds the blank test beside the member
    /// rules, so an <c>aliases</c> element or a <c>complex</c> member whose format is blank is refused by the
    /// same rule as an identifier whose own format is.
    /// </para>
    /// </remarks>
    public bool IsWellFormed() => CheckKnownFormat() is not false;


    /// <summary>
    /// Checks this identifier against the member rules of its <see cref="Format"/>, as
    /// <see cref="IsValidForKnownFormat"/> describes them: <see langword="true"/> or
    /// <see langword="false"/> for a format the catalog knows (<see cref="SubjectIdentifierFormats.IsKnown"/>),
    /// <see langword="false"/> for an identifier whose <see cref="Members"/> hold an entry named
    /// <c>format</c> or whose <see cref="Format"/> is blank, and <see langword="null"/> for a format the catalog
    /// does not know. A blank value names no format
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: the value of the
    /// <c>format</c> member "is the name of that Identifier Format"), so it is refused before the catalog is asked,
    /// at every depth this check reaches: <see cref="IsWellFormed"/>, <see cref="IsValidAliases"/> and
    /// <see cref="IsValidComplex"/> read the same arm. The three-valued answer lets
    /// <see cref="IsValidAliases"/> and <see cref="IsValidComplex"/> admit a member of an unknown format while
    /// <see cref="IsValidForKnownFormat"/> refuses it. The catalog is asked before the rules, so the final arm is
    /// reached only by a name the catalog knows that has no rule below, and it answers
    /// <see langword="false"/>: such a name fails closed.
    /// </summary>
    private bool? CheckKnownFormat() => Format switch
    {
        _ when Members.ContainsKey(SubjectIdentifierMemberNames.Format) => false,
        _ when string.IsNullOrWhiteSpace(Format) => false,
        _ when !SubjectIdentifierFormats.IsKnown(Format) => null,
        _ when SubjectIdentifierFormats.IsEmail(Format) => HasDescribedMembers([SubjectIdentifierMemberNames.Email], []),
        _ when SubjectIdentifierFormats.IsAccount(Format) || SubjectIdentifierFormats.IsUri(Format) => HasDescribedMembers([SubjectIdentifierMemberNames.Uri], []),
        _ when SubjectIdentifierFormats.IsIssuerSubject(Format) => HasDescribedMembers([SubjectIdentifierMemberNames.Iss, SubjectIdentifierMemberNames.Sub], []),
        _ when SubjectIdentifierFormats.IsOpaque(Format) => HasDescribedMembers([SubjectIdentifierMemberNames.Id], []),
        _ when SubjectIdentifierFormats.IsPhoneNumber(Format) => HasDescribedMembers([SubjectIdentifierMemberNames.PhoneNumber], []),
        _ when SubjectIdentifierFormats.IsDecentralizedIdentifier(Format) => HasDescribedMembers([SubjectIdentifierMemberNames.Url], []),
        _ when SubjectIdentifierFormats.IsAliases(Format) => IsValidAliases(),
        _ when SubjectIdentifierFormats.IsSamlNameId(Format) => HasDescribedMembers(
            [SubjectIdentifierMemberNames.Issuer, SubjectIdentifierMemberNames.NameId],
            [SubjectIdentifierMemberNames.NameIdFormat, SubjectIdentifierMemberNames.NameQualifier, SubjectIdentifierMemberNames.SpNameQualifier, SubjectIdentifierMemberNames.SpProvidedId]),
        _ when SubjectIdentifierFormats.IsJwtId(Format) => HasDescribedMembers([SubjectIdentifierMemberNames.Iss, SubjectIdentifierMemberNames.Jti], []),
        _ when SubjectIdentifierFormats.IsSamlAssertionId(Format) => HasDescribedMembers([SubjectIdentifierMemberNames.Issuer, SubjectIdentifierMemberNames.AssertionId], []),
        _ when SubjectIdentifierFormats.IsIpAddresses(Format) => IsValidIpAddresses(),
        _ when SubjectIdentifierFormats.IsComplex(Format) => IsValidComplex(),
        _ => false
    };


    /// <summary>
    /// Whether <see cref="Members"/> holds every name of <paramref name="required"/> as a non-empty JSON
    /// string and no other entry than a name of <paramref name="optional"/> whose value is a JSON string:
    /// the member rule of <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>
    /// for a format that describes exactly these members.
    /// </summary>
    /// <param name="required">The names of the members the format requires.</param>
    /// <param name="optional">The names of the members the format describes as optional.</param>
    private bool HasDescribedMembers(ReadOnlySpan<string> required, ReadOnlySpan<string> optional)
    {
        foreach(string name in required)
        {
            if(!HasNonEmptyString(name))
            {
                return false;
            }
        }

        foreach(KeyValuePair<string, object> member in Members)
        {
            bool isDescribed = required.Contains(member.Key) || (optional.Contains(member.Key) && member.Value is string);
            if(!isDescribed)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Whether this <c>aliases</c> identifier carries exactly its <c>identifiers</c> member as a JSON array
    /// of one or more Subject Identifiers, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see>: every
    /// element is a JSON object whose <c>format</c> member names a format, a string that is not blank, white
    /// space included (a Subject Identifier,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>;
    /// <see cref="CheckKnownFormat"/> refuses a blank one at every depth), no element is in the Aliases
    /// Identifier Format (aliases identifiers are not nested), no element is a <c>complex</c> subject, and an
    /// element of a format this library recognizes satisfies that format. An element of a format this library
    /// does not recognize is admitted, since
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see> also lets a
    /// Collision-Resistant Name name an Identifier Format. Exact duplicates are admitted:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">Section 3.2.8</see>'s "SHOULD NOT
    /// contain exact duplicates" binds the party that writes the identifier, and a reader loses nothing by a
    /// repeated alias.
    /// <para>
    /// A <c>complex</c> element is refused because
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see> makes the
    /// array's elements Subject Identifiers ("a JSON array containing one or more Subject Identifiers"),
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.2">OpenID Shared Signals Framework 1.0 Section 3.2</see>
    /// makes the value of a simple subject a Subject Identifier, and
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.1.4">Section 3.1.4</see>
    /// names the two kinds of value apart ("The value of a Subject Member MAY be a "simple subject" or a
    /// "complex subject"."): a complex subject is not a Subject Identifier an <c>aliases</c> array holds. The
    /// reading is this library's; no sentence of either specification states the refusal. The reading
    /// concerns what an <c>aliases</c> array holds and nothing else: an identifier whose own format is
    /// <c>complex</c> is the Shared Signals shape the catalog carries, held to its members by
    /// <see cref="IsValidComplex"/>. With the refusal the check ends: a member of a complex subject is a
    /// simple subject or an <c>aliases</c> identifier, and an element of an <c>aliases</c> identifier is
    /// neither <c>aliases</c> nor <c>complex</c>.
    /// </para>
    /// </summary>
    private bool IsValidAliases()
    {
        if(Members.Count != 1
            || !Members.TryGetValue(SubjectIdentifierMemberNames.Identifiers, out object? value)
            || value is string
            || value is not System.Collections.IEnumerable elements)
        {
            return false;
        }

        bool isAny = false;
        foreach(object? element in elements)
        {
            if(element is not IReadOnlyDictionary<string, object> nested
                || FromWireObject(nested) is not SubjectIdentifier alias
                || SubjectIdentifierFormats.IsAliases(alias.Format)
                || SubjectIdentifierFormats.IsComplex(alias.Format)
                || alias.CheckKnownFormat() is false)
            {
                return false;
            }

            isAny = true;
        }

        return isAny;
    }


    /// <summary>
    /// Whether this <c>ip-addresses</c> identifier carries exactly its <c>ip-addresses</c> member as a JSON
    /// array of one or more strings, each non-empty, per
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.3">OpenID Shared Signals Framework 1.0 Section 3.5.3</see>:
    /// "The value MUST be in the format of an array of strings". A JSON string in the place of the array is
    /// refused: a string is a sequence of characters to the runtime and not a JSON array. The textual form of
    /// each address is not checked (<see cref="IsValidForKnownFormat"/> names that rule).
    /// </summary>
    private bool IsValidIpAddresses()
    {
        if(Members.Count != 1
            || !Members.TryGetValue(SubjectIdentifierMemberNames.IpAddresses, out object? value)
            || value is string
            || value is not System.Collections.IEnumerable elements)
        {
            return false;
        }

        bool isAny = false;
        foreach(object? element in elements)
        {
            if(element is not string address || address.Length == 0)
            {
                return false;
            }

            isAny = true;
        }

        return isAny;
    }


    /// <summary>
    /// Whether this <c>complex</c> identifier has at least one member and every member is a Subject
    /// Identifier that is a simple subject, per
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3">OpenID Shared Signals Framework 1.0 Section 3.3</see>:
    /// "A Complex Subject Member has a name and a value that is a JSON [RFC7159] object that has a format
    /// field, and one or more Simple Subject Members." Every member is a JSON object that
    /// <see cref="FromWireObject"/> reads, whose <c>format</c> member names a format, a string that is not
    /// blank, white space included (<see cref="CheckKnownFormat"/>); a member of a format the catalog knows
    /// satisfies that format; a
    /// member of a format the catalog does not know is admitted, as an <c>aliases</c> element is, since
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.4">Section 3.4</see>
    /// admits "A proprietary subject identifier format that is agreed to between parties."; and no member is
    /// itself <c>complex</c>, since
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.2">Section 3.2</see>
    /// describes the value of a Simple Subject Member as a Subject Identifier of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see> and
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.1.4">Section 3.1.4</see>
    /// names the two kinds of value apart: "The value of a Subject Member MAY be a "simple subject" or a
    /// "complex subject"." A member of the <c>aliases</c> format is admitted as a simple subject, and it holds
    /// no complex subject (<see cref="IsValidAliases"/>).
    /// </summary>
    private bool IsValidComplex()
    {
        bool isAny = false;
        foreach(KeyValuePair<string, object> member in Members)
        {
            if(member.Value is not IReadOnlyDictionary<string, object> nested
                || FromWireObject(nested) is not SubjectIdentifier parsed
                || SubjectIdentifierFormats.IsComplex(parsed.Format)
                || parsed.CheckKnownFormat() is false)
            {
                return false;
            }

            isAny = true;
        }

        return isAny;
    }


    /// <summary>Builds an identifier of <paramref name="format"/> carrying the one member <paramref name="memberName"/>.</summary>
    private static SubjectIdentifier Single(string format, string memberName, string value) =>
        new()
        {
            Format = format,
            Members = new Dictionary<string, object>(StringComparer.Ordinal) { [memberName] = value }
        };


    /// <summary>Whether <see cref="Members"/> holds <paramref name="memberName"/> as a non-empty JSON string.</summary>
    private bool HasNonEmptyString(string memberName) =>
        Members.TryGetValue(memberName, out object? value) && value is string s && !string.IsNullOrEmpty(s);
}
