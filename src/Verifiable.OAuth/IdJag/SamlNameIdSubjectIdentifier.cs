using System.Diagnostics;

using Verifiable.Core.SecurityEvents;
using Verifiable.JCose;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The member names of a SAML NameID Subject Identifier (the <c>saml-nameid</c> form of the
/// <c>sub_id</c> claim) per draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §3.2.1 and
/// <see href="https://www.rfc-editor.org/rfc/rfc9493">RFC 9493</see>. These are the JSON object member
/// names inside the <see cref="WellKnownJwtClaimNames.SubId"/> claim, each the spelling of
/// <see cref="SubjectIdentifierMemberNames"/> or <see cref="SubjectIdentifierFormats"/> so that every name
/// is spelled once.
/// </summary>
public static class SamlNameIdMemberNames
{
    /// <summary>
    /// The <c>format</c> member: names the Subject Identifier Format
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>);
    /// <see cref="SubjectIdentifierMemberNames.Format"/>.
    /// </summary>
    public static string Format => SubjectIdentifierMemberNames.Format;

    /// <summary>
    /// The Subject Identifier Format value identifying a SAML NameID identifier
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">Section 3.2.1</see>);
    /// <see cref="SubjectIdentifierFormats.SamlNameId"/>.
    /// </summary>
    public static string SamlNameIdFormat => SubjectIdentifierFormats.SamlNameId;

    /// <summary>
    /// The <c>issuer</c> member: the SAML issuer entity identifier
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">Section 3.2.1</see> /
    /// <see href="https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf">SAML 2.0 Core</see> Section 8.3.6);
    /// <see cref="SubjectIdentifierMemberNames.Issuer"/>.
    /// </summary>
    public static string Issuer => SubjectIdentifierMemberNames.Issuer;

    /// <summary>
    /// The <c>nameid</c> member: the SAML Assertion Subject &lt;NameID&gt; value
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">Section 3.2.1</see>);
    /// <see cref="SubjectIdentifierMemberNames.NameId"/>.
    /// </summary>
    public static string NameId => SubjectIdentifierMemberNames.NameId;

    /// <summary>
    /// The <c>nameid_format</c> member: the Format attribute of the &lt;NameID&gt;
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">Section 3.2.1</see>,
    /// OPTIONAL); <see cref="SubjectIdentifierMemberNames.NameIdFormat"/>.
    /// </summary>
    public static string NameIdFormat => SubjectIdentifierMemberNames.NameIdFormat;

    /// <summary>
    /// The <c>name_qualifier</c> member: the NameQualifier attribute of the &lt;NameID&gt;
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">Section 3.2.1</see>,
    /// OPTIONAL); <see cref="SubjectIdentifierMemberNames.NameQualifier"/>.
    /// </summary>
    public static string NameQualifier => SubjectIdentifierMemberNames.NameQualifier;

    /// <summary>
    /// The <c>sp_name_qualifier</c> member: the SPNameQualifier attribute of the &lt;NameID&gt;
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">Section 3.2.1</see>,
    /// OPTIONAL); <see cref="SubjectIdentifierMemberNames.SpNameQualifier"/>.
    /// </summary>
    public static string SpNameQualifier => SubjectIdentifierMemberNames.SpNameQualifier;

    /// <summary>
    /// The <c>sp_provided_id</c> member: the SPProvidedID attribute of the &lt;NameID&gt;
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">Section 3.2.1</see>,
    /// OPTIONAL); <see cref="SubjectIdentifierMemberNames.SpProvidedId"/>.
    /// </summary>
    public static string SpProvidedId => SubjectIdentifierMemberNames.SpProvidedId;
}


/// <summary>
/// A SAML NameID Subject Identifier — the <c>saml-nameid</c> form of the <c>sub_id</c> claim
/// (draft-ietf-oauth-identity-assertion-authz-grant-04 §3.2.1, <see href="https://www.rfc-editor.org/rfc/rfc9493">RFC 9493</see>)
/// — identifying the End-User by a SAML 2.0 Assertion Subject &lt;NameID&gt; within the context of a
/// SAML issuer. It carries the same subject as the ID-JAG <c>sub</c> claim, but in the SAML subject
/// namespace a Resource Authorization Server uses for SSO.
/// </summary>
/// <remarks>
/// Per §9.5 the <see cref="Issuer"/> (the SAML issuer) MUST NOT be used to establish trust in the ID-JAG
/// issuer — the grant is trusted via its own <c>iss</c>, signature, audience, expiry and client binding
/// first; only then MAY a Resource Authorization Server use this identifier for subject resolution, and
/// only when the validated ID-JAG issuer is explicitly associated with this SAML issuer by local
/// configuration or trusted federation metadata. Per §3.2.2 a Resource Authorization Server MUST compare
/// every member that is part of its subject-resolution identifier set for that SAML issuer, and MUST NOT
/// resolve by <see cref="NameId"/> alone unless local policy defines it as the sole identifier.
/// <para>
/// The NameID and its qualifiers can identify a person, so the debugger display and <see cref="ToString"/>
/// show the SAML issuer and which optional members are present only.
/// </para>
/// </remarks>
[DebuggerDisplay("SamlNameIdSubjectIdentifier(Issuer={Issuer}, HasNameIdFormat={NameIdFormat != null}, HasNameQualifier={NameQualifier != null}, HasSpNameQualifier={SpNameQualifier != null}, HasSpProvidedId={SpProvidedId != null})")]
public sealed record SamlNameIdSubjectIdentifier
{
    /// <summary>The SAML issuer entity identifier for the assertion or configured mapping (§3.2.1, REQUIRED).</summary>
    public required string Issuer { get; init; }

    /// <summary>The SAML Assertion Subject &lt;NameID&gt; value (§3.2.1, REQUIRED).</summary>
    public required string NameId { get; init; }

    /// <summary>The Format attribute of the &lt;NameID&gt; (§3.2.1, OPTIONAL); <see langword="null"/> when absent.</summary>
    public string? NameIdFormat { get; init; }

    /// <summary>The NameQualifier attribute of the &lt;NameID&gt; (§3.2.1, OPTIONAL); <see langword="null"/> when absent.</summary>
    public string? NameQualifier { get; init; }

    /// <summary>
    /// The SPNameQualifier attribute of the &lt;NameID&gt; (§3.2.1, OPTIONAL); <see langword="null"/> when
    /// absent. When the NameID is scoped to a Service Provider this value is part of the subject namespace
    /// (§3.2.2).
    /// </summary>
    public string? SpNameQualifier { get; init; }

    /// <summary>The SPProvidedID attribute of the &lt;NameID&gt; (§3.2.1, OPTIONAL); <see langword="null"/> when absent.</summary>
    public string? SpProvidedId { get; init; }


    /// <summary>
    /// Renders this identifier as the <c>sub_id</c> claim object — <c>format</c> = <c>saml-nameid</c>, the
    /// REQUIRED <c>issuer</c> and <c>nameid</c>, and each optional member included exactly when it is
    /// present
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>):
    /// the <see cref="SubjectIdentifier.ToWireObject"/> of <see cref="ToSubjectIdentifier"/>.
    /// The runtime value is a <see cref="Dictionary{TKey, TValue}"/> the JWT payload serialiser emits as a
    /// nested JSON object.
    /// </summary>
    /// <returns>The claim object for the <c>sub_id</c> claim.</returns>
    public IReadOnlyDictionary<string, object> ToClaimObject() => ToSubjectIdentifier().ToWireObject();


    /// <summary>
    /// Renders the SAML issuer and which optional members are present, in the words of the debugger display,
    /// and neither <see cref="NameId"/> nor the value of any optional member.
    /// </summary>
    /// <remarks>
    /// A record's generated text prints every property, and the NameID and its qualifiers can identify a
    /// person; an identifier that reaches a log, a trace or an exception message through its text carries none
    /// of those values. The rule is this library's.
    /// </remarks>
    /// <returns>
    /// The text <c>SamlNameIdSubjectIdentifier(Issuer=..., HasNameIdFormat=..., HasNameQualifier=...,
    /// HasSpNameQualifier=..., HasSpProvidedId=...)</c>.
    /// </returns>
    public override string ToString() =>
        $"SamlNameIdSubjectIdentifier(Issuer={Issuer}, HasNameIdFormat={NameIdFormat is not null}, HasNameQualifier={NameQualifier is not null}, HasSpNameQualifier={SpNameQualifier is not null}, HasSpProvidedId={SpProvidedId is not null})";


    /// <summary>
    /// Projects this identifier to a Subject Identifier of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>, a
    /// <see cref="SubjectIdentifier"/> of the
    /// <see cref="SubjectIdentifierFormats.SamlNameId"/> format: the REQUIRED <c>issuer</c> and
    /// <c>nameid</c> members and each optional member exactly when it is present, as
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>
    /// states: "Each optional field MUST be included exactly when the corresponding attribute is present on
    /// that &lt;NameID&gt; or in the configured mapping." <see cref="ToClaimObject"/> renders this
    /// projection's wire object.
    /// </summary>
    /// <returns>The Subject Identifier.</returns>
    public SubjectIdentifier ToSubjectIdentifier()
    {
        Dictionary<string, object> members = new(StringComparer.Ordinal)
        {
            [SamlNameIdMemberNames.Issuer] = Issuer,
            [SamlNameIdMemberNames.NameId] = NameId
        };

        if(NameIdFormat is not null)
        {
            members[SamlNameIdMemberNames.NameIdFormat] = NameIdFormat;
        }

        if(NameQualifier is not null)
        {
            members[SamlNameIdMemberNames.NameQualifier] = NameQualifier;
        }

        if(SpNameQualifier is not null)
        {
            members[SamlNameIdMemberNames.SpNameQualifier] = SpNameQualifier;
        }

        if(SpProvidedId is not null)
        {
            members[SamlNameIdMemberNames.SpProvidedId] = SpProvidedId;
        }

        return new SubjectIdentifier
        {
            Format = SubjectIdentifierFormats.SamlNameId,
            Members = members
        };
    }


    /// <summary>
    /// Reads a <see cref="SamlNameIdSubjectIdentifier"/> from a Subject Identifier of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>, a
    /// <see cref="SubjectIdentifier"/> whose <see cref="SubjectIdentifier.Format"/> is
    /// <see cref="SubjectIdentifierFormats.SamlNameId"/> and which is valid for that format
    /// (<see cref="SubjectIdentifier.IsValidForKnownFormat"/>): the REQUIRED <c>issuer</c> and <c>nameid</c>
    /// non-empty JSON strings, each optional member a JSON string when present, and no other member
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>). Any other
    /// identifier yields <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// A non-empty <c>issuer</c> and <c>nameid</c> is this library's reading, after the pattern of the formats
    /// of <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2">RFC 9493 Section 3.2</see>, each of
    /// which says of its required members that they are "REQUIRED and MUST NOT be null or empty", and no
    /// sentence of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">Section 3.2.1</see>,
    /// which describes each of the two as "A JSON string containing" its value.
    /// </remarks>
    /// <param name="identifier">The Subject Identifier to read.</param>
    /// <param name="samlIdentifier">The SAML NameID identifier on success; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="identifier"/> is a valid SAML NameID identifier.</returns>
    public static bool TryFrom(SubjectIdentifier identifier, out SamlNameIdSubjectIdentifier? samlIdentifier)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        samlIdentifier = null;

        if(!SubjectIdentifierFormats.IsSamlNameId(identifier.Format)
            || !identifier.IsValidForKnownFormat()
            || identifier.Members[SamlNameIdMemberNames.Issuer] is not string issuer
            || identifier.Members[SamlNameIdMemberNames.NameId] is not string nameId)
        {
            return false;
        }

        samlIdentifier = new SamlNameIdSubjectIdentifier
        {
            Issuer = issuer,
            NameId = nameId,
            NameIdFormat = ReadOptionalMember(identifier, SamlNameIdMemberNames.NameIdFormat),
            NameQualifier = ReadOptionalMember(identifier, SamlNameIdMemberNames.NameQualifier),
            SpNameQualifier = ReadOptionalMember(identifier, SamlNameIdMemberNames.SpNameQualifier),
            SpProvidedId = ReadOptionalMember(identifier, SamlNameIdMemberNames.SpProvidedId)
        };

        return true;
    }


    /// <summary>
    /// Parses a decoded <c>sub_id</c> claim value into a <see cref="SamlNameIdSubjectIdentifier"/> iff it
    /// is a SAML NameID Subject Identifier valid for its format: the JSON object is projected by
    /// <see cref="SubjectIdentifier.FromWireObject"/> and read by <see cref="TryFrom"/>. A value that is
    /// absent, not an object, of a different Subject Identifier Format, or not valid for the
    /// <c>saml-nameid</c> format
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">Section 3.2.1</see>)
    /// yields <see langword="false"/>, and the Resource Authorization Server applies its
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>
    /// policy for a malformed or unsupported <c>sub_id</c>. Parsing never derives trust from the identifier
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">Section 9.5</see>).
    /// </summary>
    /// <param name="claimValue">
    /// The decoded <c>sub_id</c> claim value, in either the read-only or the mutable dictionary shape a JWT
    /// payload parser may produce.
    /// </param>
    /// <param name="identifier">The parsed identifier on success; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when a well-formed SAML NameID identifier was parsed.</returns>
    public static bool TryParse(object? claimValue, out SamlNameIdSubjectIdentifier? identifier)
    {
        identifier = null;
        IReadOnlyDictionary<string, object>? claimObject = IdJagAssertionValidation.AsClaimObject(claimValue);

        return claimObject is not null
            && SubjectIdentifier.FromWireObject(claimObject) is SubjectIdentifier subjectIdentifier
            && TryFrom(subjectIdentifier, out identifier);
    }


    /// <summary>
    /// Reads the optional member <paramref name="memberName"/> of a SAML NameID Subject Identifier already
    /// valid for its format, where a present optional member is a JSON string; <see langword="null"/> when
    /// the member is absent.
    /// </summary>
    private static string? ReadOptionalMember(SubjectIdentifier identifier, string memberName) =>
        identifier.Members.TryGetValue(memberName, out object? value) ? value as string : null;
}
