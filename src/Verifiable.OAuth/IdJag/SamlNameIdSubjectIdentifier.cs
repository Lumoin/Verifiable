using System.Diagnostics;

using Verifiable.JCose;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The member names of a SAML NameID Subject Identifier (the <c>saml-nameid</c> form of the
/// <c>sub_id</c> claim) per draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §3.2.1 and
/// <see href="https://www.rfc-editor.org/rfc/rfc9493">RFC 9493</see>. These are the JSON object member
/// names inside the <see cref="WellKnownJwtClaimNames.SubId"/> claim.
/// </summary>
public static class SamlNameIdMemberNames
{
    /// <summary>The <c>format</c> member — names the Subject Identifier Format (RFC 9493).</summary>
    public static readonly string Format = "format";

    /// <summary>The Subject Identifier Format value identifying a SAML NameID identifier (§3.2.1).</summary>
    public static readonly string SamlNameIdFormat = "saml-nameid";

    /// <summary>The <c>issuer</c> member — the SAML issuer entity identifier (§3.2.1 / SAML §8.3.6).</summary>
    public static readonly string Issuer = "issuer";

    /// <summary>The <c>nameid</c> member — the SAML Assertion Subject &lt;NameID&gt; value (§3.2.1).</summary>
    public static readonly string NameId = "nameid";

    /// <summary>The <c>nameid_format</c> member — the Format attribute of the &lt;NameID&gt; (§3.2.1, OPTIONAL).</summary>
    public static readonly string NameIdFormat = "nameid_format";

    /// <summary>The <c>name_qualifier</c> member — the NameQualifier attribute of the &lt;NameID&gt; (§3.2.1, OPTIONAL).</summary>
    public static readonly string NameQualifier = "name_qualifier";

    /// <summary>The <c>sp_name_qualifier</c> member — the SPNameQualifier attribute of the &lt;NameID&gt; (§3.2.1, OPTIONAL).</summary>
    public static readonly string SpNameQualifier = "sp_name_qualifier";

    /// <summary>The <c>sp_provided_id</c> member — the SPProvidedID attribute of the &lt;NameID&gt; (§3.2.1, OPTIONAL).</summary>
    public static readonly string SpProvidedId = "sp_provided_id";
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
/// </remarks>
[DebuggerDisplay("SamlNameIdSubjectIdentifier Issuer={Issuer}, NameId={NameId}")]
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
    /// present (§3.2.2). The runtime value is a <see cref="Dictionary{TKey, TValue}"/> the JWT payload
    /// serialiser emits as a nested JSON object.
    /// </summary>
    /// <returns>The claim object for the <c>sub_id</c> claim.</returns>
    public IReadOnlyDictionary<string, object> ToClaimObject()
    {
        Dictionary<string, object> claim = new(StringComparer.Ordinal)
        {
            [SamlNameIdMemberNames.Format] = SamlNameIdMemberNames.SamlNameIdFormat,
            [SamlNameIdMemberNames.Issuer] = Issuer,
            [SamlNameIdMemberNames.NameId] = NameId
        };

        if(NameIdFormat is not null)
        {
            claim[SamlNameIdMemberNames.NameIdFormat] = NameIdFormat;
        }

        if(NameQualifier is not null)
        {
            claim[SamlNameIdMemberNames.NameQualifier] = NameQualifier;
        }

        if(SpNameQualifier is not null)
        {
            claim[SamlNameIdMemberNames.SpNameQualifier] = SpNameQualifier;
        }

        if(SpProvidedId is not null)
        {
            claim[SamlNameIdMemberNames.SpProvidedId] = SpProvidedId;
        }

        return claim;
    }


    /// <summary>
    /// Parses a decoded <c>sub_id</c> claim value into a <see cref="SamlNameIdSubjectIdentifier"/> iff it
    /// is a well-formed SAML NameID Subject Identifier — a JSON object whose <c>format</c> is
    /// <c>saml-nameid</c> with non-empty <c>issuer</c> and <c>nameid</c> members (§3.2.1). A value that is
    /// absent, not an object, of a different Subject Identifier Format, or missing a REQUIRED member
    /// yields <see langword="false"/> — the Resource Authorization Server treats that as "no usable SAML
    /// NameID" and applies its §3.2.2 policy. Parsing never derives trust from the identifier (§9.5).
    /// </summary>
    /// <param name="claimValue">The decoded <c>sub_id</c> claim value.</param>
    /// <param name="identifier">The parsed identifier on success; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when a well-formed SAML NameID identifier was parsed.</returns>
    public static bool TryParse(object? claimValue, out SamlNameIdSubjectIdentifier? identifier)
    {
        identifier = null;

        //§3.2.1: format MUST be saml-nameid; a different (or absent) format is not this identifier type.
        if(!TryReadMember(claimValue, SamlNameIdMemberNames.Format, out string? format)
            || !string.Equals(format, SamlNameIdMemberNames.SamlNameIdFormat, StringComparison.Ordinal))
        {
            return false;
        }

        //§3.2.1: issuer and nameid are REQUIRED; a malformed identifier missing either is rejected.
        if(!TryReadMember(claimValue, SamlNameIdMemberNames.Issuer, out string? issuer)
            || string.IsNullOrEmpty(issuer))
        {
            return false;
        }

        if(!TryReadMember(claimValue, SamlNameIdMemberNames.NameId, out string? nameId)
            || string.IsNullOrEmpty(nameId))
        {
            return false;
        }

        //§3.2.1: each optional member is surfaced exactly when present (a null member is simply absent).
        TryReadMember(claimValue, SamlNameIdMemberNames.NameIdFormat, out string? nameIdFormat);
        TryReadMember(claimValue, SamlNameIdMemberNames.NameQualifier, out string? nameQualifier);
        TryReadMember(claimValue, SamlNameIdMemberNames.SpNameQualifier, out string? spNameQualifier);
        TryReadMember(claimValue, SamlNameIdMemberNames.SpProvidedId, out string? spProvidedId);

        identifier = new SamlNameIdSubjectIdentifier
        {
            Issuer = issuer,
            NameId = nameId,
            NameIdFormat = nameIdFormat,
            NameQualifier = nameQualifier,
            SpNameQualifier = spNameQualifier,
            SpProvidedId = spProvidedId
        };

        return true;
    }


    /// <summary>
    /// Reads a string member from a decoded JSON object value, accepting either the read-only or the
    /// mutable dictionary shape a JWT payload parser may produce.
    /// </summary>
    private static bool TryReadMember(object? claimValue, string member, out string? value)
    {
        (bool found, value) = claimValue switch
        {
            IReadOnlyDictionary<string, object> readOnly when readOnly.TryGetValue(member, out object? raw) && raw is string s => (true, s),
            IDictionary<string, object> mutable when mutable.TryGetValue(member, out object? raw) && raw is string s => (true, s),
            _ => (false, null)
        };

        return found;
    }
}
