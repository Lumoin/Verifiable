namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The well-known member NAMES that may appear inside a Complex Subject
/// (<see cref="SubjectIdentifierFormats.Complex"/>), each naming a Simple Subject
/// Member that is itself a Subject Identifier, per OpenID Shared Signals
/// Framework 1.0 §3.3.
/// </summary>
/// <remarks>
/// These names are OPTIONAL and additional names MAY be used; each member name
/// appears at most once. All members of a Complex Subject MUST describe the same
/// Subject Principal (SSF §3.3.1).
/// </remarks>
public static class ComplexSubjectMemberNames
{
    /// <summary>The <c>user</c> member — a Subject Identifier for a user.</summary>
    public static readonly string User = "user";

    /// <summary>The <c>device</c> member — a Subject Identifier for a device.</summary>
    public static readonly string Device = "device";

    /// <summary>The <c>session</c> member — a Subject Identifier for a session.</summary>
    public static readonly string Session = "session";

    /// <summary>The <c>application</c> member — a Subject Identifier for an application.</summary>
    public static readonly string Application = "application";

    /// <summary>The <c>tenant</c> member — a Subject Identifier for a tenant.</summary>
    public static readonly string Tenant = "tenant";

    /// <summary>The <c>org_unit</c> member — a Subject Identifier for an organizational unit.</summary>
    public static readonly string OrgUnit = "org_unit";

    /// <summary>The <c>group</c> member — a Subject Identifier for a group.</summary>
    public static readonly string Group = "group";
}
