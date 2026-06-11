using System;
using Verifiable.Cryptography.Text;

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
    /// <summary>The UTF-8 source literal of <see cref="User"/>.</summary>
    public static ReadOnlySpan<byte> UserUtf8 => "user"u8;

    /// <summary>The <c>user</c> member — a Subject Identifier for a user.</summary>
    public static readonly string User = Utf8Constants.ToInternedString(UserUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Device"/>.</summary>
    public static ReadOnlySpan<byte> DeviceUtf8 => "device"u8;

    /// <summary>The <c>device</c> member — a Subject Identifier for a device.</summary>
    public static readonly string Device = Utf8Constants.ToInternedString(DeviceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Session"/>.</summary>
    public static ReadOnlySpan<byte> SessionUtf8 => "session"u8;

    /// <summary>The <c>session</c> member — a Subject Identifier for a session.</summary>
    public static readonly string Session = Utf8Constants.ToInternedString(SessionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Application"/>.</summary>
    public static ReadOnlySpan<byte> ApplicationUtf8 => "application"u8;

    /// <summary>The <c>application</c> member — a Subject Identifier for an application.</summary>
    public static readonly string Application = Utf8Constants.ToInternedString(ApplicationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Tenant"/>.</summary>
    public static ReadOnlySpan<byte> TenantUtf8 => "tenant"u8;

    /// <summary>The <c>tenant</c> member — a Subject Identifier for a tenant.</summary>
    public static readonly string Tenant = Utf8Constants.ToInternedString(TenantUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OrgUnit"/>.</summary>
    public static ReadOnlySpan<byte> OrgUnitUtf8 => "org_unit"u8;

    /// <summary>The <c>org_unit</c> member — a Subject Identifier for an organizational unit.</summary>
    public static readonly string OrgUnit = Utf8Constants.ToInternedString(OrgUnitUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Group"/>.</summary>
    public static ReadOnlySpan<byte> GroupUtf8 => "group"u8;

    /// <summary>The <c>group</c> member — a Subject Identifier for a group.</summary>
    public static readonly string Group = Utf8Constants.ToInternedString(GroupUtf8);
}
