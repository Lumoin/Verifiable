using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm;

/// <summary>
/// TBS command priority values.
/// </summary>
/// <remarks>
/// <para>
/// Priority determines the order of command execution when multiple commands
/// are queued. Higher values indicate higher priority.
/// </para>
/// <para>
/// See <see href="https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsip_submit_command">
/// Tbsip_Submit_Command</see>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1008:Enums should have zero value", Justification = "This follows the Windows TBS API.")]
public enum TbsPriority: uint
{
    /// <summary>
    /// Low priority (100).
    /// </summary>
    Low = 100,

    /// <summary>
    /// Normal priority (200) - default for most applications.
    /// </summary>
    Normal = 200,

    /// <summary>
    /// High priority (300).
    /// </summary>
    High = 300,

    /// <summary>
    /// System priority (400) - highest priority, typically used by system components.
    /// </summary>
    System = 400
}
