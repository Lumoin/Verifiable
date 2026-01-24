namespace Verifiable.Tpm.EventLog;

/// <summary>
/// TCG event types as defined in the PC Client Platform Firmware Profile Specification.
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">
/// TCG PC Client Platform Firmware Profile Specification</see>
/// (Section 10.4.1 "Event Types", Table 9).
/// </para>
/// <para>
/// EFI event types are defined in:
/// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">
/// TCG EFI Protocol Specification</see>
/// (Section 7 "Event Log Structure", Table 7).
/// </para>
/// </remarks>
public static class TcgEventType
{
    //Pre-boot events (defined in TCG PC Client Specific Implementation Specification).
    public const uint EV_PREBOOT_CERT = 0x00000000;
    public const uint EV_POST_CODE = 0x00000001;
    public const uint EV_UNUSED = 0x00000002;
    public const uint EV_NO_ACTION = 0x00000003;
    public const uint EV_SEPARATOR = 0x00000004;
    public const uint EV_ACTION = 0x00000005;
    public const uint EV_EVENT_TAG = 0x00000006;
    public const uint EV_S_CRTM_CONTENTS = 0x00000007;
    public const uint EV_S_CRTM_VERSION = 0x00000008;
    public const uint EV_CPU_MICROCODE = 0x00000009;
    public const uint EV_PLATFORM_CONFIG_FLAGS = 0x0000000A;
    public const uint EV_TABLE_OF_DEVICES = 0x0000000B;
    public const uint EV_COMPACT_HASH = 0x0000000C;
    public const uint EV_IPL = 0x0000000D;
    public const uint EV_IPL_PARTITION_DATA = 0x0000000E;
    public const uint EV_NONHOST_CODE = 0x0000000F;
    public const uint EV_NONHOST_CONFIG = 0x00000010;
    public const uint EV_NONHOST_INFO = 0x00000011;
    public const uint EV_OMIT_BOOT_DEVICE_EVENTS = 0x00000012;

    //EFI events (defined in TCG EFI Protocol Specification).
    public const uint EV_EFI_EVENT_BASE = 0x80000000;
    public const uint EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001;
    public const uint EV_EFI_VARIABLE_BOOT = 0x80000002;
    public const uint EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003;
    public const uint EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004;
    public const uint EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000005;
    public const uint EV_EFI_GPT_EVENT = 0x80000006;
    public const uint EV_EFI_ACTION = 0x80000007;
    public const uint EV_EFI_PLATFORM_FIRMWARE_BLOB = 0x80000008;
    public const uint EV_EFI_HANDOFF_TABLES = 0x80000009;
    public const uint EV_EFI_PLATFORM_FIRMWARE_BLOB2 = 0x8000000A;
    public const uint EV_EFI_HANDOFF_TABLES2 = 0x8000000B;
    public const uint EV_EFI_VARIABLE_BOOT2 = 0x8000000C;
    public const uint EV_EFI_GPT_EVENT2 = 0x8000000D;
    public const uint EV_EFI_HCRTM_EVENT = 0x80000010;
    public const uint EV_EFI_VARIABLE_AUTHORITY = 0x800000E0;
    public const uint EV_EFI_SPDM_FIRMWARE_BLOB = 0x800000E1;
    public const uint EV_EFI_SPDM_FIRMWARE_CONFIG = 0x800000E2;
    public const uint EV_EFI_SPDM_DEVICE_POLICY = 0x800000E3;
    public const uint EV_EFI_SPDM_DEVICE_AUTHORITY = 0x800000E4;

    /// <summary>
    /// Gets a human-readable name for an event type.
    /// </summary>
    public static string GetName(uint eventType)
    {
        return eventType switch
        {
            EV_PREBOOT_CERT => "EV_PREBOOT_CERT",
            EV_POST_CODE => "EV_POST_CODE",
            EV_UNUSED => "EV_UNUSED",
            EV_NO_ACTION => "EV_NO_ACTION",
            EV_SEPARATOR => "EV_SEPARATOR",
            EV_ACTION => "EV_ACTION",
            EV_EVENT_TAG => "EV_EVENT_TAG",
            EV_S_CRTM_CONTENTS => "EV_S_CRTM_CONTENTS",
            EV_S_CRTM_VERSION => "EV_S_CRTM_VERSION",
            EV_CPU_MICROCODE => "EV_CPU_MICROCODE",
            EV_PLATFORM_CONFIG_FLAGS => "EV_PLATFORM_CONFIG_FLAGS",
            EV_TABLE_OF_DEVICES => "EV_TABLE_OF_DEVICES",
            EV_COMPACT_HASH => "EV_COMPACT_HASH",
            EV_IPL => "EV_IPL",
            EV_IPL_PARTITION_DATA => "EV_IPL_PARTITION_DATA",
            EV_NONHOST_CODE => "EV_NONHOST_CODE",
            EV_NONHOST_CONFIG => "EV_NONHOST_CONFIG",
            EV_NONHOST_INFO => "EV_NONHOST_INFO",
            EV_OMIT_BOOT_DEVICE_EVENTS => "EV_OMIT_BOOT_DEVICE_EVENTS",
            EV_EFI_EVENT_BASE => "EV_EFI_EVENT_BASE",
            EV_EFI_VARIABLE_DRIVER_CONFIG => "EV_EFI_VARIABLE_DRIVER_CONFIG",
            EV_EFI_VARIABLE_BOOT => "EV_EFI_VARIABLE_BOOT",
            EV_EFI_BOOT_SERVICES_APPLICATION => "EV_EFI_BOOT_SERVICES_APPLICATION",
            EV_EFI_BOOT_SERVICES_DRIVER => "EV_EFI_BOOT_SERVICES_DRIVER",
            EV_EFI_RUNTIME_SERVICES_DRIVER => "EV_EFI_RUNTIME_SERVICES_DRIVER",
            EV_EFI_GPT_EVENT => "EV_EFI_GPT_EVENT",
            EV_EFI_ACTION => "EV_EFI_ACTION",
            EV_EFI_PLATFORM_FIRMWARE_BLOB => "EV_EFI_PLATFORM_FIRMWARE_BLOB",
            EV_EFI_HANDOFF_TABLES => "EV_EFI_HANDOFF_TABLES",
            EV_EFI_PLATFORM_FIRMWARE_BLOB2 => "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
            EV_EFI_HANDOFF_TABLES2 => "EV_EFI_HANDOFF_TABLES2",
            EV_EFI_VARIABLE_BOOT2 => "EV_EFI_VARIABLE_BOOT2",
            EV_EFI_GPT_EVENT2 => "EV_EFI_GPT_EVENT2",
            EV_EFI_HCRTM_EVENT => "EV_EFI_HCRTM_EVENT",
            EV_EFI_VARIABLE_AUTHORITY => "EV_EFI_VARIABLE_AUTHORITY",
            EV_EFI_SPDM_FIRMWARE_BLOB => "EV_EFI_SPDM_FIRMWARE_BLOB",
            EV_EFI_SPDM_FIRMWARE_CONFIG => "EV_EFI_SPDM_FIRMWARE_CONFIG",
            EV_EFI_SPDM_DEVICE_POLICY => "EV_EFI_SPDM_DEVICE_POLICY",
            EV_EFI_SPDM_DEVICE_AUTHORITY => "EV_EFI_SPDM_DEVICE_AUTHORITY",
            _ => $"Unknown(0x{eventType:X8})"
        };
    }
}