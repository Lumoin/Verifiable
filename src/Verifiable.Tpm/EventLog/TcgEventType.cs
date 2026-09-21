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
    /// <summary>
    /// Legacy pre-boot certificate event, retained for compatibility with the 1.2-era Trusted Platform Support Service.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_PREBOOT_CERT = 0x00000000;

    /// <summary>
    /// POST code or embedded SMM code measurement recorded during platform power-on self-test.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_POST_CODE = 0x00000001;

    /// <summary>
    /// Reserved event type not used by conformant event log producers.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_UNUSED = 0x00000002;

    /// <summary>
    /// Informational event that carries data such as the specification identifier or startup locality without extending a PCR.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_NO_ACTION = 0x00000003;

    /// <summary>
    /// Boundary marker written with a fixed event data value to signal a transition between event log phases and to let a verifier detect extension attacks.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_SEPARATOR = 0x00000004;

    /// <summary>
    /// ASCII string describing a firmware-initiated action, measured verbatim as the event data.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_ACTION = 0x00000005;

    /// <summary>
    /// Tagged event structure (<c>TCG_PCClientTaggedEventStruct</c>) carrying a vendor- or specification-defined sub-event.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_EVENT_TAG = 0x00000006;

    /// <summary>
    /// Measurement of the code contents of the CRTM (Core Root of Trust for Measurement).
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_S_CRTM_CONTENTS = 0x00000007;

    /// <summary>
    /// Measurement of the version identifier of the CRTM (Core Root of Trust for Measurement).
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_S_CRTM_VERSION = 0x00000008;

    /// <summary>
    /// Measurement of a CPU microcode update applied by firmware during boot.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_CPU_MICROCODE = 0x00000009;

    /// <summary>
    /// Measurement of platform configuration flags that alter the remainder of the boot process.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_PLATFORM_CONFIG_FLAGS = 0x0000000A;

    /// <summary>
    /// Measurement of the table of boot devices enumerated by firmware.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_TABLE_OF_DEVICES = 0x0000000B;

    /// <summary>
    /// Digest-only measurement carrying no event data beyond the recorded hash, used where the full measured content would be excessive to log.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_COMPACT_HASH = 0x0000000C;

    /// <summary>
    /// Measurement of the Initial Program Loader (the boot loader or OS loader) handed control by firmware.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_IPL = 0x0000000D;

    /// <summary>
    /// Measurement of the partition table entry associated with the Initial Program Loader.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_IPL_PARTITION_DATA = 0x0000000E;

    /// <summary>
    /// Measurement of code executing on a non-host platform component, such as an embedded controller.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_NONHOST_CODE = 0x0000000F;

    /// <summary>
    /// Measurement of configuration data belonging to a non-host platform component.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_NONHOST_CONFIG = 0x00000010;

    /// <summary>
    /// Informational event describing a non-host platform component whose content is not necessarily verifiable by hash.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_NONHOST_INFO = 0x00000011;

    /// <summary>
    /// Marker recorded when boot device events were intentionally omitted from the event log.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_OMIT_BOOT_DEVICE_EVENTS = 0x00000012;

    //EFI events (defined in TCG EFI Protocol Specification).
    /// <summary>
    /// Base value marking the start of the EFI event type range; not itself a measured event.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">TCG EFI Protocol Specification</see>, Table 7.
    /// </remarks>
    public const uint EV_EFI_EVENT_BASE = 0x80000000;

    /// <summary>
    /// Measurement of an EFI variable consumed by a driver to configure its runtime behavior.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">TCG EFI Protocol Specification</see>, Table 7.
    /// </remarks>
    public const uint EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001;

    /// <summary>
    /// Measurement of an EFI boot variable, such as <c>BootOrder</c> or a <c>Boot####</c> entry, that determines the platform's boot sequence.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">TCG EFI Protocol Specification</see>, Table 7.
    /// </remarks>
    public const uint EV_EFI_VARIABLE_BOOT = 0x80000002;

    /// <summary>
    /// Measurement of an EFI application loaded through Boot Services, such as the OS loader.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">TCG EFI Protocol Specification</see>, Table 7.
    /// </remarks>
    public const uint EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003;

    /// <summary>
    /// Measurement of an EFI driver loaded through Boot Services.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">TCG EFI Protocol Specification</see>, Table 7.
    /// </remarks>
    public const uint EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004;

    /// <summary>
    /// Measurement of an EFI driver that remains resident and callable through Runtime Services after boot completes.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">TCG EFI Protocol Specification</see>, Table 7.
    /// </remarks>
    public const uint EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000005;

    /// <summary>
    /// Measurement of the GUID Partition Table of a boot device.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">TCG EFI Protocol Specification</see>, Table 7.
    /// </remarks>
    public const uint EV_EFI_GPT_EVENT = 0x80000006;

    /// <summary>
    /// ASCII string describing an EFI-specific firmware action, measured verbatim as the event data.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">TCG EFI Protocol Specification</see>, Table 7.
    /// </remarks>
    public const uint EV_EFI_ACTION = 0x80000007;

    /// <summary>
    /// Measurement of a firmware blob, identified by its address and length, executed or loaded by the platform.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">TCG EFI Protocol Specification</see>, Table 7.
    /// </remarks>
    public const uint EV_EFI_PLATFORM_FIRMWARE_BLOB = 0x80000008;

    /// <summary>
    /// Measurement of the EFI handoff tables passed from firmware to the OS loader.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/">TCG EFI Protocol Specification</see>, Table 7.
    /// </remarks>
    public const uint EV_EFI_HANDOFF_TABLES = 0x80000009;

    /// <summary>
    /// Measurement of a firmware blob, extended with a descriptive string identifying the blob's purpose.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_EFI_PLATFORM_FIRMWARE_BLOB2 = 0x8000000A;

    /// <summary>
    /// Measurement of the EFI handoff tables, extended with a descriptive string identifying the table's purpose.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_EFI_HANDOFF_TABLES2 = 0x8000000B;

    /// <summary>
    /// Measurement of an EFI boot variable, extended to carry the variable's UEFI device path.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_EFI_VARIABLE_BOOT2 = 0x8000000C;

    /// <summary>
    /// Measurement of the GUID Partition Table, superseding <see cref="EV_EFI_GPT_EVENT"/> with an updated event data structure.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_EFI_GPT_EVENT2 = 0x8000000D;

    /// <summary>
    /// Measurement recorded when the Host CRTM (H-CRTM) sequence establishes late-launch trust in the platform.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_EFI_HCRTM_EVENT = 0x80000010;

    /// <summary>
    /// Measurement of an EFI variable used as a Secure Boot authority, such as a database or key exchange key entry.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_EFI_VARIABLE_AUTHORITY = 0x800000E0;

    /// <summary>
    /// Measurement of a firmware blob whose integrity was established through the SPDM (Security Protocol and Data Model) protocol.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_EFI_SPDM_FIRMWARE_BLOB = 0x800000E1;

    /// <summary>
    /// Measurement of configuration data for a component whose integrity was established through the SPDM protocol.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_EFI_SPDM_FIRMWARE_CONFIG = 0x800000E2;

    /// <summary>
    /// Measurement of the security policy applied to a device attested through the SPDM protocol.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
    public const uint EV_EFI_SPDM_DEVICE_POLICY = 0x800000E3;

    /// <summary>
    /// Measurement of the authority (certificate chain) used to attest a device through the SPDM protocol.
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">TCG PC Client Platform Firmware Profile Specification</see>, Table 9.
    /// </remarks>
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
