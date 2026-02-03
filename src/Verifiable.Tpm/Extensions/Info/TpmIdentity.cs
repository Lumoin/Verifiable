using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Extensions.Info;

/// <summary>
/// TPM identity and firmware information.
/// </summary>
/// <remarks>
/// <para>
/// Contains manufacturer identification and firmware version details
/// extracted from TPM fixed properties (PT_FIXED).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmIdentity
{
    /// <summary>
    /// Gets the TPM family specification (e.g., "2.0").
    /// </summary>
    public string Family { get; }

    /// <summary>
    /// Gets the specification revision level.
    /// </summary>
    public int Revision { get; }

    /// <summary>
    /// Gets the specification level.
    /// </summary>
    public int Level { get; }

    /// <summary>
    /// Gets the manufacturer ID (4-character TCG vendor code).
    /// </summary>
    /// <remarks>
    /// Common values: "AMD ", "INTC" (Intel), "IFX " (Infineon), "STM " (ST Micro).
    /// </remarks>
    public string ManufacturerId { get; }

    /// <summary>
    /// Gets the vendor string (free-form vendor text, up to 16 characters).
    /// </summary>
    /// <remarks>
    /// Combined from VENDOR_STRING_1 through VENDOR_STRING_4 properties.
    /// Often contains the manufacturer name or TPM model.
    /// </remarks>
    public string VendorString { get; }

    /// <summary>
    /// Gets the vendor-defined TPM type.
    /// </summary>
    public int VendorTpmType { get; }

    /// <summary>
    /// Gets the combined firmware version string (e.g., "6.32.0.6").
    /// </summary>
    /// <remarks>
    /// Combined from FIRMWARE_VERSION_1 (major.minor) and FIRMWARE_VERSION_2 (build.patch).
    /// </remarks>
    public string FirmwareVersion { get; }

    /// <summary>
    /// Gets the firmware version as a structured Version object.
    /// </summary>
    public Version Firmware { get; }

    /// <summary>
    /// Gets the year the firmware was built.
    /// </summary>
    public int FirmwareYear { get; }

    /// <summary>
    /// Gets the day of year the firmware was built (1-366).
    /// </summary>
    public int FirmwareDayOfYear { get; }

    /// <summary>
    /// Gets the number of PCRs supported by this TPM.
    /// </summary>
    public int PcrCount { get; }

    /// <summary>
    /// Gets the maximum input buffer size in bytes.
    /// </summary>
    public int MaxInputBuffer { get; }

    /// <summary>
    /// Gets the maximum NV buffer size in bytes.
    /// </summary>
    public int MaxNvBuffer { get; }

    internal TpmIdentity(
        string family,
        int revision,
        int level,
        string manufacturerId,
        string vendorString,
        int vendorTpmType,
        int firmwareMajor,
        int firmwareMinor,
        int firmwareBuild,
        int firmwarePatch,
        int firmwareYear,
        int firmwareDayOfYear,
        int pcrCount,
        int maxInputBuffer,
        int maxNvBuffer)
    {
        Family = family;
        Revision = revision;
        Level = level;
        ManufacturerId = manufacturerId;
        VendorString = vendorString;
        VendorTpmType = vendorTpmType;
        FirmwareYear = firmwareYear;
        FirmwareDayOfYear = firmwareDayOfYear;
        PcrCount = pcrCount;
        MaxInputBuffer = maxInputBuffer;
        MaxNvBuffer = maxNvBuffer;

        Firmware = new Version(firmwareMajor, firmwareMinor, firmwareBuild, firmwarePatch);
        FirmwareVersion = $"{firmwareMajor}.{firmwareMinor}.{firmwareBuild}.{firmwarePatch}";
    }

    private string DebuggerDisplay => $"{ManufacturerId.Trim()} {Family} rev {Revision}, firmware {FirmwareVersion}";
}