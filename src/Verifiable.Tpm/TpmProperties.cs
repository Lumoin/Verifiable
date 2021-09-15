using System;

namespace Verifiable.Tpm
{
    /// <summary>
    /// TPM Properties according to <see href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">
    /// Trusted Platform Module Library Part 2: Structures [pdf]</see>.
    /// </summary>
    /// <param name="SpecificationLevel">Abc1.</param>
    /// <param name="FamilyIndicator"></param>
    /// <param name="SpecificationRevision"></param>
    /// <param name="SpecificationDate"></param>
    /// <param name="ManufacturerName"></param>
    /// <param name="VendorString"></param>
    /// <param name="VendorType"></param>
    /// <param name="PlatformSpecificationLevel"></param>
    /// <param name="PlatformSpecificationRevision"></param>
    /// <param name="PlatformSpecificationDate"></param>
    /// <param name="FirmwareVersion"></param>
    /// <param name="ActiveSessionsMax"></param>
    /// <param name="PlatformMemoryInMegaBytes"></param>
    /// <param name="IsFips1402"></param>
    public record TpmProperties(
        string SpecificationLevel,
        string FamilyIndicator,
        string SpecificationRevision,
        DateTime SpecificationDate,
        string ManufacturerName,
        string VendorString,
        string VendorType,
        string PlatformSpecificationLevel,
        string PlatformSpecificationRevision,
        DateOnly PlatformSpecificationDate,
        Version FirmwareVersion,
        uint ActiveSessionsMax,
        string PlatformMemoryInMegaBytes,
        bool IsFips1402)
    {
        /// <summary>
        /// Test docs 2.
        /// </summary>
        public string SpecificationLevel { get; init; } = Guard.NotNull(SpecificationLevel, nameof(SpecificationLevel));

        public string FamilyIndicator { get; init; } = Guard.NotNull(FamilyIndicator, nameof(FamilyIndicator));

        public string SpecificationRevision { get; init; } = Guard.NotNull(SpecificationRevision, nameof(SpecificationRevision));

        public DateTime SpecificationDate { get; init; } = SpecificationDate;

        public string ManufacturerName { get; init; } = Guard.NotNull(ManufacturerName, nameof(ManufacturerName));

        public string VendorString { get; init; } = Guard.NotNull(VendorString, nameof(VendorString));

        public string VendorType { get; init; } = Guard.NotNull(VendorType, nameof(VendorType));

        public string PlatformSpecificationLevel { get; init; } = Guard.NotNull(PlatformSpecificationLevel, nameof(PlatformSpecificationLevel));

        public string PlatformSpecificationRevision { get; init; } = Guard.NotNull(PlatformSpecificationRevision, nameof(PlatformSpecificationRevision));

        public DateOnly PlatformSpecificationDate { get; init; } = PlatformSpecificationDate;

        public Version FirmwareVersion { get; init; } = FirmwareVersion;

        public uint ActiveSessionsMax { get; init; } = ActiveSessionsMax;

        public string PlatformMemoryInMegaBytes { get; init; } = Guard.NotNull(PlatformMemoryInMegaBytes, nameof(PlatformMemoryInMegaBytes));

        /// <summary>
        /// Indicates that the TPM is designed to comply with all of the FIPS 140-2 requirements at Level 1 or higher.
        /// </summary>
        public bool IsFips1402 { get; init; } = IsFips1402;
    };
}
