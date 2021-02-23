using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using Tpm2Lib;

namespace Verifiable.Tpm
{
    /// <summary>
    /// TPM Properties according to <see href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">
    /// Trusted Platform Module Library Part 2: Structures [pdf]</see>.
    /// </summary>
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
        DateTime PlatformSpecificationDate,
        Version FirmwareVersion,
        uint ActiveSessionsMax,
        string PlatformMemoryInMegaBytes,
        bool IsFips1402)
    {
        /// <summary>
        /// Test docs 2.
        /// </summary>
        public string SpecificationLevel { get; init; } = Validate(SpecificationLevel, nameof(SpecificationLevel));

        public string FamilyIndicator { get; init; } = Validate(FamilyIndicator, nameof(FamilyIndicator));

        public string SpecificationRevision { get; init; } = Validate(SpecificationRevision, nameof(SpecificationRevision));

        public DateTime SpecificationDate { get; init; } = SpecificationDate;

        public string ManufacturerName { get; init; } = Validate(ManufacturerName, nameof(ManufacturerName));

        public string VendorString { get; init; } = Validate(VendorString, nameof(VendorString));

        public string VendorType { get; init; } = Validate(VendorType, nameof(VendorType));

        public string PlatformSpecificationLevel { get; init; } = Validate(PlatformSpecificationLevel, nameof(PlatformSpecificationLevel));

        public string PlatformSpecificationRevision { get; init; } = Validate(PlatformSpecificationRevision, nameof(PlatformSpecificationRevision));

        public DateTime PlatformSpecificationDate { get; init; } = PlatformSpecificationDate;

        public Version FirmwareVersion { get; init; } = FirmwareVersion;

        public uint ActiveSessionsMax { get; init; } = ActiveSessionsMax;

        public string PlatformMemoryInMegaBytes { get; init; } = Validate(PlatformMemoryInMegaBytes, nameof(PlatformMemoryInMegaBytes));

        /// <summary>
        /// Indicates that the TPM is designed to comply with all of the FIPS 140-2 requirements at Level 1 or higher.
        /// </summary>
        public bool IsFips1402 { get; set; } = IsFips1402;

        
        private static string Validate(string value, string parameterName)
        {
            ArgumentNullException.ThrowIfNull(value, parameterName);

            return value;
        }
    };


    public static class TpmExtensions
    {
        public static TpmProperties GetTpmProperties(this Tpm2 tpm)
        {
            //TODO: Get all of these properties...
            /*
            None = 0,
            PtGroup = 256,
            PtFixed = 256,
            FamilyIndicator = 256,
            Level = 257,
            Revision = 258,
            DayOfYear = 259,
            Year = 260,
            Manufacturer = 261,
            VendorString1 = 262,
            VendorString2 = 263,
            VendorString3 = 264,
            VendorString4 = 265,
            VendorTpmType = 266,
            FirmwareVersion1 = 267,
            FirmwareVersion2 = 268,
            InputBuffer = 269,
            HrTransientMin = 270,
            HrPersistentMin = 271,
            HrLoadedMin = 272,
            ActiveSessionsMax = 273,
            PcrCount = 274,
            PcrSelectMin = 275,
            ContextGapMax = 276,
            NvCountersMax = 278,
            NvIndexMax = 279,
            Memory = 280,
            ClockUpdate = 281,
            ContextHash = 282,
            ContextSym = 283,
            ContextSymSize = 284,
            OrderlyCount = 285,
            MaxCommandSize = 286,
            MaxResponseSize = 287,
            MaxDigest = 288,
            MaxObjectContext = 289,
            MaxSessionContext = 290,
            PsFamilyIndicator = 291,
            PsLevel = 292,
            PsRevision = 293,
            PsDayOfYear = 294,
            PsYear = 295,
            SplitMax = 296,
            TotalCommands = 297,
            LibraryCommands = 298,
            VendorCommands = 299,
            NvBufferMax = 300,
            Modes = 301,
            MaxCapBuffer = 302,
            PtVar = 512,
            Permanent = 512,
            StartupClear = 513,
            HrNvIndex = 514,
            HrLoaded = 515,
            HrLoadedAvail = 516,
            HrActive = 517,
            HrActiveAvail = 518,
            HrTransientAvail = 519,
            HrPersistent = 520,
            HrPersistentAvail = 521,
            NvCounters = 522,
            NvCountersAvail = 523,
            AlgorithmSet = 524,
            LoadedCurves = 525,
            LockoutCounter = 526,
            MaxAuthFail = 527,
            LockoutInterval = 528,
            LockoutRecovery = 529,
            NvWriteRecovery = 530,
            AuditCounter0 = 531,
            AuditCounter1 = 532
            */

            TaggedTpmPropertyArray tpmProperties;
            _ = tpm.GetCapability(Cap.TpmProperties, (uint)Pt.PtFixed, 1000, out var capProperties);
            tpmProperties = (TaggedTpmPropertyArray)capProperties;

            string specificationLevel = tpmProperties.tpmProperty[Pt.Level - Pt.PtFixed].value.ToString();

            var tpmProperty = tpmProperties.tpmProperty[Pt.FamilyIndicator - Pt.PtFixed].value;
            var tpmFamilyIndicator = BitConverter.GetBytes(ReverseBytes(tpmProperty));
            string familyIndicator = Encoding.UTF8.GetString(tpmFamilyIndicator);

            tpmProperty = tpmProperties.tpmProperty[Pt.Revision - Pt.PtFixed].value;
            var specificationRevision = (float)tpmProperty / 100;

            //TODO: See DateOnly type at https://www.infoq.com/news/2021/04/Net6-Date-Time/.
            tpmProperty = tpmProperties.tpmProperty[Pt.Year - Pt.PtFixed].value;
            var specificationDate = new DateTime((int)tpmProperty - 1, 12, 31);
            tpmProperty = tpmProperties.tpmProperty[Pt.DayOfYear - Pt.PtFixed].value;
            specificationDate = specificationDate.AddDays(tpmProperty);

            var manufacturerBytes = BitConverter.GetBytes(ReverseBytes(tpmProperties.tpmProperty[Pt.Manufacturer - Pt.PtFixed].value));
            string manufacturerName = Encoding.UTF8.GetString(manufacturerBytes);

            //According to the specification each of the vendor strings can be up to four charachters long.
            var vendorStringBuilder = new StringBuilder();
            vendorStringBuilder.Append(Encoding.UTF8.GetString(BitConverter.GetBytes(ReverseBytes(tpmProperties.tpmProperty[Pt.VendorString1 - Pt.PtFixed].value))));
            vendorStringBuilder.Append(Encoding.UTF8.GetString(BitConverter.GetBytes(ReverseBytes(tpmProperties.tpmProperty[Pt.VendorString2 - Pt.PtFixed].value))));
            vendorStringBuilder.Append(Encoding.UTF8.GetString(BitConverter.GetBytes(ReverseBytes(tpmProperties.tpmProperty[Pt.VendorString3 - Pt.PtFixed].value))));
            vendorStringBuilder.Append(Encoding.UTF8.GetString(BitConverter.GetBytes(ReverseBytes(tpmProperties.tpmProperty[Pt.VendorString4 - Pt.PtFixed].value))));

            string vendorType = tpmProperties.tpmProperty[Pt.VendorTpmType - Pt.PtFixed].value.ToString();
            string platformSpecificationLevel = tpmProperties.tpmProperty[Pt.PsLevel - Pt.PtFixed].value.ToString();

            tpmProperty = tpmProperties.tpmProperty[Pt.PsRevision - Pt.PtFixed].value;
            string platformSpecificationRevision = ((float)tpmProperty / 100).ToString(CultureInfo.InvariantCulture);

            //TODO: See DateOnly type at https://www.infoq.com/news/2021/04/Net6-Date-Time/.
            tpmProperty = tpmProperties.tpmProperty[Pt.PsYear - Pt.PtFixed].value;
            var platformSpecificationDate = new DateTime((int)tpmProperty - 1, 12, 31);
            tpmProperty = tpmProperties.tpmProperty[Pt.PsDayOfYear - Pt.PtFixed].value;
            platformSpecificationDate = platformSpecificationDate.AddDays(tpmProperty);

            uint tpmFirmwareVersionHigherBits = tpmProperties.tpmProperty[Pt.FirmwareVersion1 - Pt.PtFixed].value;
            uint tpmFirmwareVersionLowerBits = tpmProperties.tpmProperty[Pt.FirmwareVersion2 - Pt.PtFixed].value;
            Version firmwareVersion = new Version(
                (int)tpmFirmwareVersionHigherBits >> 16,
                (int)tpmFirmwareVersionHigherBits & 0xFFFF,
                (int)tpmFirmwareVersionLowerBits >> 16,
                (int)tpmFirmwareVersionLowerBits & 0xFFFF);

            uint activeSessionsMax = tpmProperties.tpmProperty[Pt.ActiveSessionsMax - Pt.PtFixed].value;

            tpmProperty = tpmProperties.tpmProperty[Pt.Memory - Pt.PtFixed].value;
            var tpmMemory = (MemoryAttr)tpmProperty;
            string platformMemoryInMegaBytes = tpmMemory.ToString();

            //tpmProperty = tpmProperties.tpmProperty[Pt.Modes - Pt.PtFixed].value;
            //properties.Add(new Property { Name = nameof(Pt.Modes), Value = tpmModes.ToString() });
            bool isFips1402 = ((Tpm2.GetProperty(tpm, Pt.Modes) & (uint)ModesAttr.Fips1402) != 0);

            /*tpm.GetCapability(Cap.TpmProperties, (uint)Pt.PtVar, 1000, out var capPropertiesVar);
            tpmProperties = (TaggedTpmPropertyArray)capPropertiesVar;

            tpmProperty = tpmProperties.tpmProperty[Pt.Permanent - Pt.PtVar].value;
            var tpmPermanent = (PermanentAttr)tpmProperty;
            properties.Add(new Property { Name = nameof(Pt.Permanent), Value = tpmPermanent.ToString() });

            tpmProperty = tpmProperties.tpmProperty[Pt.StartupClear - Pt.PtVar].value;
            var tpmStartupClear = (StartupClearAttr)tpmProperty;
            properties.Add(new Property { Name = nameof(Pt.StartupClear), Value = tpmStartupClear.ToString() });*/

            var x = new TpmProperties(
                specificationLevel,
                familyIndicator,
                specificationRevision.ToString(CultureInfo.InvariantCulture),
                specificationDate,
                manufacturerName,
                vendorStringBuilder.ToString().Trim('\0'),
                vendorType,
                platformSpecificationLevel,
                platformSpecificationRevision,
                platformSpecificationDate,
                firmwareVersion,
                activeSessionsMax,
                platformMemoryInMegaBytes,
                isFips1402
            );

            var tmp = x.SpecificationLevel;
            return x;
        }


        /// <summary>
        /// Reverses the bytes in <paramref name="value"/> and gives the result as return value.
        /// </summary>
        /// <param name="value">The value in which to reverse the bytes.</param>
        /// <returns>The reversed bytes.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ReverseBytes(uint value)
        {
            return
                  (value & 0x000000FFU) << 24
                | (value & 0x0000FF00U) << 8
                | (value & 0x00FF0000U) >> 8
                | (value & 0xFF000000U) >> 24;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint CombineToUint(uint highBytes, uint lowBytes)
        {
            return (highBytes << 16) | (lowBytes & 0xFFFF);
        }
    }
}
