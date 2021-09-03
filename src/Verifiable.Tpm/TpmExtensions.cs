using System.Collections.Immutable;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Tpm2Lib;

namespace Verifiable.Tpm
{
    /// <summary>
    /// Extensions to work with a connected <see cref="Tpm2"/> instance.
    /// </summary>
    public static class TpmExtensions
    {
        /// <summary>
        /// Checks if the calling platform is supported by this TPM library.
        /// </summary>
        /// <returns><see langword="True"/> if this library supports TPM. <see langword="False"/> otherwise.</returns>
        /// <remarks>It may be TPM is supported by the platform, but not by this library.</remarks>
        public static bool IsTpmPlatformSupported()
        {
            //TPMs are supported only on Windows or Linux at the moment.
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }


        /// <summary>
        /// Gets all TPM information available from the system.
        /// </summary>
        /// <returns>All available TPM information that is available and extracted.</returns>
        public static TpmInfo GetAllTpmInfo(this Tpm2 tpm)
        {
            ArgumentNullException.ThrowIfNull(tpm, nameof(tpm));

            var properties = GetTpmProperties(tpm);
            var pcrBanks = GetPcrBanks(tpm);

            return new TpmInfo(properties, pcrBanks);
        }


        /// <summary>
        /// Query the <paramref name="tpm"/> for its properties.
        /// </summary>
        /// <param name="tpm">The connected TPM to query.</param>
        /// <returns>The queries properties.</returns>
        public static TpmProperties GetTpmProperties(this Tpm2 tpm)
        {
            ArgumentNullException.ThrowIfNull(tpm, nameof(tpm));
                            
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

            tpmProperty = tpmProperties.tpmProperty[Pt.PsYear - Pt.PtFixed].value;
            var platformSpecificationDate = new DateOnly((int)tpmProperty - 1, 12, 31);
            tpmProperty = tpmProperties.tpmProperty[Pt.PsDayOfYear - Pt.PtFixed].value;
            platformSpecificationDate = platformSpecificationDate.AddDays((int)tpmProperty);

            uint tpmFirmwareVersionHigherBits = tpmProperties.tpmProperty[Pt.FirmwareVersion1 - Pt.PtFixed].value;
            uint tpmFirmwareVersionLowerBits = tpmProperties.tpmProperty[Pt.FirmwareVersion2 - Pt.PtFixed].value;
            Version firmwareVersion = new(
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
            bool isFips1402 = (Tpm2.GetProperty(tpm, Pt.Modes) & (uint)ModesAttr.Fips1402) != 0;

            /*tpm.GetCapability(Cap.TpmProperties, (uint)Pt.PtVar, 1000, out var capPropertiesVar);
            tpmProperties = (TaggedTpmPropertyArray)capPropertiesVar;

            tpmProperty = tpmProperties.tpmProperty[Pt.Permanent - Pt.PtVar].value;
            var tpmPermanent = (PermanentAttr)tpmProperty;
            properties.Add(new Property { Name = nameof(Pt.Permanent), Value = tpmPermanent.ToString() });

            tpmProperty = tpmProperties.tpmProperty[Pt.StartupClear - Pt.PtVar].value;
            var tpmStartupClear = (StartupClearAttr)tpmProperty;
            properties.Add(new Property { Name = nameof(Pt.StartupClear), Value = tpmStartupClear.ToString() });*/

            return new TpmProperties(
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
        }


        /// <summary>
        /// Queries the TPM for all the available PCR banks and their data.
        /// </summary>
        /// <param name="tpm">The TPM to query.</param>
        /// <returns>All the PRC bank data available.</returns>
        public static IReadOnlyCollection<PcrBank> GetPcrBanks(this Tpm2 tpm)
        {
            ArgumentNullException.ThrowIfNull(tpm, nameof(tpm));

            var pcrBanksWithIndex = new List<PcrBank>();

            _ = tpm.GetCapability(Cap.Pcrs, 0, 255, out ICapabilitiesUnion caps);
            var pcrBanks = (PcrSelectionArray)caps;

            foreach(var pcrBank in pcrBanks.pcrSelections)
            {
                var pcrBankData = new List<PcrData>();
                
                //Select all PCRs of this bank. Likely only a subset of these can be read on any given
                //time, so they need to be read in a loop.
                var bankPcrsBeingProcessed = new PcrSelection[] { new PcrSelection(pcrBank.hash, pcrBank.GetSelectedPcrs()) };
                var maxPcrs = (uint)bankPcrsBeingProcessed[0].GetSelectedPcrs().Length;
                do
                {
                    _ = tpm.PcrRead(bankPcrsBeingProcessed, out PcrSelection[] pcrValuesBatchToRead, out Tpm2bDigest[] pcrValues);
                    if(pcrValues.Length == 0)
                    {
                        break;
                    }

                    //Only on bank of values is read at once, indicated by pcrBank.hash.
                    //So there's only one element in the array constructed and correspondingly
                    //received as an out parameter.
                    var pcrsCurrentlyBeingRead = pcrValuesBatchToRead[0].GetSelectedPcrs();

                    var currentRoundPcrsLeftToBeProcessed = bankPcrsBeingProcessed[0].GetSelectedPcrs();
                    var pcrsLefToBeReadForTheNextRounds = currentRoundPcrsLeftToBeProcessed.Except(pcrsCurrentlyBeingRead);

                    for(int i = 0; i < pcrValues.Length; i++)
                    {
                        pcrBankData.Add(new PcrData(pcrsCurrentlyBeingRead[i], ImmutableArray.Create(pcrValues[i].buffer)));
                    }


                    //This construct can be used to read the full bank. But some TPMs may
                    //have more counters, like used in industrial systems or cars. Also,
                    //this likely less than PcrSelection.MaxPcrs indexes, likely only the first eight indexes
                    //pcrs[0] = PcrSelection.FullPcrBank(tpmAlgId, PcrSelection.MaxPcrs);

                    //... So indexes are being read like this, together with the
                    //other loop logic.
                    bankPcrsBeingProcessed[0] = new PcrSelection(pcrBank.hash, maxPcrs);

                    //This loop selects new PCRs to be read for the next round
                    //on the loop from the set of all PCRs in the bank that have
                    //not been read yet. Note that the set of PCRs left to be
                    //read may be larger, or smaller than what the TPM will return
                    //in on batch.
                    foreach(var nextRoundPcr in pcrsLefToBeReadForTheNextRounds)
                    {
                        bankPcrsBeingProcessed[0].SelectPcr(nextRoundPcr);
                    }
                } while(bankPcrsBeingProcessed[0].GetSelectedPcrs().Length > 0);
                pcrBanksWithIndex.Add(new PcrBank(pcrBank.hash.ToString(), pcrBankData));
            }

            return pcrBanksWithIndex.AsReadOnly();
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
