namespace Verifiable.Tpm.Infrastructure.Spec.Constants;

/// <summary>
/// TPM_PT constants (TPM property tags).
/// </summary>
/// <remarks>
/// <para>
/// Used with <c>TPM2_GetCapability</c> when <c>capability == TPM_CAP_TPM_PROPERTIES</c>.
/// </para>
/// <para>
/// Specification: TPM 2.0 Library Specification (Part 2: Structures), section "6 Constants", Table 29 (TPM_PT).
/// </para>
/// </remarks>
public static class TpmPtConstants
{
    /// <summary>
    /// TPM_PT_NONE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// indicates no property type
    /// </para>
    /// </remarks>
    public const uint TPM_PT_NONE = 0x00000000u;

    /// <summary>
    /// PT_GROUP.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of properties in each group Note: The first group with any properties is group 1
    /// (PT_GROUP * 1). Group 0 is reserved.
    /// </para>
    /// </remarks>
    public const uint PT_GROUP = 0x00000100u;

    /// <summary>
    /// PT_FIXED.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the group of fixed properties returned as TPMS_TAGGED_PROPERTY The values in this group are
    /// only changed due to a firmware change in the TPM.
    /// </para>
    /// </remarks>
    public const uint PT_FIXED = PT_GROUP * 1u;

    /// <summary>
    /// PT_VAR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the group of variable properties returned as TPMS_TAGGED_PROPERTY The properties in this
    /// group change because of a Protected Capability other than a firmware update. The values are
    /// not necessarily persistent across allpower transitions.
    /// </para>
    /// </remarks>
    public const uint PT_VAR = PT_GROUP * 2u;

    /// <summary>
    /// TPM_PT_FAMILY_INDICATOR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// a 4-octet character string containing the TPM Familyvalue (TPM_SPEC_FAMILY) Note: Forthis
    /// specification, the Family is "2. 0".
    /// </para>
    /// </remarks>
    public const uint TPM_PT_FAMILY_INDICATOR = PT_FIXED + 0u;

    /// <summary>
    /// TPM_PT_LEVEL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the level of the specification Note: Forthis specification, the level is zero.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_LEVEL = PT_FIXED + 1u;

    /// <summary>
    /// TPM_PT_REVISION.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the specification version Note: The Versionvalue is on the title page of the specification.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_REVISION = PT_FIXED + 2u;

    /// <summary>
    /// TPM_PT_DAY_OF_YEAR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the specification day of year using TCGcalendar Example: November 15, 2010, has a day ofyear
    /// value of 319 (0 x 0000013 F). Note: Thespecification date is on the titlepage of the
    /// specification or errata (see Clause 6. 1).
    /// </para>
    /// </remarks>
    public const uint TPM_PT_DAY_OF_YEAR = PT_FIXED + 3u;

    /// <summary>
    /// TPM_PT_YEAR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the specification year using the CE Example: Theyear 2010 has a value of 0 x 000007 DA.
    /// Note: Thespecification date is on the titlepage of the specification or errata (see Clause
    /// 6. 1).
    /// </para>
    /// </remarks>
    public const uint TPM_PT_YEAR = PT_FIXED + 4u;

    /// <summary>
    /// TPM_PT_MANUFACTURER.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the vendor ID unique to each TPMmanufacturer
    /// </para>
    /// </remarks>
    public const uint TPM_PT_MANUFACTURER = PT_FIXED + 5u;

    /// <summary>
    /// TPM_PT_VENDOR_STRING_1.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the first four characters of the vendor ID string Note: Whenthe vendor string is fewerthan
    /// 16 octets,the a dditional property value s do nothave to be present. A vendor string of 4
    /// octetscan be represented in one 32-bitvalue a ndno null terminating character is required.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_VENDOR_STRING_1 = PT_FIXED + 6u;

    /// <summary>
    /// TPM_PT_VENDOR_STRING_2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the second four characters of the vendor ID string
    /// </para>
    /// </remarks>
    public const uint TPM_PT_VENDOR_STRING_2 = PT_FIXED + 7u;

    /// <summary>
    /// TPM_PT_VENDOR_STRING_3.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the third four characters of the vendor ID string
    /// </para>
    /// </remarks>
    public const uint TPM_PT_VENDOR_STRING_3 = PT_FIXED + 8u;

    /// <summary>
    /// TPM_PT_VENDOR_STRING_4.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the fourth four characters of the vendor ID sting
    /// </para>
    /// </remarks>
    public const uint TPM_PT_VENDOR_STRING_4 = PT_FIXED + 9u;

    /// <summary>
    /// TPM_PT_VENDOR_TPM_TYPE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// vendor-definedvalue indicating the TPM model
    /// </para>
    /// </remarks>
    public const uint TPM_PT_VENDOR_TPM_TYPE = PT_FIXED + 10u;

    /// <summary>
    /// TPM_PT_FIRMWARE_VERSION_1.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the most-significant 32 bits of a TPM vendor-specificvalue indicating the version number of
    /// the firmware. See Clause 10. 12. 2 a nd Clause 10. 12. 12.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_FIRMWARE_VERSION_1 = PT_FIXED + 11u;

    /// <summary>
    /// TPM_PT_FIRMWARE_VERSION_2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the least-significant 32 bits of a TPM vendor-specificvalue indicating the version number of
    /// the firmware. See Clause 10. 12. 2 a nd Clause 10. 12. 12.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_FIRMWARE_VERSION_2 = PT_FIXED + 12u;

    /// <summary>
    /// TPM_PT_INPUT_BUFFER.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum size of a parameter (typically, TPM 2 B_MAX_BUFFER)
    /// </para>
    /// </remarks>
    public const uint TPM_PT_INPUT_BUFFER = PT_FIXED + 13u;

    /// <summary>
    /// TPM_PT_HR_TRANSIENT_MIN.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the minimum number of transient objects thatcan beheld in TPM RAM Thisminimum shall be no
    /// lessthan the minimum value required by the platform-specific specificationto which the TPM
    /// is built.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_TRANSIENT_MIN = PT_FIXED + 14u;

    /// <summary>
    /// TPM_PT_HR_PERSISTENT_MIN.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the minimum number of persistent objects that canbe held in TPM NVmemory Thisminimum shall
    /// be no lessthan the minimum value required by the platform-specific specificationto which the
    /// TPM is built.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_PERSISTENT_MIN = PT_FIXED + 15u;

    /// <summary>
    /// TPM_PT_HR_LOADED_MIN.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the minimum number of authorization sessions thatcan be held in TPMRAM Thisminimum shall be
    /// no lessthan the minimum value required by the platform-specific specificationto which the
    /// TPM is built.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_LOADED_MIN = PT_FIXED + 16u;

    /// <summary>
    /// TPM_PT_ACTIVE_SESSIONS_MAX.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of authorization sessions that may be a ctiveat a time Asession is a ctive when
    /// ithasa context associatedwith its handle. The context may eitherbe in TPM RAM orbe context
    /// saved. Thisvalue shall be no lessthan the minimum value required by the platform-specific
    /// specificationto which the TPM is built.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_ACTIVE_SESSIONS_MAX = PT_FIXED + 17u;

    /// <summary>
    /// TPM_PT_PCR_COUNT.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of PCR implemented Note: Thisnumber is determined by the defined a ttributes,not
    /// the number of PCR thatare populated.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_PCR_COUNT = PT_FIXED + 18u;

    /// <summary>
    /// TPM_PT_PCR_SELECT_MIN.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the minimum number of octets in a TPMS_PCR_SELECT. size Of Select Note: Thisvalue is not
    /// determined by the number of PCR implemented but by the number of PCR required by the
    /// platform-specific specificationwith which the TPM is compliant orby the implementer if not a
    /// dheringto a platform- specificspecification.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_PCR_SELECT_MIN = PT_FIXED + 19u;

    /// <summary>
    /// TPM_PT_CONTEXT_GAP_MAX.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum allowed difference(unsigned) betweenthe context ID value sof two saved
    /// sessioncontexts Thisvalue shall be 2𝑛 − 1,where n is a t least 16.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_CONTEXT_GAP_MAX = PT_FIXED + 20u;

    /// <summary>
    /// TPM_PT_NV_COUNTERS_MAX.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum number of NV Indexes thatare allowedto have the TPM_NT_COUNTER a ttribute Note:
    /// Itis allowed for this value tobe larger than the number of NV Indexes that canbe defined.
    /// This would beindicativeof a TPM implementationthat did not use different
    /// implementationtechnology for different NV Indextypes. Note: Thevalue zero indicates that the
    /// re isno fixed maximum. The number ofcounterindexes is determinedby the a vailable NV memory
    /// pool.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_NV_COUNTERS_MAX = PT_FIXED + 22u;

    /// <summary>
    /// TPM_PT_NV_INDEX_MAX.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum size of a n NVIndexdata area
    /// </para>
    /// </remarks>
    public const uint TPM_PT_NV_INDEX_MAX = PT_FIXED + 23u;

    /// <summary>
    /// TPM_PT_MEMORY.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// a TPMA_MEMORYindicating the memory managementmethod for the TPM
    /// </para>
    /// </remarks>
    public const uint TPM_PT_MEMORY = PT_FIXED + 24u;

    /// <summary>
    /// TPM_PT_CLOCK_UPDATE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// interval,in milliseconds, between updates to the copyof TPMS_CLOCK_INFO. clock in NV
    /// </para>
    /// </remarks>
    public const uint TPM_PT_CLOCK_UPDATE = PT_FIXED + 25u;

    /// <summary>
    /// TPM_PT_CONTEXT_HASH.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the a lgorithm used for the integrity HMACon savedcontexts a nd for hashing the fu Data of
    /// TPM 2_Firmware Read()
    /// </para>
    /// </remarks>
    public const uint TPM_PT_CONTEXT_HASH = PT_FIXED + 26u;

    /// <summary>
    /// TPM_PT_CONTEXT_SYM.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// TPM_ALG_ID,the a lgorithm used for encryption ofsaved contexts
    /// </para>
    /// </remarks>
    public const uint TPM_PT_CONTEXT_SYM = PT_FIXED + 27u;

    /// <summary>
    /// TPM_PT_CONTEXT_SYM_SIZE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// TPM_KEY_BITS,the size of the key used for encryptionof saved contexts
    /// </para>
    /// </remarks>
    public const uint TPM_PT_CONTEXT_SYM_SIZE = PT_FIXED + 28u;

    /// <summary>
    /// TPM_PT_ORDERLY_COUNT.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the modulus - 1 of the countfor NV update of a n orderlycounter Thereturned value is
    /// MAX_ORDERLY_COUNT. Thiswill have a value of 2𝑁 − 1 where 1 ≤ N≤ 32 Note: An"orderly counter"
    /// is a n NV Indexwith a n TPM_NT of TPM_NV_COUNTER a nd TPMA_NV_ORDERLYSET. Note: Whenthe
    /// low-order bits of a counterequal thisvalue, a n NV write occurs onthe next increment.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_ORDERLY_COUNT = PT_FIXED + 29u;

    /// <summary>
    /// TPM_PT_MAX_COMMAND_SIZE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum value forcommand Size ina command
    /// </para>
    /// </remarks>
    public const uint TPM_PT_MAX_COMMAND_SIZE = PT_FIXED + 30u;

    /// <summary>
    /// TPM_PT_MAX_RESPONSE_SIZE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum value forresponse Size inaresponse
    /// </para>
    /// </remarks>
    public const uint TPM_PT_MAX_RESPONSE_SIZE = PT_FIXED + 31u;

    /// <summary>
    /// TPM_PT_MAX_DIGEST.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum size of a digest thatcan be producedby the TPM
    /// </para>
    /// </remarks>
    public const uint TPM_PT_MAX_DIGEST = PT_FIXED + 32u;

    /// <summary>
    /// TPM_PT_MAX_OBJECT_CONTEXT.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum size of a n object contextthat will be returned by TPM 2_Context Save()
    /// </para>
    /// </remarks>
    public const uint TPM_PT_MAX_OBJECT_CONTEXT = PT_FIXED + 33u;

    /// <summary>
    /// TPM_PT_MAX_SESSION_CONTEXT.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum size of asession contextthat will bereturned by TPM 2_Context Save()
    /// </para>
    /// </remarks>
    public const uint TPM_PT_MAX_SESSION_CONTEXT = PT_FIXED + 34u;

    /// <summary>
    /// TPM_PT_PS_FAMILY_INDICATOR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// platform-specificfamily (a TPM_PS value) Note: Theplatform-specific value s for the
    /// TPM_PT_PSparameters are in the relevant platform-specificspecification. In the Reference
    /// Code, all of the se value s are 0.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_PS_FAMILY_INDICATOR = PT_FIXED + 35u;

    /// <summary>
    /// TPM_PT_PS_LEVEL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the level of the platform-specific specification
    /// </para>
    /// </remarks>
    public const uint TPM_PT_PS_LEVEL = PT_FIXED + 36u;

    /// <summary>
    /// TPM_PT_PS_REVISION.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// a platform specific value
    /// </para>
    /// </remarks>
    public const uint TPM_PT_PS_REVISION = PT_FIXED + 37u;

    /// <summary>
    /// TPM_PT_PS_DAY_OF_YEAR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the platform-specific TPM specification day of yearusing TCG calendar Example: November 15,
    /// 2010, has a day ofyear value of 319 (0 x 0000013 F).
    /// </para>
    /// </remarks>
    public const uint TPM_PT_PS_DAY_OF_YEAR = PT_FIXED + 38u;

    /// <summary>
    /// TPM_PT_PS_YEAR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the platform-specific TPM specification year using the CE Example: Theyear 2010 has a value
    /// of 0 x 000007 DA.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_PS_YEAR = PT_FIXED + 39u;

    /// <summary>
    /// TPM_PT_SPLIT_MAX.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of split signing operations supported bythe TPM
    /// </para>
    /// </remarks>
    public const uint TPM_PT_SPLIT_MAX = PT_FIXED + 40u;

    /// <summary>
    /// TPM_PT_TOTAL_COMMANDS.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// totalnumber of command s implemented in the TPM
    /// </para>
    /// </remarks>
    public const uint TPM_PT_TOTAL_COMMANDS = PT_FIXED + 41u;

    /// <summary>
    /// TPM_PT_LIBRARY_COMMANDS.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// number of command s from the TPMlibrarythat areimplemented
    /// </para>
    /// </remarks>
    public const uint TPM_PT_LIBRARY_COMMANDS = PT_FIXED + 42u;

    /// <summary>
    /// TPM_PT_VENDOR_COMMANDS.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// number of vendor command s that are implemented
    /// </para>
    /// </remarks>
    public const uint TPM_PT_VENDOR_COMMANDS = PT_FIXED + 43u;

    /// <summary>
    /// TPM_PT_NV_BUFFER_MAX.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum datasize in one NVwrite, NV read, NVextend, or NV certify command
    /// </para>
    /// </remarks>
    public const uint TPM_PT_NV_BUFFER_MAX = PT_FIXED + 44u;

    /// <summary>
    /// TPM_PT_MODES.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// a TPMA_MODES value, indicating that the TPM isdesigned for the se modes.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_MODES = PT_FIXED + 45u;

    /// <summary>
    /// TPM_PT_MAX_CAP_BUFFER.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the maximum size of a TPMS_CAPABILITY_DATAstructurereturned in TPM 2_Get Capability().
    /// </para>
    /// </remarks>
    public const uint TPM_PT_MAX_CAP_BUFFER = PT_FIXED + 46u;

    /// <summary>
    /// TPM_PT_FIRMWARE_SVN.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the TPM vendor-specific value indicating the SVN ofthe firmware. Thisvalue shall be less
    /// than or equalto UINT 16_MAX.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_FIRMWARE_SVN = PT_FIXED + 47u;

    /// <summary>
    /// TPM_PT_FIRMWARE_MAX_SVN.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the TPM vendor-specific value indicating the maximum value that TPM_PT_FIRMWARE_SVN may take
    /// in the future. intentionallyleft empty
    /// </para>
    /// </remarks>
    public const uint TPM_PT_FIRMWARE_MAX_SVN = PT_FIXED + 48u;

    /// <summary>
    /// TPM_PT_PERMANENT.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// TPMA_PERMANENT
    /// </para>
    /// </remarks>
    public const uint TPM_PT_PERMANENT = PT_VAR + 0u;

    /// <summary>
    /// TPM_PT_STARTUP_CLEAR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// TPMA_STARTUP_CLEAR
    /// </para>
    /// </remarks>
    public const uint TPM_PT_STARTUP_CLEAR = PT_VAR + 1u;

    /// <summary>
    /// TPM_PT_HR_NV_INDEX.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of NV Indexes currently defined
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_NV_INDEX = PT_VAR + 2u;

    /// <summary>
    /// TPM_PT_HR_LOADED.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of authorization sessions currently loadedinto TPM RAM
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_LOADED = PT_VAR + 3u;

    /// <summary>
    /// TPM_PT_HR_LOADED_AVAIL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of a dditional authorization sessions, ofany type, which could beloadedinto TPM
    /// RAM Thisvalue is a n estimate. If this value is a tleast 1,the n a t least one authorization
    /// sessionof anytype may be loaded. Any command that changesthe RAM memory allocation can make
    /// thisestimate invalid. Example: Avalid implementation is permitted to return 1 even if more
    /// than one authorizationsession wouldfit into RAM.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_LOADED_AVAIL = PT_VAR + 4u;

    /// <summary>
    /// TPM_PT_HR_ACTIVE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of a ctive authorization sessions currentlybeing tracked by the TPM Thisis the
    /// sum of the loaded a nd saved sessions.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_ACTIVE = PT_VAR + 5u;

    /// <summary>
    /// TPM_PT_HR_ACTIVE_AVAIL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of a dditional authorization sessions, ofany type, which could becreated
    /// Thisvalue is a n estimate. If this value is a tleast 1,the n a t least one authorization
    /// sessionof anytype may be created. Any command that changesthe RAM memory allocation can make
    /// thisestimate invalid. Example: Avalid implementation is permitted to return 1 even if more
    /// than one authorizationsession couldbe created.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_ACTIVE_AVAIL = PT_VAR + 6u;

    /// <summary>
    /// TPM_PT_HR_TRANSIENT_AVAIL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// estimateof the number of a dditional transient objectsthat could be loaded into TPMRAM
    /// Thisvalue is a n estimate. If this value is a tleast 1,the n a t least one object ofany type
    /// may be loaded. Any command thatchanges the memory allocationcan make this estimate invalid.
    /// Example: Avalid implementation is permitted to return 1 even if more than one
    /// transientobject wouldfit into RAM.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_TRANSIENT_AVAIL = PT_VAR + 7u;

    /// <summary>
    /// TPM_PT_HR_PERSISTENT.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of persistent objects currently loaded into TPM NV memory
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_PERSISTENT = PT_VAR + 8u;

    /// <summary>
    /// TPM_PT_HR_PERSISTENT_AVAIL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of a dditional persistent objects that couldbe loaded into NV memory Thisvalue is
    /// a n estimate. If this value is a tleast 1,the n a t least one object ofany type may be
    /// madepersistent. Any command that changes the NVmemory allocation can make this estimate
    /// invalid. Example: Avalid implementation is permitted to return 1 even if more than one
    /// persistentobject wouldfit into NV memory.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_HR_PERSISTENT_AVAIL = PT_VAR + 9u;

    /// <summary>
    /// TPM_PT_NV_COUNTERS.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of defined NV Indexes thathave the TPM_NT_COUNTERattribute
    /// </para>
    /// </remarks>
    public const uint TPM_PT_NV_COUNTERS = PT_VAR + 10u;

    /// <summary>
    /// TPM_PT_NV_COUNTERS_AVAIL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of a dditional NV Indexes thatcan be defined with the ir TPM_NT of TPM_NV_COUNTER
    /// a nd the TPMA_NV_ORDERLYattribute SET Thisvalue is a n estimate. If this value is a tleast
    /// 1,the n a t least one NV Indexmay be created witha TPM_NT of TPM_NV_COUNTER a nd the
    /// TPMA_NV_ORDERLYattributes. Anycommand thatchanges the NV memory allocation canmake
    /// thisestimate invalid. Example: Avalid implementation is permitted to return 1 even if more
    /// than one NVcounter could be defined.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_NV_COUNTERS_AVAIL = PT_VAR + 11u;

    /// <summary>
    /// TPM_PT_ALGORITHM_SET.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// codethat limits the a lgorithms that may be used withthe TPM
    /// </para>
    /// </remarks>
    public const uint TPM_PT_ALGORITHM_SET = PT_VAR + 12u;

    /// <summary>
    /// TPM_PT_LOADED_CURVES.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of loaded ECC curves
    /// </para>
    /// </remarks>
    public const uint TPM_PT_LOADED_CURVES = PT_VAR + 13u;

    /// <summary>
    /// TPM_PT_LOCKOUT_COUNTER.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the current value of the lockout counter (failed Tries)
    /// </para>
    /// </remarks>
    public const uint TPM_PT_LOCKOUT_COUNTER = PT_VAR + 14u;

    /// <summary>
    /// TPM_PT_MAX_AUTH_FAIL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of authorization failures before DA lockoutis invoked
    /// </para>
    /// </remarks>
    public const uint TPM_PT_MAX_AUTH_FAIL = PT_VAR + 15u;

    /// <summary>
    /// TPM_PT_LOCKOUT_INTERVAL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of seconds before the value reportedby TPM_PT_LOCKOUT_COUNTER isdecremented
    /// </para>
    /// </remarks>
    public const uint TPM_PT_LOCKOUT_INTERVAL = PT_VAR + 16u;

    /// <summary>
    /// TPM_PT_LOCKOUT_RECOVERY.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the number of seconds a fter a lockout Authfailure beforeuse of lockout Auth may be a
    /// ttempted a gain
    /// </para>
    /// </remarks>
    public const uint TPM_PT_LOCKOUT_RECOVERY = PT_VAR + 17u;

    /// <summary>
    /// TPM_PT_NV_WRITE_RECOVERY.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// number of milliseconds before the TPM will a cceptanother command that will modify NV
    /// Thisvalue is a n a pproximation a ndmay go up or downover time.
    /// </para>
    /// </remarks>
    public const uint TPM_PT_NV_WRITE_RECOVERY = PT_VAR + 18u;

    /// <summary>
    /// TPM_PT_AUDIT_COUNTER_0.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the high-order 32 bits of the command audit counter
    /// </para>
    /// </remarks>
    public const uint TPM_PT_AUDIT_COUNTER_0 = PT_VAR + 19u;

    /// <summary>
    /// TPM_PT_AUDIT_COUNTER_1.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Specification (Comments column):
    /// the low-order 32 bits of the command audit counter
    /// </para>
    /// </remarks>
    public const uint TPM_PT_AUDIT_COUNTER_1 = PT_VAR + 20u;

}