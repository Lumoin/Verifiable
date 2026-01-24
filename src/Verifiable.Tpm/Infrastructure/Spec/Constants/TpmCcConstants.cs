using System;

namespace Verifiable.Tpm.Structures.Spec.Constants;

/// <summary>
/// TPM_CC constants (command codes).
/// </summary>
/// <remarks>
/// <para>
/// Purpose: Identifiers for TPM 2.0 commands (command codes).
/// </para>
/// <para>
/// Specification: TPM 2.0 Library Specification (Part 2: Structures), section "6.5 TPM_CC" (Table 15).
/// </para>
/// <para>
/// Note: TPM_CC_HMAC/TPM_CC_HMAC_Start share values with TPM_CC_MAC/TPM_CC_MAC_Start (mutually
/// exclusive implementations).
/// </para>
/// </remarks>
public enum TpmCcConstants : uint
{
    /// <summary>
    /// compile variable May decrease based on implementation.
    /// </summary>
    TPM_CC_FIRST = 0x0000011F,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_UndefineSpaceSpecial = 0x0000011F,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_EvictControl = 0x00000120,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_HierarchyControl = 0x00000121,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_UndefineSpace = 0x00000122,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ChangeEPS = 0x00000124,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ChangePPS = 0x00000125,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Clear = 0x00000126,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ClearControl = 0x00000127,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ClockSet = 0x00000128,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_HierarchyChangeAuth = 0x00000129,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_DefineSpace = 0x0000012A,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_PCR_Allocate = 0x0000012B,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_PCR_SetAuthPolicy = 0x0000012C,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_PP_Commands = 0x0000012D,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_SetPrimaryPolicy = 0x0000012E,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_FieldUpgradeStart = 0x0000012F,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ClockRateAdjust = 0x00000130,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_CreatePrimary = 0x00000131,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_GlobalWriteLock = 0x00000132,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_GetCommandAuditDigest = 0x00000133,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_Increment = 0x00000134,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_SetBits = 0x00000135,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_Extend = 0x00000136,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_Write = 0x00000137,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_WriteLock = 0x00000138,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_DictionaryAttackLockReset = 0x00000139,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_DictionaryAttackParameters = 0x0000013A,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_ChangeAuth = 0x0000013B,

    /// <summary>
    /// PCR
    /// </summary>
    TPM_CC_PCR_Event = 0x0000013C,

    /// <summary>
    /// PCR
    /// </summary>
    TPM_CC_PCR_Reset = 0x0000013D,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_SequenceComplete = 0x0000013E,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_SetAlgorithmSet = 0x0000013F,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_SetCommandCodeAuditStatus = 0x00000140,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_FieldUpgradeData = 0x00000141,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_IncrementalSelfTest = 0x00000142,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_SelfTest = 0x00000143,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Startup = 0x00000144,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Shutdown = 0x00000145,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_StirRandom = 0x00000146,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ActivateCredential = 0x00000147,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Certify = 0x00000148,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyNV = 0x00000149,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_CertifyCreation = 0x0000014A,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Duplicate = 0x0000014B,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_GetTime = 0x0000014C,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_GetSessionAuditDigest = 0x0000014D,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_Read = 0x0000014E,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_ReadLock = 0x0000014F,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ObjectChangeAuth = 0x00000150,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicySecret = 0x00000151,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Rewrap = 0x00000152,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Create = 0x00000153,

    /// <summary>
    /// ECC
    /// </summary>
    TPM_CC_ECDH_ZGen = 0x00000154,

    /// <summary>
    /// see NOTE below
    /// </summary>
    TPM_CC_HMAC = 0x00000155,

    /// <summary>
    /// see NOTE below
    /// </summary>
    TPM_CC_MAC = 0x00000155,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Import = 0x00000156,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Load = 0x00000157,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Quote = 0x00000158,

    /// <summary>
    /// RSA
    /// </summary>
    TPM_CC_RSA_Decrypt = 0x00000159,

    /// <summary>
    /// see NOTE below
    /// </summary>
    TPM_CC_HMAC_Start = 0x0000015B,

    /// <summary>
    /// see NOTE below
    /// </summary>
    TPM_CC_MAC_Start = 0x0000015B,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_SequenceUpdate = 0x0000015C,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Sign = 0x0000015D,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Unseal = 0x0000015E,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicySigned = 0x00000160,

    /// <summary>
    /// Context
    /// </summary>
    TPM_CC_ContextLoad = 0x00000161,

    /// <summary>
    /// Context
    /// </summary>
    TPM_CC_ContextSave = 0x00000162,

    /// <summary>
    /// ECC
    /// </summary>
    TPM_CC_ECDH_KeyGen = 0x00000163,

    /// <summary>
    /// Deprecated. See Part 0.
    /// </summary>
    TPM_CC_EncryptDecrypt = 0x00000164,

    /// <summary>
    /// Context
    /// </summary>
    TPM_CC_FlushContext = 0x00000165,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_LoadExternal = 0x00000167,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_MakeCredential = 0x00000168,

    /// <summary>
    /// NV
    /// </summary>
    TPM_CC_NV_ReadPublic = 0x00000169,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyAuthorize = 0x0000016A,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyAuthValue = 0x0000016B,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyCommandCode = 0x0000016C,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyCounterTimer = 0x0000016D,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyCpHash = 0x0000016E,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyLocality = 0x0000016F,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyNameHash = 0x00000170,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyOR = 0x00000171,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyTicket = 0x00000172,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ReadPublic = 0x00000173,

    /// <summary>
    /// RSA
    /// </summary>
    TPM_CC_RSA_Encrypt = 0x00000174,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_StartAuthSession = 0x00000176,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_VerifySignature = 0x00000177,

    /// <summary>
    /// ECC
    /// </summary>
    TPM_CC_ECC_Parameters = 0x00000178,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_FirmwareRead = 0x00000179,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_GetCapability = 0x0000017A,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_GetRandom = 0x0000017B,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_GetTestResult = 0x0000017C,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_Hash = 0x0000017D,

    /// <summary>
    /// PCR
    /// </summary>
    TPM_CC_PCR_Read = 0x0000017E,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyPCR = 0x0000017F,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_PolicyRestart = 0x00000180,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ReadClock = 0x00000181,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_PCR_Extend = 0x00000182,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_PCR_SetAuthValue = 0x00000183,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_Certify = 0x00000184,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_EventSequenceComplete = 0x00000185,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_HashSequenceStart = 0x00000186,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyPhysicalPresence = 0x00000187,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyDuplicationSelect = 0x00000188,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyGetDigest = 0x00000189,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_TestParms = 0x0000018A,

    /// <summary>
    /// ECC
    /// </summary>
    TPM_CC_Commit = 0x0000018B,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyPassword = 0x0000018C,

    /// <summary>
    /// ECC
    /// </summary>
    TPM_CC_ZGen_2Phase = 0x0000018D,

    /// <summary>
    /// ECC
    /// </summary>
    TPM_CC_EC_Ephemeral = 0x0000018E,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyNvWritten = 0x0000018F,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyTemplate = 0x00000190,

    /// <summary>
    /// Deprecated. See Part 0.
    /// </summary>
    TPM_CC_CreateLoaded = 0x00000191,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyAuthorizeNV = 0x00000192,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_EncryptDecrypt2 = 0x00000193,

    /// <summary>
    /// Deprecated. See Part 0.
    /// </summary>
    TPM_CC_AC_GetCapability = 0x00000194,

    /// <summary>
    /// Deprecated. See Part 0.
    /// </summary>
    TPM_CC_AC_Send = 0x00000195,

    /// <summary>
    /// Deprecated. See Part 0.
    /// </summary>
    TPM_CC_Policy_AC_SendSelect = 0x00000196,

    /// <summary>
    /// Deprecated. See Part 0.
    /// </summary>
    TPM_CC_CertifyX509 = 0x00000197,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ACT_SetTimeout = 0x00000198,

    /// <summary>
    /// ECC
    /// </summary>
    TPM_CC_ECC_Encrypt = 0x00000199,

    /// <summary>
    /// ECC
    /// </summary>
    TPM_CC_ECC_Decrypt = 0x0000019A,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyCapability = 0x0000019B,

    /// <summary>
    /// Policy
    /// </summary>
    TPM_CC_PolicyParameters = 0x0000019C,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_DefineSpace2 = 0x0000019D,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_NV_ReadPublic2 = 0x0000019E,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_SetCapability = 0x0000019F,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_ReadOnlyControl = 0x000001A0,

    /// <summary>
    /// Command code.
    /// </summary>
    TPM_CC_PolicyTransportSPDM = 0x000001A1,

    /// <summary>
    /// Compile variable. May increase based on implementation.
    /// </summary>
    TPM_CC_LAST = 0x000001A1,

    /// <summary>
    /// Command code.
    /// </summary>
    CC_VEND = 0x20000000,

    /// <summary>
    /// used for testing of command dispatch
    /// </summary>
    TPM_CC_Vendor_TCG_Test = CC_VEND+0x000

}