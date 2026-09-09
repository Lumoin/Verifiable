using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Provides extension accessors for discovering available TPM response codecs.
/// </summary>
/// <remarks>
/// <para>
/// This extension class allows accessing response codecs using a clean, discoverable
/// syntax directly on the <see cref="TpmResponseCodec"/> type. Instead of defining
/// separate parser classes, codecs are accessed through the base type with
/// IntelliSense support.
/// </para>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <code>
/// //Register a codec for GetRandom.
/// registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
///
/// //All available codecs are discoverable via IntelliSense.
/// registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);
/// </code>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with latest syntax.")]
public static class TpmResponseCodecExtensions
{
    extension(TpmResponseCodec)
    {
        /// <summary>
        /// Codec for TPM2_GetRandom response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>TPM2B_DIGEST randomBytes - the random data.</description></item>
        /// </list>
        /// <para>
        /// The first (and only) response parameter, <c>randomBytes</c>, is a <c>TPM2B_DIGEST</c> sized buffer,
        /// so it is eligible for session-based parameter encryption (the <c>encrypt</c> attribute).
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 16.1 - TPM2_GetRandom.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec GetRandom => TpmResponseCodec.Create(
            GetRandomResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_StartAuthSession response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response handles:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>sessionHandle (TPMI_SH_AUTH_SESSION) - handle for the created session.</description></item>
        /// </list>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>nonceTPM (TPM2B_NONCE) - TPM's nonce for the session.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 11.1 - TPM2_StartAuthSession.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec StartAuthSession => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, BaseMemoryPool pool) =>
                StartAuthSessionResponse.Parse(ref reader, TpmiShAuthSession.FromValue(handle), pool));

        /// <summary>
        /// Codec for TPM2_FlushContext response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This command has no response handles and no response parameters.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 28.4 - TPM2_FlushContext.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec FlushContext => TpmResponseCodec.NoParameters(FlushContextResponse.Instance);

        /// <summary>
        /// Codec for TPM2_ContextSave response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This command has no response handles.
        /// </para>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>context (TPMS_CONTEXT) - the saved context.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 28.2 - TPM2_ContextSave.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec ContextSave => TpmResponseCodec.Create(
            ContextSaveResponse.Parse, responseFirstParameterIsEncryptable: false);

        /// <summary>
        /// Codec for TPM2_ContextLoad response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response handle: loadedHandle (TPM_HANDLE). No response parameters — nothing is read from the
        /// parameter area at all.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 28.3 - TPM2_ContextLoad.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec ContextLoad => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, BaseMemoryPool pool) => ContextLoadResponse.Parse(handle));

        /// <summary>
        /// Codec for TPM2_PolicyCommandCode response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This command has no response handles and no response parameters.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 23.11 - TPM2_PolicyCommandCode.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PolicyCommandCode => TpmResponseCodec.NoParameters(PolicyCommandCodeResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyAuthValue response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This command has no response handles and no response parameters.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 23.17 - TPM2_PolicyAuthValue.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PolicyAuthValue => TpmResponseCodec.NoParameters(PolicyAuthValueResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyPCR response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This command has no response handles and no response parameters.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 23.7 - TPM2_PolicyPCR.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PolicyPcr => TpmResponseCodec.NoParameters(PolicyPcrResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyOR response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, clause 23.6).
        /// </summary>
        public static TpmResponseCodec PolicyOr => TpmResponseCodec.NoParameters(PolicyOrResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyNV response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, clause 23.9).
        /// </summary>
        public static TpmResponseCodec PolicyNv => TpmResponseCodec.NoParameters(PolicyNvResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyCounterTimer response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 23.10).
        /// </summary>
        public static TpmResponseCodec PolicyCounterTimer => TpmResponseCodec.NoParameters(PolicyCounterTimerResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyPassword response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 23.18).
        /// </summary>
        public static TpmResponseCodec PolicyPassword => TpmResponseCodec.NoParameters(PolicyPasswordResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyRestart response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 11.2, Table 16).
        /// </summary>
        public static TpmResponseCodec PolicyRestart => TpmResponseCodec.NoParameters(PolicyRestartResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyLocality response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 23.8, Table 154).
        /// </summary>
        public static TpmResponseCodec PolicyLocality => TpmResponseCodec.NoParameters(PolicyLocalityResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyCpHash response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 23.13, Table 164).
        /// </summary>
        public static TpmResponseCodec PolicyCpHash => TpmResponseCodec.NoParameters(PolicyCpHashResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyNameHash response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 23.14, Table 166).
        /// </summary>
        public static TpmResponseCodec PolicyNameHash => TpmResponseCodec.NoParameters(PolicyNameHashResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyDuplicationSelect response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 23.15, Table 169).
        /// </summary>
        public static TpmResponseCodec PolicyDuplicationSelect => TpmResponseCodec.NoParameters(PolicyDuplicationSelectResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyParameters response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 23.24, Table 188).
        /// </summary>
        public static TpmResponseCodec PolicyParameters => TpmResponseCodec.NoParameters(PolicyParametersResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyTemplate response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 23.21, Table 180).
        /// </summary>
        public static TpmResponseCodec PolicyTemplate => TpmResponseCodec.NoParameters(PolicyTemplateResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyNvWritten response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 23.20, Table 178).
        /// </summary>
        public static TpmResponseCodec PolicyNvWritten => TpmResponseCodec.NoParameters(PolicyNvWrittenResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyAuthorizeNV response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 23.22, Table 182).
        /// </summary>
        public static TpmResponseCodec PolicyAuthorizeNv => TpmResponseCodec.NoParameters(PolicyAuthorizeNvResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyGetDigest response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>policyDigest (TPM2B_DIGEST) - the session's current policy digest.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 23.19 - TPM2_PolicyGetDigest.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PolicyGetDigest => TpmResponseCodec.Create(PolicyGetDigestResponse.Parse);

        /// <summary>
        /// Codec for TPM2_PolicySecret response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>timeout (TPM2B_TIMEOUT) - empty in the immediate (expiration 0) form.</description></item>
        ///   <item><description>policyTicket (TPMT_TK_AUTH) - a NULL ticket in the immediate form.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 23.4 - TPM2_PolicySecret.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PolicySecret => TpmResponseCodec.Create(PolicySecretResponse.Parse);

        /// <summary>
        /// Codec for TPM2_PolicySigned response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>timeout (TPM2B_TIMEOUT) - empty; the real ticket mint is deferred.</description></item>
        ///   <item><description>policyTicket (TPMT_TK_AUTH) - a NULL ticket; the real mint is deferred.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 23.3 - TPM2_PolicySigned.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PolicySigned => TpmResponseCodec.Create(PolicySignedResponse.Parse);

        /// <summary>
        /// Codec for TPM2_PolicyTicket response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, clause 23.5).
        /// </summary>
        public static TpmResponseCodec PolicyTicket => TpmResponseCodec.NoParameters(PolicyTicketResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyAuthorize response.
        /// </summary>
        /// <remarks>
        /// TPM2_PolicyAuthorize has no response parameters beyond the header (TPM 2.0 Library Part 3, clause 23.16).
        /// </remarks>
        public static TpmResponseCodec PolicyAuthorize => TpmResponseCodec.NoParameters(PolicyAuthorizeResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_DefineSpace response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 31.3).
        /// </summary>
        public static TpmResponseCodec NvDefineSpace => TpmResponseCodec.NoParameters(NvDefineSpaceResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_Read response.
        /// </summary>
        /// <remarks>
        /// Response parameters: data (TPM2B_MAX_NV_BUFFER). See TPM 2.0 Library Part 3, clause 31.13.
        /// </remarks>
        public static TpmResponseCodec NvRead => TpmResponseCodec.Create(NvReadResponse.Parse);

        /// <summary>
        /// Codec for TPM2_NV_Write response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, clause 31.7).
        /// </summary>
        public static TpmResponseCodec NvWrite => TpmResponseCodec.NoParameters(NvWriteResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_UndefineSpace response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 31.4).
        /// </summary>
        public static TpmResponseCodec NvUndefineSpace => TpmResponseCodec.NoParameters(NvUndefineSpaceResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_UndefineSpaceSpecial response. This command has no response handles and no
        /// response parameters (TPM 2.0 Library Part 3, clause 31.5, Table 250).
        /// </summary>
        public static TpmResponseCodec NvUndefineSpaceSpecial => TpmResponseCodec.NoParameters(NvUndefineSpaceSpecialResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_ChangeAuth response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 31.15).
        /// </summary>
        public static TpmResponseCodec NvChangeAuth => TpmResponseCodec.NoParameters(NvChangeAuthResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_Increment response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 31.8).
        /// </summary>
        public static TpmResponseCodec NvIncrement => TpmResponseCodec.NoParameters(NvIncrementResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_Extend response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 31.9).
        /// </summary>
        public static TpmResponseCodec NvExtend => TpmResponseCodec.NoParameters(NvExtendResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_SetBits response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 31.10).
        /// </summary>
        public static TpmResponseCodec NvSetBits => TpmResponseCodec.NoParameters(NvSetBitsResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_WriteLock response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 31.11).
        /// </summary>
        public static TpmResponseCodec NvWriteLock => TpmResponseCodec.NoParameters(NvWriteLockResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_ReadLock response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 31.14).
        /// </summary>
        public static TpmResponseCodec NvReadLock => TpmResponseCodec.NoParameters(NvReadLockResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_GlobalWriteLock response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 31.12).
        /// </summary>
        public static TpmResponseCodec NvGlobalWriteLock => TpmResponseCodec.NoParameters(NvGlobalWriteLockResponse.Instance);

        /// <summary>
        /// Codec for TPM2_EvictControl response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, clause 28.5).
        /// </summary>
        public static TpmResponseCodec EvictControl => TpmResponseCodec.NoParameters(EvictControlResponse.Instance);

        /// <summary>
        /// Codec for TPM2_CreatePrimary response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response handles:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>objectHandle (TPM_HANDLE) - handle for the created object.</description></item>
        /// </list>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outPublic (TPM2B_PUBLIC) - the public area of the created object.</description></item>
        ///   <item><description>creationData (TPM2B_CREATION_DATA) - creation data.</description></item>
        ///   <item><description>creationHash (TPM2B_DIGEST) - digest of creationData.</description></item>
        ///   <item><description>creationTicket (TPMT_TK_CREATION) - ticket for proof of creation.</description></item>
        ///   <item><description>name (TPM2B_NAME) - the name of the created object.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 24.1 - TPM2_CreatePrimary.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec CreatePrimary => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, BaseMemoryPool pool) =>
                CreatePrimaryResponse.Parse(ref reader, TpmiDhObject.FromValue(handle), pool));

        /// <summary>
        /// Codec for TPM2_Create response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// No response handle (the created object is not loaded). Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outPrivate (TPM2B_PRIVATE) - the parent-wrapped private blob.</description></item>
        ///   <item><description>outPublic (TPM2B_PUBLIC) - the public area of the created object.</description></item>
        ///   <item><description>creationData (TPM2B_CREATION_DATA), creationHash (TPM2B_DIGEST), creationTicket (TPMT_TK_CREATION).</description></item>
        /// </list>
        /// <para>
        /// Named <c>CreateObject</c> rather than <c>Create</c> to avoid colliding with the
        /// <see cref="TpmResponseCodec.Create{TResponse}"/> factory. See TPM 2.0 Library Part 3, clause 12.1.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec CreateObject => TpmResponseCodec.Create(CreateResponse.Parse);

        /// <summary>
        /// Codec for TPM2_Load response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response handle: objectHandle (TPMI_DH_OBJECT). Response parameters: name (TPM2B_NAME).
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 12.2 - TPM2_Load.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Load => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, BaseMemoryPool pool) =>
                LoadResponse.Parse(ref reader, TpmiDhObject.FromValue(handle), pool));

        /// <summary>
        /// Codec for TPM2_LoadExternal response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response handle: objectHandle (TPMI_DH_OBJECT). Response parameters: name (TPM2B_NAME).
        /// </para>
        /// <para>
        /// <c>name</c> is a sized buffer and so is eligible for session-based encrypt parameter protection
        /// (TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 12.3, Table 22's zero-handle session table
        /// admitting an independent encrypt claim on it).
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 12.3 - TPM2_LoadExternal.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec LoadExternal => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, BaseMemoryPool pool) =>
                LoadExternalResponse.Parse(ref reader, TpmiDhObject.FromValue(handle), pool),
            responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_ObjectChangeAuth response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outPrivate (TPM2B_PRIVATE) - the object's sensitive area re-wrapped under its parent with the new authorization value.</description></item>
        /// </list>
        /// <para>
        /// <c>outPrivate</c> is a sized buffer and the response's first parameter, so it is eligible for
        /// session-based encrypt parameter protection (TPM 2.0 Library Part 1, clause 18.1). See TPM 2.0 Part 3,
        /// clause 12.8 - TPM2_ObjectChangeAuth.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec ObjectChangeAuth => TpmResponseCodec.Create(ObjectChangeAuthResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_RSA_Encrypt response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outData (TPM2B_PUBLIC_KEY_RSA) - the encrypted output.</description></item>
        /// </list>
        /// <para>
        /// <c>outData</c> is a sized buffer and the response's first (and only) parameter, so it is eligible for
        /// session-based encrypt parameter protection (TPM 2.0 Library Part 1, clause 18.1). See TPM 2.0 Part 3,
        /// clause 14.2 - TPM2_RSA_Encrypt.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec RsaEncrypt => TpmResponseCodec.Create(RsaEncryptResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_RSA_Decrypt response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>message (TPM2B_PUBLIC_KEY_RSA) - the decrypted output.</description></item>
        /// </list>
        /// <para>
        /// <c>message</c> is a sized buffer and the response's first (and only) parameter, so it is eligible for
        /// session-based encrypt parameter protection (TPM 2.0 Library Part 1, clause 18.1). See TPM 2.0 Part 3,
        /// clause 14.3 - TPM2_RSA_Decrypt.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec RsaDecrypt => TpmResponseCodec.Create(RsaDecryptResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_GetCapability response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>moreData (TPMI_YES_NO) - flag indicating more data is available.</description></item>
        ///   <item><description>capabilityData (TPMS_CAPABILITY_DATA) - the capability data.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 30.2 - TPM2_GetCapability.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec GetCapability => TpmResponseCodec.Create(
            GetCapabilityResponse.Parse);

        /// <summary>
        /// Codec for TPM2_PCR_Read response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>pcrUpdateCounter (UINT32) - current value of PCR update counter.</description></item>
        ///   <item><description>pcrSelectionOut (TPML_PCR_SELECTION) - PCRs that were read.</description></item>
        ///   <item><description>pcrValues (TPML_DIGEST) - the PCR values.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 22.4 - TPM2_PCR_Read.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PcrRead => TpmResponseCodec.Create(PcrReadResponse.Parse);

        /// <summary>
        /// Codec for TPM2_PCR_Extend response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters: none (Table 131) — the named register has been extended with every listed digest
        /// whose bank is implemented.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 22.2, Table 131 - TPM2_PCR_Extend.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PcrExtend => TpmResponseCodec.NoParameters(PcrExtendResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PCR_Event response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>digests (TPML_DIGEST_VALUES) - the tagged digests of the event data, one per bank; a list, not a TPM2B, so not encryptable.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 22.3, Table 133 - TPM2_PCR_Event.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PcrEvent => TpmResponseCodec.Create(PcrEventResponse.Parse);

        /// <summary>
        /// Codec for TPM2_PCR_Reset response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters: none (Table 143) — the named register reads all zeros in every bank.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 22.8, Table 143 - TPM2_PCR_Reset.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PcrReset => TpmResponseCodec.NoParameters(PcrResetResponse.Instance);

        /// <summary>
        /// Codec for TPM2_EventSequenceComplete response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>results (TPML_DIGEST_VALUES) - the tagged digests of the whole event, one per implemented hash algorithm; a list, not a TPM2B, so not encryptable.</description></item>
        /// </list>
        /// <para>
        /// On success, the sequence context named by the request's <c>sequenceHandle</c> is flushed from the
        /// TPM (TPM 2.0 Library Part 3, clause 17.9.1).
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 17.9, Table 96 - TPM2_EventSequenceComplete.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec EventSequenceComplete => TpmResponseCodec.Create(EventSequenceCompleteResponse.Parse);

        /// <summary>
        /// Codec for TPM2_Sign response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>signature (TPMT_SIGNATURE) - sigAlg (2) selecting a TPMU_SIGNATURE member: ECDSA (hash + TPM2B_ECC_PARAMETER(r) + TPM2B_ECC_PARAMETER(s)) or RSASSA/RSAPSS (hash + TPM2B_PUBLIC_KEY_RSA).</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 20.5 - TPM2_Sign.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Sign => TpmResponseCodec.Create(SignResponse.Parse);

        /// <summary>
        /// Codec for TPM2_SignDigest response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>signature (TPMT_SIGNATURE) - sigAlg (2) selecting a TPMU_SIGNATURE member: ECDSA (hash + TPM2B_ECC_PARAMETER(r) + TPM2B_ECC_PARAMETER(s)) or RSASSA/RSAPSS (hash + TPM2B_PUBLIC_KEY_RSA).</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 20.7, Table 127 - TPM2_SignDigest.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec SignDigest => TpmResponseCodec.Create(SignDigestResponse.Parse);

        /// <summary>
        /// Codec for TPM2_SignSequenceStart response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response handle:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>sequenceHandle (TPMI_DH_OBJECT) - the handle of the newly opened sequence object.</description></item>
        /// </list>
        /// <para>
        /// No response parameters.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 17.5, Table 88 - TPM2_SignSequenceStart.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec SignSequenceStart => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, BaseMemoryPool pool) =>
                SignSequenceStartResponse.Parse(ref reader, TpmiDhObject.FromValue(handle), pool));

        /// <summary>
        /// Codec for TPM2_SequenceUpdate response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 17.7, Table 92).
        /// </summary>
        public static TpmResponseCodec SequenceUpdate => TpmResponseCodec.NoParameters(SequenceUpdateResponse.Instance);

        /// <summary>
        /// Codec for TPM2_SignSequenceComplete response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>signature (TPMT_SIGNATURE) - sigAlg (2) selecting a TPMU_SIGNATURE member: ECDSA (hash + TPM2B_ECC_PARAMETER(r) + TPM2B_ECC_PARAMETER(s)) or RSASSA/RSAPSS (hash + TPM2B_PUBLIC_KEY_RSA).</description></item>
        /// </list>
        /// <para>
        /// On success, the sequence context named by the request's <c>sequenceHandle</c> is flushed from the
        /// TPM (TPM 2.0 Library Part 1, clause 29.4.6).
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 20.6, Table 125 - TPM2_SignSequenceComplete.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec SignSequenceComplete => TpmResponseCodec.Create(SignSequenceCompleteResponse.Parse);

        /// <summary>
        /// Codec for TPM2_HashSequenceStart response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response handle:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>sequenceHandle (TPMI_DH_OBJECT) - the handle of the newly opened hash or Event Sequence context.</description></item>
        /// </list>
        /// <para>
        /// No response parameters.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 17.4, Table 86 - TPM2_HashSequenceStart.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec HashSequenceStart => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, BaseMemoryPool pool) =>
                HashSequenceStartResponse.Parse(ref reader, TpmiDhObject.FromValue(handle), pool));

        /// <summary>
        /// Codec for TPM2_SequenceComplete response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>result (TPM2B_DIGEST) - the digest or HMAC of the whole sequence; the first response parameter, encryptable.</description></item>
        ///   <item><description>validation (TPMT_TK_HASHCHECK) - tag + hierarchy + TPM2B_DIGEST; the NULL Ticket when no ticket was minted.</description></item>
        /// </list>
        /// <para>
        /// On success, the sequence context named by the request's <c>sequenceHandle</c> is flushed from the
        /// TPM (TPM 2.0 Library Part 1, clause 29.4.6).
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 17.8, Table 94 - TPM2_SequenceComplete.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec SequenceComplete => TpmResponseCodec.Create(SequenceCompleteResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_Hash response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outHash (TPM2B_DIGEST) - the digest of the data; the first response parameter, encryptable.</description></item>
        ///   <item><description>validation (TPMT_TK_HASHCHECK) - tag + hierarchy + TPM2B_DIGEST; the NULL Ticket when no ticket was minted.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 15.4, Table 70 - TPM2_Hash.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Hash => TpmResponseCodec.Create(HashResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_HMAC_Start response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response handle:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>sequenceHandle (TPMI_DH_OBJECT) - the handle of the newly opened HMAC sequence context.</description></item>
        /// </list>
        /// <para>
        /// No response parameters.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 17.2, Table 81 - TPM2_HMAC_Start.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec HmacStart => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, BaseMemoryPool pool) =>
                HmacStartResponse.Parse(ref reader, TpmiDhObject.FromValue(handle), pool));

        /// <summary>
        /// Codec for TPM2_HMAC response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outHMAC (TPM2B_DIGEST) - the HMAC of the data; the first response parameter, encryptable.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 15.5, Table 72 - TPM2_HMAC.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Hmac => TpmResponseCodec.Create(HmacResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_VerifySequenceStart response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response handle:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>sequenceHandle (TPMI_DH_OBJECT) - the handle of the newly opened sequence object.</description></item>
        /// </list>
        /// <para>
        /// No response parameters.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 17.6, Table 90 - TPM2_VerifySequenceStart.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec VerifySequenceStart => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, BaseMemoryPool pool) =>
                VerifySequenceStartResponse.Parse(ref reader, TpmiDhObject.FromValue(handle), pool));

        /// <summary>
        /// Codec for TPM2_VerifySequenceComplete response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>validation (TPMT_TK_VERIFIED) - the validation ticket, tagged TPM_ST_MESSAGE_VERIFIED.</description></item>
        /// </list>
        /// <para>
        /// On success, the sequence context named by the request's <c>sequenceHandle</c> is flushed from the
        /// TPM (TPM 2.0 Library Part 1, clause 29.4.6).
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 20.3, Table 119 - TPM2_VerifySequenceComplete.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec VerifySequenceComplete => TpmResponseCodec.Create(VerifySequenceCompleteResponse.Parse);

        /// <summary>
        /// Codec for TPM2_Quote response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>quoted (TPM2B_ATTEST) - the signed attestation (a marshaled TPMS_ATTEST).</description></item>
        ///   <item><description>signature (TPMT_SIGNATURE) - sigAlg (2) selecting a TPMU_SIGNATURE member.</description></item>
        /// </list>
        /// <para>
        /// The first response parameter, <c>quoted</c>, is a <c>TPM2B_ATTEST</c> sized buffer (TPM 2.0 Library
        /// Part 3, clause 18.4, Table 102), which is what TPM 2.0 Library Part 1, clause 18.1 requires of an
        /// encryptable parameter and what clause 15.4 restates, so it is eligible for session-based parameter
        /// encryption (the <c>encrypt</c> attribute). A quote is normally published to a relying party, but the
        /// attestation names the platform and its PCR state, so a caller that wants that off the bus attaches an
        /// encrypt session and the TPM encrypts the attestation before it computes any rpHash.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 18.4 - TPM2_Quote.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Quote => TpmResponseCodec.Create(
            QuoteResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_Certify response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>certifyInfo (TPM2B_ATTEST) - the signed attestation (a marshaled TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY).</description></item>
        ///   <item><description>signature (TPMT_SIGNATURE) - sigAlg (2) selecting a TPMU_SIGNATURE member.</description></item>
        /// </list>
        /// <para>
        /// The first response parameter, <c>certifyInfo</c>, is a <c>TPM2B_ATTEST</c> sized buffer (TPM 2.0
        /// Library Part 3, clause 18.2, Table 98), which is what TPM 2.0 Library Part 1, clause 18.1 requires of
        /// an encryptable parameter and what clause 15.4 restates, so it is eligible for session-based parameter
        /// encryption (the <c>encrypt</c> attribute). The attestation names the certified object and the
        /// qualifying data bound to it, so a caller that wants that off the bus attaches an encrypt session and
        /// the TPM encrypts the attestation before it computes any rpHash.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 18.2 - TPM2_Certify.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Certify => TpmResponseCodec.Create(
            CertifyResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_CertifyCreation response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>certifyInfo (TPM2B_ATTEST) - the signed attestation (a marshaled TPMS_ATTEST of type TPM_ST_ATTEST_CREATION).</description></item>
        ///   <item><description>signature (TPMT_SIGNATURE) - sigAlg (2) selecting a TPMU_SIGNATURE member.</description></item>
        /// </list>
        /// <para>
        /// The first response parameter, <c>certifyInfo</c>, is a <c>TPM2B_ATTEST</c> sized buffer (TPM 2.0
        /// Library Part 3, clause 18.3, Table 100), which is what TPM 2.0 Library Part 1, clause 18.1 requires of
        /// an encryptable parameter and what clause 15.4 restates, so it is eligible for session-based parameter
        /// encryption (the <c>encrypt</c> attribute). Only that first parameter is ever encrypted; the
        /// <c>signature</c> that follows it travels in the clear.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 18.3 - TPM2_CertifyCreation.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec CertifyCreation => TpmResponseCodec.Create(
            CertifyCreationResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_GetTime response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>timeInfo (TPM2B_ATTEST) - the signed attestation (a marshaled TPMS_ATTEST of type TPM_ST_ATTEST_TIME).</description></item>
        ///   <item><description>signature (TPMT_SIGNATURE) - sigAlg (2) selecting a TPMU_SIGNATURE member.</description></item>
        /// </list>
        /// <para>
        /// The first response parameter, <c>timeInfo</c>, is a <c>TPM2B_ATTEST</c> sized buffer (TPM 2.0 Library
        /// Part 3, clause 18.7, Table 108), which is what TPM 2.0 Library Part 1, clause 18.1 requires of an
        /// encryptable parameter and what clause 15.4 restates, so it is eligible for session-based parameter
        /// encryption (the <c>encrypt</c> attribute). The attestation carries the TPM's Clock, resetCount and
        /// restartCount, which are privacy-relevant correlators, so a caller that wants them off the bus attaches
        /// an encrypt session and the TPM encrypts the attestation before it computes any rpHash.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 18.7 - TPM2_GetTime.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec GetTime => TpmResponseCodec.Create(
            GetTimeResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_GetSessionAuditDigest response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>auditInfo (TPM2B_ATTEST) - the signed attestation (a marshaled TPMS_ATTEST of type TPM_ST_ATTEST_SESSION_AUDIT).</description></item>
        ///   <item><description>signature (TPMT_SIGNATURE) - sigAlg (2) selecting a TPMU_SIGNATURE member, or TPM_ALG_NULL for the NULL Signature.</description></item>
        /// </list>
        /// <para>
        /// The first response parameter, <c>auditInfo</c>, is a <c>TPM2B_ATTEST</c> sized buffer (TPM 2.0 Library
        /// Part 3, clause 18.5, Table 104), which is what TPM 2.0 Library Part 1, clause 18.1 requires of an
        /// encryptable parameter and what clause 15.4 restates, so it is eligible for session-based parameter
        /// encryption (the <c>encrypt</c> attribute). The attestation carries the audit session's digest, which is
        /// privacy-relevant, so a caller that wants it off the bus attaches an encrypt session and the TPM
        /// encrypts the attestation before it computes any rpHash.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 18.5 - TPM2_GetSessionAuditDigest.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec GetSessionAuditDigest => TpmResponseCodec.Create(
            GetSessionAuditDigestResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_ReadClock response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>currentTime (TPMS_TIME_INFO) - the current Time/Clock/resetCount/restartCount/Safe snapshot, uncertified and unsigned.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 29.1 - TPM2_ReadClock.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec ReadClock => TpmResponseCodec.Create(ReadClockResponse.Parse);

        /// <summary>
        /// Codec for TPM2_ClockRateAdjust response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 29.3).
        /// </summary>
        public static TpmResponseCodec ClockRateAdjust => TpmResponseCodec.NoParameters(ClockRateAdjustResponse.Instance);

        /// <summary>
        /// Codec for TPM2_ClockSet response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, clause 29.2).
        /// </summary>
        public static TpmResponseCodec ClockSet => TpmResponseCodec.NoParameters(ClockSetResponse.Instance);

        /// <summary>
        /// Codec for TPM2_StirRandom response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, clause 16.2).
        /// </summary>
        public static TpmResponseCodec StirRandom => TpmResponseCodec.NoParameters(StirRandomResponse.Instance);

        /// <summary>
        /// Codec for TPM2_TestParms response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, clause 30.3).
        /// </summary>
        public static TpmResponseCodec TestParms => TpmResponseCodec.NoParameters(TestParmsResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_Certify response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>certifyInfo (TPM2B_ATTEST) - the signed attestation (a marshaled TPMS_ATTEST of type TPM_ST_ATTEST_NV).</description></item>
        ///   <item><description>signature (TPMT_SIGNATURE) - sigAlg (2) selecting a TPMU_SIGNATURE member.</description></item>
        /// </list>
        /// <para>
        /// The first response parameter, <c>certifyInfo</c>, is a <c>TPM2B_ATTEST</c> sized buffer (TPM 2.0
        /// Library Part 3, clause 31.16, Table 272), which is what TPM 2.0 Library Part 1, clause 18.1 requires
        /// of an encryptable parameter and what clause 15.4 restates, so it is eligible for session-based
        /// parameter encryption (the <c>encrypt</c> attribute). The attestation embeds the certified NV contents
        /// themselves, so an encrypt session is how a caller keeps those contents off the bus; the TPM encrypts
        /// the attestation before it computes any rpHash.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 31.16 - TPM2_NV_Certify.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec NvCertify => TpmResponseCodec.Create(
            NvCertifyResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_VerifySignature response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>validation (TPMT_TK_VERIFIED) - the validation ticket. Unlike every attest-producing command, there is no TPM2B_ATTEST and no TPMT_SIGNATURE.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 20.2 - TPM2_VerifySignature.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec VerifySignature => TpmResponseCodec.Create(VerifySignatureResponse.Parse);

        /// <summary>
        /// Codec for TPM2_VerifyDigestSignature response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>validation (TPMT_TK_VERIFIED) - the validation ticket, tagged TPM_ST_DIGEST_VERIFIED. Like TPM2_VerifySignature(), there is no TPM2B_ATTEST and no TPMT_SIGNATURE.</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 20.4, Table 121 - TPM2_VerifyDigestSignature.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec VerifyDigestSignature => TpmResponseCodec.Create(VerifyDigestSignatureResponse.Parse);

        /// <summary>
        /// Codec for TPM2_Encapsulate response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>sharedSecret (TPM2B_SHARED_SECRET) - the KEM output, parsed first.</description></item>
        ///   <item><description>ciphertext (TPM2B_KEM_CIPHERTEXT) - the public artifact the holder of the KEM private key decapsulates, parsed second.</description></item>
        /// </list>
        /// <para>
        /// The first response parameter, <c>sharedSecret</c>, is a sized buffer, so it is eligible for
        /// session-based parameter encryption (the <c>encrypt</c> attribute) — the only protection the
        /// command offers it absent an attached encrypt session.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 14.10, Table 61 - TPM2_Encapsulate.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Encapsulate => TpmResponseCodec.Create(
            EncapsulateResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_Decapsulate response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>sharedSecret (TPM2B_SHARED_SECRET) - the recovered shared secret.</description></item>
        /// </list>
        /// <para>
        /// The first (and only) response parameter, <c>sharedSecret</c>, is a sized buffer, so it is
        /// eligible for session-based parameter encryption (the <c>encrypt</c> attribute).
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 14.11, Table 63 - TPM2_Decapsulate.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Decapsulate => TpmResponseCodec.Create(
            DecapsulateResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_MakeCredential response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>credentialBlob (TPM2B_ID_OBJECT) - the integrity-protected, encrypted credential.</description></item>
        ///   <item><description>secret (TPM2B_ENCRYPTED_SECRET) - the seed encrypted to the credential key's public area.</description></item>
        /// </list>
        /// <para>
        /// The command's tag cell admits <c>TPM_ST_SESSIONS</c> "if an audit, encrypt, or decrypt session is
        /// present" (Table 28), and the reference command-attribute table marks the response <c>ENCRYPT_2</c>:
        /// <c>credentialBlob</c>, the first response parameter, is a sized buffer an <c>encrypt</c> companion
        /// session may protect, a second layer of confidentiality over the credential's own cryptographic
        /// wrapping. See TPM 2.0 Library Part 3, clause 12.6 - TPM2_MakeCredential.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec MakeCredential => TpmResponseCodec.Create(
            MakeCredentialResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_Duplicate response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>encryptionKeyOut (TPM2B_DATA) - the inner-wrapper key, empty for the no-inner-wrapper form.</description></item>
        ///   <item><description>duplicate (TPM2B_PRIVATE) - the duplicated object's protected sensitive area.</description></item>
        ///   <item><description>outSymSeed (TPM2B_ENCRYPTED_SECRET) - the outer-wrapper seed protected to the new parent.</description></item>
        /// </list>
        /// <para>
        /// All three outputs protect themselves cryptographically, so the first parameter is left
        /// non-encryptable. See TPM 2.0 Library Part 3, clause 13.1 - TPM2_Duplicate.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Duplicate => TpmResponseCodec.Create(DuplicateResponse.Parse);

        /// <summary>
        /// Codec for TPM2_Import response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outPrivate (TPM2B_PRIVATE) - the imported object's sensitive area re-wrapped under the new parent.</description></item>
        /// </list>
        /// <para>
        /// The blob protects itself cryptographically, so the parameter is left non-encryptable. See TPM 2.0
        /// Part 3, clause 13.3 - TPM2_Import.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Import => TpmResponseCodec.Create(ImportResponse.Parse);

        /// <summary>
        /// Codec for TPM2_ActivateCredential response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>certInfo (TPM2B_DIGEST) - the recovered credential secret.</description></item>
        /// </list>
        /// <para>
        /// The recovered secret is confidential, so the first (and only) response parameter is eligible for
        /// session-based parameter encryption (the <c>encrypt</c> attribute). See TPM 2.0 Library Part 3, clause 12.5 -
        /// TPM2_ActivateCredential.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec ActivateCredential => TpmResponseCodec.Create(
            ActivateCredentialResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_Unseal response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outData (TPM2B_SENSITIVE_DATA) - the recovered sealed data.</description></item>
        /// </list>
        /// <para>
        /// The first (and only) response parameter, <c>outData</c>, is a sized buffer, so it is eligible for
        /// session-based parameter encryption (the <c>encrypt</c> attribute) - the recovered secret can be
        /// returned over an AES-CFB-encrypted channel.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 12.7 - TPM2_Unseal.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Unseal => TpmResponseCodec.Create(
            UnsealResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_ECDH_ZGen response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outPoint (TPM2B_ECC_POINT) - outer size (2) + TPM2B_ECC_PARAMETER(x) + TPM2B_ECC_PARAMETER(y).</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 14.5 - TPM2_ECDH_ZGen.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec EcdhZGen => TpmResponseCodec.Create(EcdhZGenResponse.Parse);

        /// <summary>
        /// Codec for TPM2_DictionaryAttackLockReset response. This command has no response handles and no
        /// response parameters (TPM 2.0 Library Part 3, clause 25.2).
        /// </summary>
        public static TpmResponseCodec DictionaryAttackLockReset => TpmResponseCodec.NoParameters(DictionaryAttackLockResetResponse.Instance);

        /// <summary>
        /// Codec for TPM2_DictionaryAttackParameters response. This command has no response handles and no
        /// response parameters (TPM 2.0 Library Part 3, clause 25.3).
        /// </summary>
        public static TpmResponseCodec DictionaryAttackParameters => TpmResponseCodec.NoParameters(DictionaryAttackParametersResponse.Instance);

        /// <summary>
        /// Codec for TPM2_HierarchyChangeAuth response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 24.8).
        /// </summary>
        public static TpmResponseCodec HierarchyChangeAuth => TpmResponseCodec.NoParameters(HierarchyChangeAuthResponse.Instance);

        /// <summary>
        /// Codec for TPM2_Clear response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, clause 24.6).
        /// </summary>
        public static TpmResponseCodec Clear => TpmResponseCodec.NoParameters(ClearResponse.Instance);

        /// <summary>
        /// Codec for TPM2_ClearControl response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 24.7).
        /// </summary>
        public static TpmResponseCodec ClearControl => TpmResponseCodec.NoParameters(ClearControlResponse.Instance);

        /// <summary>
        /// Codec for TPM2_HierarchyControl response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 24.2).
        /// </summary>
        public static TpmResponseCodec HierarchyControl => TpmResponseCodec.NoParameters(HierarchyControlResponse.Instance);

        /// <summary>
        /// Codec for TPM2_SetPrimaryPolicy response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, clause 24.3).
        /// </summary>
        public static TpmResponseCodec SetPrimaryPolicy => TpmResponseCodec.NoParameters(SetPrimaryPolicyResponse.Instance);

        /// <summary>
        /// Codec for TPM2_ReadPublic response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outPublic (TPM2B_PUBLIC) - the public area of the object.</description></item>
        ///   <item><description>name (TPM2B_NAME) - the object name.</description></item>
        ///   <item><description>qualifiedName (TPM2B_NAME) - the qualified name.</description></item>
        /// </list>
        /// <para>
        /// The command's tag cell admits <c>TPM_ST_SESSIONS</c> "if an audit or encrypt session is present"
        /// (Table 24): <c>outPublic</c>, the first response parameter, is a sized buffer an <c>encrypt</c>
        /// companion session may protect.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 12.4 - TPM2_ReadPublic.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec ReadPublic => TpmResponseCodec.Create(
            ReadPublicResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_NV_ReadPublic response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>nvPublic (TPM2B_NV_PUBLIC) - the public area of the NV Index.</description></item>
        ///   <item><description>nvName (TPM2B_NAME) - the Name of the Index.</description></item>
        /// </list>
        /// <para>
        /// The first response parameter, <c>nvPublic</c>, is a sized buffer and so is eligible for
        /// session-based parameter encryption per the reference command-attribute table (an <c>ENCRYPT_2</c>
        /// target); the command's tag cell ("<c>TPM_ST_SESSIONS</c> if an audit or encrypt session is present")
        /// admits an encrypt companion even though the request carries no authorization (Auth Index: None).
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 31.6 - TPM2_NV_ReadPublic.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec NvReadPublic => TpmResponseCodec.Create(
            NvReadPublicResponse.Parse, responseFirstParameterIsEncryptable: true);

        /// <summary>
        /// Codec for TPM2_GetTestResult response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Response parameters:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>outData (TPM2B_MAX_BUFFER) - test result data, manufacturer-specific.</description></item>
        ///   <item><description>testResult (TPM_RC) - the value a subsequent TPM2_SelfTest() would return.</description></item>
        /// </list>
        /// <para>
        /// The command's tag cell admits <c>TPM_ST_SESSIONS</c> "if an audit or encrypt session is present"
        /// (Table 12): <c>outData</c>, the first response parameter, is a sized buffer an <c>encrypt</c>
        /// companion session may protect.
        /// </para>
        /// <para>
        /// See TPM 2.0 Library Part 3, clause 10.4 - TPM2_GetTestResult.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec GetTestResult => TpmResponseCodec.Create(
            GetTestResultResponse.Parse, responseFirstParameterIsEncryptable: true);
    }
}
