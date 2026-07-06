using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

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
        /// See TPM 2.0 Part 3, Section 16.1 - TPM2_GetRandom.
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
        /// See TPM 2.0 Part 3, Section 11.1 - TPM2_StartAuthSession.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec StartAuthSession => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, System.Buffers.MemoryPool<byte> pool) =>
                StartAuthSessionResponse.Parse(ref reader, TpmiShAuthSession.FromValue(handle), pool));

        /// <summary>
        /// Codec for TPM2_FlushContext response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This command has no response handles and no response parameters.
        /// </para>
        /// <para>
        /// See TPM 2.0 Part 3, Section 28.4 - TPM2_FlushContext.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec FlushContext => TpmResponseCodec.NoParameters(FlushContextResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyCommandCode response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This command has no response handles and no response parameters.
        /// </para>
        /// <para>
        /// See TPM 2.0 Part 3, Section 23.4 - TPM2_PolicyCommandCode.
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
        /// See TPM 2.0 Part 3, Section 23.18 - TPM2_PolicyAuthValue.
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
        /// See TPM 2.0 Part 3, Section 23.7 - TPM2_PolicyPCR.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PolicyPcr => TpmResponseCodec.NoParameters(PolicyPcrResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyOR response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, Section 23.6).
        /// </summary>
        public static TpmResponseCodec PolicyOr => TpmResponseCodec.NoParameters(PolicyOrResponse.Instance);

        /// <summary>
        /// Codec for TPM2_PolicyNV response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, Section 23.9).
        /// </summary>
        public static TpmResponseCodec PolicyNv => TpmResponseCodec.NoParameters(PolicyNvResponse.Instance);

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
        /// See TPM 2.0 Part 3, Section 23.6 - TPM2_PolicyGetDigest.
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
        /// See TPM 2.0 Part 3, Section 23.4 - TPM2_PolicySecret.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PolicySecret => TpmResponseCodec.Create(PolicySecretResponse.Parse);

        /// <summary>
        /// Codec for TPM2_NV_DefineSpace response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, Section 31.3).
        /// </summary>
        public static TpmResponseCodec NvDefineSpace => TpmResponseCodec.NoParameters(NvDefineSpaceResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_Read response.
        /// </summary>
        /// <remarks>
        /// Response parameters: data (TPM2B_MAX_NV_BUFFER). See TPM 2.0 Library Part 3, Section 31.13.
        /// </remarks>
        public static TpmResponseCodec NvRead => TpmResponseCodec.Create(NvReadResponse.Parse);

        /// <summary>
        /// Codec for TPM2_NV_Write response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, Section 31.7).
        /// </summary>
        public static TpmResponseCodec NvWrite => TpmResponseCodec.NoParameters(NvWriteResponse.Instance);

        /// <summary>
        /// Codec for TPM2_NV_UndefineSpace response. This command has no response handles and no response
        /// parameters (TPM 2.0 Library Part 3, Section 31.4).
        /// </summary>
        public static TpmResponseCodec NvUndefineSpace => TpmResponseCodec.NoParameters(NvUndefineSpaceResponse.Instance);

        /// <summary>
        /// Codec for TPM2_EvictControl response. This command has no response handles and no response parameters
        /// (TPM 2.0 Library Part 3, Section 28.5).
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
        /// See TPM 2.0 Part 3, Section 24.1 - TPM2_CreatePrimary.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec CreatePrimary => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, System.Buffers.MemoryPool<byte> pool) =>
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
        /// <see cref="TpmResponseCodec.Create{TResponse}"/> factory. See TPM 2.0 Part 3, Section 12.1.
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
        /// See TPM 2.0 Part 3, Section 12.2 - TPM2_Load.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Load => TpmResponseCodec.CreateWithHandle(
            static (ref TpmReader reader, uint handle, System.Buffers.MemoryPool<byte> pool) =>
                LoadResponse.Parse(ref reader, TpmiDhObject.FromValue(handle), pool));

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
        /// See TPM 2.0 Part 3, Section 30.2 - TPM2_GetCapability.
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
        /// See TPM 2.0 Part 3, Section 22.4 - TPM2_PCR_Read.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec PcrRead => TpmResponseCodec.Create(PcrReadResponse.Parse);

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
        /// See TPM 2.0 Part 3, Section 20.2 - TPM2_Sign.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Sign => TpmResponseCodec.Create(SignResponse.Parse);

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
        /// The first response parameter, <c>quoted</c>, is a sized buffer and so would be encrypt-eligible, but a
        /// quote is public by design (it proves platform state to a relying party), so it is left non-encryptable.
        /// </para>
        /// <para>
        /// See TPM 2.0 Part 3, Section 18.4 - TPM2_Quote.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Quote => TpmResponseCodec.Create(QuoteResponse.Parse);

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
        /// The first response parameter, <c>certifyInfo</c>, is a sized buffer and so would be encrypt-eligible,
        /// but an attestation is public by design, so it is left non-encryptable.
        /// </para>
        /// <para>
        /// See TPM 2.0 Part 3, Section 18.2 - TPM2_Certify.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Certify => TpmResponseCodec.Create(CertifyResponse.Parse);

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
        /// The first response parameter, <c>certifyInfo</c>, is a sized buffer and so would be encrypt-eligible,
        /// but an attestation is public by design, so it is left non-encryptable.
        /// </para>
        /// <para>
        /// See TPM 2.0 Part 3, Section 18.3 - TPM2_CertifyCreation.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec CertifyCreation => TpmResponseCodec.Create(CertifyCreationResponse.Parse);

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
        /// The first response parameter, <c>timeInfo</c>, is a sized buffer and so would be encrypt-eligible, but
        /// an attestation is public by design, so it is left non-encryptable.
        /// </para>
        /// <para>
        /// See TPM 2.0 Part 3, Section 18.7 - TPM2_GetTime.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec GetTime => TpmResponseCodec.Create(GetTimeResponse.Parse);

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
        /// The first response parameter, <c>certifyInfo</c>, is a sized buffer and so would be encrypt-eligible,
        /// but an attestation is public by design, so it is left non-encryptable.
        /// </para>
        /// <para>
        /// See TPM 2.0 Part 3, Section 31.16 - TPM2_NV_Certify.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec NvCertify => TpmResponseCodec.Create(NvCertifyResponse.Parse);

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
        /// See TPM 2.0 Part 3, Section 20.1 - TPM2_VerifySignature.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec VerifySignature => TpmResponseCodec.Create(VerifySignatureResponse.Parse);

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
        /// Both outputs are public (they protect the credential cryptographically), so the first parameter is left
        /// non-encryptable. See TPM 2.0 Part 3, Section 12.6 - TPM2_MakeCredential.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec MakeCredential => TpmResponseCodec.Create(MakeCredentialResponse.Parse);

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
        /// session-based parameter encryption (the <c>encrypt</c> attribute). See TPM 2.0 Part 3, Section 12.5 -
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
        /// See TPM 2.0 Part 3, Section 12.7 - TPM2_Unseal.
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
        /// See TPM 2.0 Part 3, Section 14.5 - TPM2_ECDH_ZGen.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec EcdhZGen => TpmResponseCodec.Create(EcdhZGenResponse.Parse);

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
        /// See TPM 2.0 Part 3, Section 12.4 - TPM2_ReadPublic.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec ReadPublic => TpmResponseCodec.Create(ReadPublicResponse.Parse);
    }
}
