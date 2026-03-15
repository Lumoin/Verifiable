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
        /// See TPM 2.0 Part 3, Section 16.1 - TPM2_GetRandom.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec GetRandom => TpmResponseCodec.Create(GetRandomResponse.Parse);

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
        public static TpmResponseCodec FlushContext => TpmResponseCodec.NoParameters();

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
        ///   <item><description>signature (TPMT_SIGNATURE) - the signature: sigAlg (2) + hashAlg (2) + TPM2B_ECC_PARAMETER(r) + TPM2B_ECC_PARAMETER(s).</description></item>
        /// </list>
        /// <para>
        /// See TPM 2.0 Part 3, Section 20.2 - TPM2_Sign.
        /// </para>
        /// </remarks>
        public static TpmResponseCodec Sign => TpmResponseCodec.Create(SignResponse.Parse);

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
