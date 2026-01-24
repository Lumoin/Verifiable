using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for common TPM data types.
/// </summary>
/// <remarks>
/// <para>
/// This static class provides ready-to-use tags for TPM buffer types.
/// Each tag contains the appropriate <see cref="Purpose"/> and
/// <see cref="MaterialSemantics"/> metadata.
/// </para>
/// <para>
/// <strong>Usage</strong>
/// </para>
/// <code>
/// //Use a pre-built tag when creating TPM buffers.
/// var nonce = new Tpm2bNonce(storage, TpmTags.Nonce);
///
/// //Or retrieve components from a tag.
/// var purpose = TpmTags.Auth.Get&lt;Purpose&gt;();
/// </code>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="Purpose"/>
/// <seealso cref="MaterialSemantics"/>
public static class TpmTags
{
    /// <summary>
    /// Tag for TPM2B_NONCE - session nonce values.
    /// </summary>
    /// <remarks>
    /// Used for nonceCaller and nonceTPM in session protocols.
    /// See TPM 2.0 Part 1, Section 17.6.3 - Session Nonces.
    /// </remarks>
    public static Tag Nonce { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Nonce),
        (typeof(MaterialSemantics), MaterialSemantics.Direct));

    /// <summary>
    /// Tag for TPM2B_AUTH - authorization values.
    /// </summary>
    /// <remarks>
    /// Used for passwords, HMACs, and authValue in authorization protocols.
    /// See TPM 2.0 Part 1, Section 17.6.4 - Authorization Values.
    /// </remarks>
    public static Tag Auth { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Auth),
        (typeof(MaterialSemantics), MaterialSemantics.Direct));

    /// <summary>
    /// Tag for TPM2B_DIGEST - hash digest values.
    /// </summary>
    /// <remarks>
    /// Used for hash results, PCR values, and cpHash/rpHash computations.
    /// </remarks>
    public static Tag Digest { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Digest),
        (typeof(MaterialSemantics), MaterialSemantics.Direct));

    /// <summary>
    /// Tag for raw TPM response data.
    /// </summary>
    /// <remarks>
    /// Used for the raw byte response from a TPM command before parsing.
    /// </remarks>
    public static Tag Response { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Transport),
        (typeof(MaterialSemantics), MaterialSemantics.Direct));

    /// <summary>
    /// Tag for TPM2B_ECC_PARAMETER - ECC coordinate values.
    /// </summary>
    /// <remarks>
    /// Used for x and y coordinates in ECC public points.
    /// See TPM 2.0 Part 2, Section 10.2.5.
    /// </remarks>
    public static Tag EccParameter { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Verification),
        (typeof(MaterialSemantics), MaterialSemantics.Direct));

    /// <summary>
    /// Tag for TPM2B_SENSITIVE_DATA - sensitive user data.
    /// </summary>
    /// <remarks>
    /// Used for sensitive data in sealed objects or key derivation.
    /// See TPM 2.0 Part 2, Section 10.9.3.
    /// </remarks>
    public static Tag SensitiveData { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Encryption),
        (typeof(MaterialSemantics), MaterialSemantics.Direct));
}