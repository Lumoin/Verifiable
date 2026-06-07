namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// The <c>DeviceKeyInfo</c> sub-structure inside an MSO per ISO/IEC 18013-5
/// §9.1.2.4 — the wallet-side public key the issuer binds to this
/// credential, plus the optional authorization-bounds and metadata maps.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="DeviceKey"/> is the COSE_Key the wallet will use to produce
/// <c>DeviceSigned</c> structures at presentation time. The MSO commits to
/// this key through the issuer's COSE_Sign1 signature, so a verifier that
/// trusts the MSO can be confident that signatures from this key originate
/// from the credential's intended holder.
/// </para>
/// <para>
/// <see cref="KeyAuthorizations"/> and <see cref="KeyInfo"/> are kept as
/// opaque encoded bytes in M.2; structured parsing lands when a consumer
/// needs it. The authorization shape (namespaces / data elements the device
/// key may release) is part of the M.4 / M.6 validator path; the keyInfo map
/// is a free-form integer-keyed slot for issuer-specific device-attestation
/// parameters.
/// </para>
/// </remarks>
public sealed class MdocDeviceKeyInfo
{
    /// <summary>
    /// Initializes a <c>DeviceKeyInfo</c> view from caller-supplied parts.
    /// </summary>
    /// <param name="deviceKey">The wallet's bound public COSE_Key.</param>
    /// <param name="encodedKeyAuthorizations">
    /// Optional opaque-encoded <c>keyAuthorizations</c> bytes. Structured
    /// parsing is deferred to the validator chunk.
    /// </param>
    /// <param name="encodedKeyInfo">
    /// Optional opaque-encoded <c>keyInfo</c> bytes (integer-keyed map of
    /// issuer-specific device-attestation parameters).
    /// </param>
    public MdocDeviceKeyInfo(
        MdocCoseKey deviceKey,
        ReadOnlyMemory<byte>? encodedKeyAuthorizations = null,
        ReadOnlyMemory<byte>? encodedKeyInfo = null)
    {
        ArgumentNullException.ThrowIfNull(deviceKey);

        DeviceKey = deviceKey;
        EncodedKeyAuthorizations = encodedKeyAuthorizations;
        EncodedKeyInfo = encodedKeyInfo;
    }


    /// <summary>The COSE_Key the wallet holds privately and uses to sign <c>DeviceAuth</c>.</summary>
    public MdocCoseKey DeviceKey { get; }

    /// <summary>
    /// Opaque encoding of the <c>keyAuthorizations</c> map. The structured
    /// view (namespaces / data elements the device key may release) lives at
    /// the validator layer.
    /// </summary>
    public ReadOnlyMemory<byte>? EncodedKeyAuthorizations { get; }

    /// <summary>
    /// Opaque encoding of the integer-keyed <c>keyInfo</c> map (issuer-specific
    /// device-attestation parameters).
    /// </summary>
    public ReadOnlyMemory<byte>? EncodedKeyInfo { get; }
}
