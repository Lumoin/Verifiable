using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Tpm.Extensions.Pcr;

namespace Verifiable.Tpm.Extensions.Info;

/// <summary>
/// Comprehensive TPM information snapshot.
/// </summary>
/// <remarks>
/// <para>
/// Contains all discoverable information about a TPM including identity,
/// supported algorithms, ECC curves, and PCR values.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmInfo
{
    /// <summary>
    /// Gets the TPM identity and firmware information.
    /// </summary>
    public TpmIdentity Identity { get; }

    /// <summary>
    /// Gets the list of supported algorithm names.
    /// </summary>
    /// <remarks>
    /// Common algorithms include: SHA1, SHA256, SHA384, SHA512, RSA, ECC, AES, HMAC.
    /// </remarks>
    public IReadOnlyList<string> SupportedAlgorithms { get; }

    /// <summary>
    /// Gets the list of supported ECC curve names.
    /// </summary>
    /// <remarks>
    /// Common curves include: NIST_P256, NIST_P384, NIST_P521, SM2_P256.
    /// </remarks>
    public IReadOnlyList<string> SupportedCurves { get; }

    /// <summary>
    /// Gets the PCR values snapshot.
    /// </summary>
    public PcrSnapshot Pcrs { get; }

    /// <summary>
    /// Gets the platform type (Windows, Linux, etc.).
    /// </summary>
    public string Platform { get; }

    internal TpmInfo(
        TpmIdentity identity,
        IReadOnlyList<string> supportedAlgorithms,
        IReadOnlyList<string> supportedCurves,
        PcrSnapshot pcrs,
        string platform)
    {
        Identity = identity;
        SupportedAlgorithms = supportedAlgorithms;
        SupportedCurves = supportedCurves;
        Pcrs = pcrs;
        Platform = platform;
    }

    private string DebuggerDisplay =>
        $"{Identity.ManufacturerId.Trim()} TPM {Identity.Family}, {SupportedAlgorithms.Count} algorithms, {Pcrs.Banks.Count} PCR banks";
}