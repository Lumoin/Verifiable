using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Extensions.Pcr;

/// <summary>
/// A snapshot of all PCR values from a TPM.
/// </summary>
/// <remarks>
/// <para>
/// Contains PCR values from all active banks (banks with allocated PCRs).
/// Empty banks reported by the TPM are not included.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PcrSnapshot
{
    private readonly Dictionary<string, PcrBank> banksByAlgorithm;

    /// <summary>
    /// Gets all active PCR banks (banks with at least one PCR allocated).
    /// </summary>
    public IReadOnlyList<PcrBank> Banks { get; }

    /// <summary>
    /// Gets the PCR update counter at the time of reading.
    /// </summary>
    /// <remarks>
    /// This counter increments each time any PCR is extended on the TPM.
    /// </remarks>
    public uint UpdateCounter { get; }

    /// <summary>
    /// Gets whether the update counter remained stable across all reads.
    /// </summary>
    /// <remarks>
    /// <para>
    /// If pagination required multiple TPM commands, this indicates whether
    /// the update counter was consistent. A value of <c>false</c> means PCRs
    /// may have been extended during the read operation.
    /// </para>
    /// </remarks>
    public bool IsConsistent { get; }

    /// <summary>
    /// Gets the bank for the specified algorithm name.
    /// </summary>
    /// <param name="algorithm">The algorithm name (e.g., "SHA256", "SHA-256", "sha256").</param>
    /// <returns>The PCR bank.</returns>
    /// <exception cref="KeyNotFoundException">The algorithm is not present or has no allocated PCRs.</exception>
    public PcrBank this[string algorithm] => banksByAlgorithm[NormalizeAlgorithmName(algorithm)];

    internal PcrSnapshot(
        List<PcrBank> banks,
        uint updateCounter,
        bool isConsistent)
    {
        Banks = banks;
        UpdateCounter = updateCounter;
        IsConsistent = isConsistent;

        banksByAlgorithm = new Dictionary<string, PcrBank>(StringComparer.OrdinalIgnoreCase);
        foreach(var bank in banks)
        {
            banksByAlgorithm[bank.Algorithm] = bank;
        }
    }

    /// <summary>
    /// Checks whether a bank for the specified algorithm exists and has allocated PCRs.
    /// </summary>
    /// <param name="algorithm">The algorithm name (e.g., "SHA256", "SHA-256", "sha256").</param>
    /// <returns><c>true</c> if the bank exists with allocated PCRs; otherwise, <c>false</c>.</returns>
    public bool HasBank(string algorithm)
    {
        return banksByAlgorithm.ContainsKey(NormalizeAlgorithmName(algorithm));
    }

    /// <summary>
    /// Attempts to get the bank for the specified algorithm.
    /// </summary>
    /// <param name="algorithm">The algorithm name (e.g., "SHA256", "SHA-256", "sha256").</param>
    /// <param name="bank">The bank, if found.</param>
    /// <returns><c>true</c> if the bank exists; otherwise, <c>false</c>.</returns>
    public bool TryGetBank(string algorithm, [NotNullWhen(true)] out PcrBank? bank)
    {
        return banksByAlgorithm.TryGetValue(NormalizeAlgorithmName(algorithm), out bank);
    }

    /// <summary>
    /// Gets a specific PCR value by algorithm and index.
    /// </summary>
    /// <param name="algorithm">The algorithm name.</param>
    /// <param name="index">The PCR index.</param>
    /// <returns>The digest value.</returns>
    /// <exception cref="KeyNotFoundException">The algorithm or PCR index is not present.</exception>
    public byte[] GetPcr(string algorithm, int index)
    {
        return this[algorithm][index];
    }

    /// <summary>
    /// Attempts to get a specific PCR value.
    /// </summary>
    /// <param name="algorithm">The algorithm name.</param>
    /// <param name="index">The PCR index.</param>
    /// <param name="value">The digest value, if found.</param>
    /// <returns><c>true</c> if the value was found; otherwise, <c>false</c>.</returns>
    public bool TryGetPcr(string algorithm, int index, [NotNullWhen(true)] out byte[]? value)
    {
        value = null;

        if(!TryGetBank(algorithm, out var bank))
        {
            return false;
        }

        return bank.TryGetPcr(index, out value);
    }

    private static string NormalizeAlgorithmName(string algorithm)
    {
        //Handle common variations: "SHA-256" -> "SHA256", "sha256" -> "SHA256".
        return algorithm.Replace("-", "",StringComparison.OrdinalIgnoreCase).ToUpperInvariant();
    }

    private string DebuggerDisplay
    {
        get
        {
            string consistency = IsConsistent ? "consistent" : "inconsistent";
            return $"{Banks.Count} banks, counter={UpdateCounter}, {consistency}";
        }
    }
}