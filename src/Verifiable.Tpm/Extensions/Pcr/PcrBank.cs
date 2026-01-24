using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Extensions.Pcr;

/// <summary>
/// PCR values from a single hash algorithm bank.
/// </summary>
/// <remarks>
/// <para>
/// Represents all PCR digests read from one bank (e.g., SHA256).
/// Only PCRs that are allocated in the TPM configuration are present.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PcrBank
{
    private readonly Dictionary<int, byte[]> values;

    /// <summary>
    /// Gets the algorithm name (e.g., "SHA256", "SHA384").
    /// </summary>
    public string Algorithm { get; }

    /// <summary>
    /// Gets the digest size in bytes.
    /// </summary>
    public int DigestSize { get; }

    /// <summary>
    /// Gets the PCR indices that are allocated in this bank.
    /// </summary>
    public IReadOnlyList<int> AllocatedPcrs { get; }

    /// <summary>
    /// Gets the number of allocated PCRs.
    /// </summary>
    public int Count => values.Count;

    /// <summary>
    /// Gets the digest for the specified PCR index.
    /// </summary>
    /// <param name="index">The PCR index.</param>
    /// <returns>The digest value as a byte array.</returns>
    /// <exception cref="KeyNotFoundException">The PCR index is not allocated in this bank.</exception>
    public byte[] this[int index] => values[index];

    internal PcrBank(string algorithm, int digestSize, Dictionary<int, byte[]> values)
    {
        Algorithm = algorithm;
        DigestSize = digestSize;
        this.values = values;

        //Build sorted list of allocated PCR indices.
        var indices = new List<int>(values.Keys);
        indices.Sort();
        AllocatedPcrs = indices;
    }

    /// <summary>
    /// Checks if the specified PCR index is allocated in this bank.
    /// </summary>
    /// <param name="index">The PCR index.</param>
    /// <returns><c>true</c> if the PCR is allocated; otherwise, <c>false</c>.</returns>
    public bool HasPcr(int index) => values.ContainsKey(index);

    /// <summary>
    /// Attempts to get the digest for the specified PCR index.
    /// </summary>
    /// <param name="index">The PCR index.</param>
    /// <param name="value">The digest value, if allocated.</param>
    /// <returns><c>true</c> if the PCR is allocated; otherwise, <c>false</c>.</returns>
    public bool TryGetPcr(int index, [NotNullWhen(true)] out byte[]? value)
    {
        return values.TryGetValue(index, out value);
    }

    /// <summary>
    /// Checks if the specified PCR has been extended (is non-zero).
    /// </summary>
    /// <param name="index">The PCR index.</param>
    /// <returns><c>true</c> if the PCR has been extended; <c>false</c> if zero or not allocated.</returns>
    public bool IsExtended(int index)
    {
        if(!values.TryGetValue(index, out byte[]? bytes))
        {
            return false;
        }

        foreach(byte b in bytes)
        {
            if(b != 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Checks if the specified PCR is in an error state (all 0xFF).
    /// </summary>
    /// <param name="index">The PCR index.</param>
    /// <returns><c>true</c> if the PCR is in error state; <c>false</c> otherwise or if not allocated.</returns>
    public bool IsErrorState(int index)
    {
        if(!values.TryGetValue(index, out byte[]? bytes))
        {
            return false;
        }

        foreach(byte b in bytes)
        {
            if(b != 0xFF)
            {
                return false;
            }
        }

        return true;
    }

    private string DebuggerDisplay => $"{Algorithm}: {Count} PCRs, {DigestSize} bytes each";
}