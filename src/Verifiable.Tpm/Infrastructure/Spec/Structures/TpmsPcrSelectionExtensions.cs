using System;
using System.Collections.Generic;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Extension methods for <see cref="TpmsPcrSelection"/>.
/// </summary>
/// <remarks>
/// Provides methods to query and manipulate PCR selections.
/// </remarks>
public static class TpmsPcrSelectionExtensions
{
    /// <summary>
    /// Gets a human-readable description of the PCR selection.
    /// </summary>
    /// <param name="selection">The PCR selection to describe.</param>
    /// <returns>A human-readable description.</returns>
    public static string GetDescription(this TpmsPcrSelection selection)
    {
        var selected = selection.GetSelectedPcrs();

        if(selected.Count == 0)
        {
            return $"{selection.HashAlgorithm}: no PCRs selected";
        }

        return $"{selection.HashAlgorithm}: PCRs {string.Join(", ", selected)}";
    }

    /// <summary>
    /// Gets the list of selected PCR indices.
    /// </summary>
    /// <param name="selection">The PCR selection.</param>
    /// <returns>A list of selected PCR indices (0-based).</returns>
    public static IReadOnlyList<int> GetSelectedPcrs(this TpmsPcrSelection selection)
    {
        var selected = new List<int>();
        ReadOnlySpan<byte> span = selection.PcrSelect.Span;

        for(int byteIndex = 0; byteIndex < span.Length; byteIndex++)
        {
            byte value = span[byteIndex];

            for(int bitIndex = 0; bitIndex < 8; bitIndex++)
            {
                if((value & (1 << bitIndex)) != 0)
                {
                    selected.Add(byteIndex * 8 + bitIndex);
                }
            }
        }

        return selected;
    }

    /// <summary>
    /// Determines if a specific PCR is selected.
    /// </summary>
    /// <param name="selection">The PCR selection.</param>
    /// <param name="pcrIndex">The PCR index to check (0-based).</param>
    /// <returns><c>true</c> if the PCR is selected; otherwise, <c>false</c>.</returns>
    public static bool IsPcrSelected(this TpmsPcrSelection selection, int pcrIndex)
    {
        if(pcrIndex < 0)
        {
            return false;
        }

        int byteIndex = pcrIndex / 8;
        int bitIndex = pcrIndex % 8;

        ReadOnlySpan<byte> span = selection.PcrSelect.Span;

        if(byteIndex >= span.Length)
        {
            return false;
        }

        return (span[byteIndex] & (1 << bitIndex)) != 0;
    }

    /// <summary>
    /// Gets the count of selected PCRs.
    /// </summary>
    /// <param name="selection">The PCR selection.</param>
    /// <returns>The number of selected PCRs.</returns>
    public static int GetSelectedCount(this TpmsPcrSelection selection)
    {
        int count = 0;
        ReadOnlySpan<byte> span = selection.PcrSelect.Span;

        for(int i = 0; i < span.Length; i++)
        {
            count += BitCount(span[i]);
        }

        return count;
    }

    /// <summary>
    /// Determines if no PCRs are selected.
    /// </summary>
    /// <param name="selection">The PCR selection.</param>
    /// <returns><c>true</c> if no PCRs are selected; otherwise, <c>false</c>.</returns>
    public static bool IsEmpty(this TpmsPcrSelection selection)
    {
        ReadOnlySpan<byte> span = selection.PcrSelect.Span;

        for(int i = 0; i < span.Length; i++)
        {
            if(span[i] != 0)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Gets the maximum PCR index that could be selected based on the bitmap size.
    /// </summary>
    /// <param name="selection">The PCR selection.</param>
    /// <returns>The maximum selectable PCR index (exclusive).</returns>
    public static int GetMaxPcrIndex(this TpmsPcrSelection selection)
    {
        return selection.PcrSelect.Length * 8;
    }

    private static int BitCount(byte value)
    {
        int count = 0;

        while(value != 0)
        {
            count += value & 1;
            value >>= 1;
        }

        return count;
    }
}
