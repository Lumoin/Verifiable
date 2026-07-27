using System;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Evaluates a <c>TPM_EO</c> comparison (TPM 2.0 Library Part 2, Section 6.8, Table 22) between two equal-length,
/// big-endian operand spans, shared by every enhanced-authorization assertion that compares a live or stored value
/// against a caller-supplied operand (<c>TPM2_PolicyCounterTimer</c>, Part 3, Section 23.10; <c>TPM2_PolicyNV</c>,
/// Part 3, Section 23.9).
/// </summary>
/// <remarks>
/// <para>
/// Both operands are always the same length at every call site: the compared value is sliced to
/// <c>operandB</c>'s own length before either is evaluated, so the reference material's "the longer buffer always
/// wins" unsigned-compare corner (relevant only when the two lengths genuinely differ) never arises here.
/// </para>
/// <para>
/// A zero-length <paramref name="operandB"/> is rejected with <see cref="TpmRcConstants.TPM_RC_SIZE"/> before any
/// comparison runs, for every <see cref="TpmEoConstants"/> value alike — a deliberately defined rejection, not the
/// vacuous-true/false convention an unsigned zero-length compare would otherwise produce.
/// </para>
/// </remarks>
public static class TpmEoComparator
{
    /// <summary>
    /// Evaluates <paramref name="operation"/> over <paramref name="operandA"/> and <paramref name="operandB"/>.
    /// </summary>
    /// <param name="operandA">The compared value (for example a live-state slice or NV Index data window).</param>
    /// <param name="operandB">The caller-supplied comparison operand; must be the same length as <paramref name="operandA"/> and non-empty.</param>
    /// <param name="operation">The <c>TPM_EO</c> comparison to perform.</param>
    /// <param name="comparisonResult">On a successful evaluation, whether the comparison held.</param>
    /// <param name="rejectionCode">On a failed evaluation, the response code the caller should reject with; otherwise <see cref="TpmRcConstants.TPM_RC_SUCCESS"/>.</param>
    /// <returns><see langword="true"/> when the operands were well-formed and <paramref name="comparisonResult"/> is valid; <see langword="false"/> when the caller should reject with <paramref name="rejectionCode"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="operandA"/> and <paramref name="operandB"/> differ in length.</exception>
    public static bool TryEvaluate(
        ReadOnlySpan<byte> operandA, ReadOnlySpan<byte> operandB, TpmEoConstants operation, out bool comparisonResult, out TpmRcConstants rejectionCode)
    {
        if(operandA.Length != operandB.Length)
        {
            throw new ArgumentException("The compared value and the comparison operand must be the same length.", nameof(operandB));
        }

        if(operandB.IsEmpty)
        {
            comparisonResult = false;
            rejectionCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        rejectionCode = TpmRcConstants.TPM_RC_SUCCESS;
        comparisonResult = operation switch
        {
            TpmEoConstants.TPM_EO_EQ => operandA.SequenceEqual(operandB),
            TpmEoConstants.TPM_EO_NEQ => !operandA.SequenceEqual(operandB),
            TpmEoConstants.TPM_EO_SIGNED_GT => CompareSigned(operandA, operandB) > 0,
            TpmEoConstants.TPM_EO_UNSIGNED_GT => CompareUnsigned(operandA, operandB) > 0,
            TpmEoConstants.TPM_EO_SIGNED_LT => CompareSigned(operandA, operandB) < 0,
            TpmEoConstants.TPM_EO_UNSIGNED_LT => CompareUnsigned(operandA, operandB) < 0,
            TpmEoConstants.TPM_EO_SIGNED_GE => CompareSigned(operandA, operandB) >= 0,
            TpmEoConstants.TPM_EO_UNSIGNED_GE => CompareUnsigned(operandA, operandB) >= 0,
            TpmEoConstants.TPM_EO_SIGNED_LE => CompareSigned(operandA, operandB) <= 0,
            TpmEoConstants.TPM_EO_UNSIGNED_LE => CompareUnsigned(operandA, operandB) <= 0,
            TpmEoConstants.TPM_EO_BITSET => IsBitSet(operandA, operandB),
            TpmEoConstants.TPM_EO_BITCLEAR => IsBitClear(operandA, operandB),

            //Unreachable defense-in-depth: an undefined TPM_EO is rejected with TPM_RC_VALUE at PARSE time by both
            //TpmSimulator.TryParsePolicyNv and TpmSimulator.TryParsePolicyCounterTimer (via TpmEoConstantsExtensions.
            //IsDefined), before a request record carrying it is ever built, so this arm can never be reached from the
            //production wire path. Kept as a hard failure rather than silently folding an impossible value.
            _ => throw new NotSupportedException($"TPM_EO operation '{operation}' is not supported.")
        };

        return true;

        //Unsigned magnitude compare over equal-length, big-endian operands: octet 0 is the most significant
        //(Part 3, Section 23.10 prose). Returns -1/0/1, mirroring the conventional three-way compare.
        static int CompareUnsigned(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            for(int i = 0; i < a.Length; i++)
            {
                if(a[i] != b[i])
                {
                    return a[i] < b[i] ? -1 : 1;
                }
            }

            return 0;
        }

        //Two's-complement signed compare: differing sign bits (the most significant bit of octet 0) decide the
        //order outright, regardless of magnitude; equal signs fall through to the unsigned byte walk.
        static int CompareSigned(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            bool aNegative = (a[0] & 0x80) != 0;
            bool bNegative = (b[0] & 0x80) != 0;

            if(aNegative != bNegative)
            {
                return aNegative ? -1 : 1;
            }

            return CompareUnsigned(a, b);
        }

        //TPM_EO_BITSET: every bit set in b must also be set in a ((a & b) == b).
        static bool IsBitSet(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            for(int i = 0; i < a.Length; i++)
            {
                if((a[i] & b[i]) != b[i])
                {
                    return false;
                }
            }

            return true;
        }

        //TPM_EO_BITCLEAR: every bit set in b must be clear in a ((a & b) == 0).
        static bool IsBitClear(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            for(int i = 0; i < a.Length; i++)
            {
                if((a[i] & b[i]) != 0)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
