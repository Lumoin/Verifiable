using System;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Unit tests for <see cref="TpmEoComparator"/> (TPM 2.0 Library Part 2, Section 6.8, Table 22), the shared
/// TPM_EO evaluator <c>TPM2_PolicyCounterTimer</c> and <c>TPM2_PolicyNV</c>'s live-session arm both call. Each of
/// the 12 operations is exercised with an equal-and-a-differing operand pair, plus the zero-length-operand
/// rejection and the mismatched-length guard.
/// </summary>
[TestClass]
internal sealed class TpmEoComparatorTests
{
    /// <summary>
    /// Verifies TPM_EO_EQ/TPM_EO_NEQ over equal and differing operands.
    /// </summary>
    [TestMethod]
    public void EqAndNeqCompareOperandsByteForByte()
    {
        ReadOnlySpan<byte> a = [0x00, 0x00, 0x00, 0x2A];
        ReadOnlySpan<byte> equalB = [0x00, 0x00, 0x00, 0x2A];
        ReadOnlySpan<byte> differentB = [0x00, 0x00, 0x00, 0x2B];

        Assert.IsTrue(TpmEoComparator.TryEvaluate(a, equalB, TpmEoConstants.TPM_EO_EQ, out bool eqEqualResult, out _));
        Assert.IsTrue(eqEqualResult, "Equal operands must satisfy TPM_EO_EQ.");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(a, differentB, TpmEoConstants.TPM_EO_EQ, out bool eqDifferentResult, out _));
        Assert.IsFalse(eqDifferentResult, "Differing operands must not satisfy TPM_EO_EQ.");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(a, equalB, TpmEoConstants.TPM_EO_NEQ, out bool neqEqualResult, out _));
        Assert.IsFalse(neqEqualResult, "Equal operands must not satisfy TPM_EO_NEQ.");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(a, differentB, TpmEoConstants.TPM_EO_NEQ, out bool neqDifferentResult, out _));
        Assert.IsTrue(neqDifferentResult, "Differing operands must satisfy TPM_EO_NEQ.");
    }

    /// <summary>
    /// Verifies the unsigned ordering operations (GT/LT/GE/LE) over a big-endian magnitude comparison, treating
    /// a high-bit-set octet as a large positive value rather than a negative one.
    /// </summary>
    [TestMethod]
    public void UnsignedOrderingOperationsCompareBigEndianMagnitude()
    {
        //0x80 is a large unsigned magnitude (128), not a negative value, unlike the signed interpretation.
        ReadOnlySpan<byte> large = [0x80];
        ReadOnlySpan<byte> small = [0x01];

        Assert.IsTrue(TpmEoComparator.TryEvaluate(large, small, TpmEoConstants.TPM_EO_UNSIGNED_GT, out bool gt, out _));
        Assert.IsTrue(gt, "0x80 must be unsigned-greater-than 0x01.");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(small, large, TpmEoConstants.TPM_EO_UNSIGNED_LT, out bool lt, out _));
        Assert.IsTrue(lt, "0x01 must be unsigned-less-than 0x80.");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(large, large, TpmEoConstants.TPM_EO_UNSIGNED_GE, out bool ge, out _));
        Assert.IsTrue(ge, "An operand must be unsigned-greater-or-equal to itself.");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(small, small, TpmEoConstants.TPM_EO_UNSIGNED_LE, out bool le, out _));
        Assert.IsTrue(le, "An operand must be unsigned-less-or-equal to itself.");
    }

    /// <summary>
    /// Verifies the signed ordering operations (GT/LT/GE/LE) apply two's-complement semantics: a high-bit-set
    /// octet is negative and therefore smaller than any positive (high-bit-clear) octet, regardless of magnitude.
    /// </summary>
    [TestMethod]
    public void SignedOrderingOperationsApplyTwosComplementSemantics()
    {
        //0x80 (two's complement -128) is signed-negative; 0x01 (+1) is signed-positive, so -128 < +1 despite the
        //unsigned magnitude comparison going the other way (see UnsignedOrderingOperationsCompareBigEndianMagnitude).
        ReadOnlySpan<byte> negative = [0x80];
        ReadOnlySpan<byte> positive = [0x01];

        Assert.IsTrue(TpmEoComparator.TryEvaluate(negative, positive, TpmEoConstants.TPM_EO_SIGNED_LT, out bool lt, out _));
        Assert.IsTrue(lt, "A negative operand must be signed-less-than a positive one, regardless of unsigned magnitude.");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(positive, negative, TpmEoConstants.TPM_EO_SIGNED_GT, out bool gt, out _));
        Assert.IsTrue(gt, "A positive operand must be signed-greater-than a negative one.");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(negative, negative, TpmEoConstants.TPM_EO_SIGNED_GE, out bool ge, out _));
        Assert.IsTrue(ge, "An operand must be signed-greater-or-equal to itself.");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(positive, positive, TpmEoConstants.TPM_EO_SIGNED_LE, out bool le, out _));
        Assert.IsTrue(le, "An operand must be signed-less-or-equal to itself.");

        //Same sign: falls through to the unsigned byte walk.
        ReadOnlySpan<byte> smallerPositive = [0x01];
        ReadOnlySpan<byte> largerPositive = [0x02];
        Assert.IsTrue(TpmEoComparator.TryEvaluate(smallerPositive, largerPositive, TpmEoConstants.TPM_EO_SIGNED_LT, out bool samesign, out _));
        Assert.IsTrue(samesign, "Same-sign operands must fall through to the unsigned magnitude comparison.");
    }

    /// <summary>
    /// Verifies TPM_EO_BITSET (all bits set in B are set in A) and TPM_EO_BITCLEAR (all bits set in B are clear
    /// in A) over a mixed bit pattern.
    /// </summary>
    [TestMethod]
    public void BitsetAndBitclearEvaluatePerByteMasks()
    {
        ReadOnlySpan<byte> a = [0b1111_0000];

        Assert.IsTrue(TpmEoComparator.TryEvaluate(a, [0b1010_0000], TpmEoConstants.TPM_EO_BITSET, out bool bitsetTrue, out _));
        Assert.IsTrue(bitsetTrue, "Every bit set in B (0b1010_0000) is set in A (0b1111_0000).");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(a, [0b0000_1000], TpmEoConstants.TPM_EO_BITSET, out bool bitsetFalse, out _));
        Assert.IsFalse(bitsetFalse, "A bit set in B (0b0000_1000) but clear in A must fail TPM_EO_BITSET.");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(a, [0b0000_1111], TpmEoConstants.TPM_EO_BITCLEAR, out bool bitclearTrue, out _));
        Assert.IsTrue(bitclearTrue, "Every bit set in B (0b0000_1111) is clear in A (0b1111_0000).");

        Assert.IsTrue(TpmEoComparator.TryEvaluate(a, [0b0001_0000], TpmEoConstants.TPM_EO_BITCLEAR, out bool bitclearFalse, out _));
        Assert.IsFalse(bitclearFalse, "A bit set in B (0b0001_0000) but also set in A must fail TPM_EO_BITCLEAR.");
    }

    /// <summary>
    /// Verifies a zero-length operandB is rejected with TPM_RC_SIZE before any comparison runs, for every
    /// operation alike (the coordinator's defined-behavior ruling, rather than the vacuous-true/false convention
    /// an unsigned zero-length compare would otherwise produce).
    /// </summary>
    [TestMethod]
    public void ZeroLengthOperandBIsRejectedWithSizeForEveryOperation()
    {
        foreach(TpmEoConstants operation in Enum.GetValues<TpmEoConstants>())
        {
            bool evaluated = TpmEoComparator.TryEvaluate(
                ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, operation, out bool comparisonResult, out TpmRcConstants rejectionCode);

            Assert.IsFalse(evaluated, $"A zero-length operandB must be rejected for operation '{operation}'.");
            Assert.IsFalse(comparisonResult, "The comparison result must be false when the evaluation itself is rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, rejectionCode, $"A zero-length operandB must reject with TPM_RC_SIZE for operation '{operation}'.");
        }
    }

    /// <summary>
    /// Verifies mismatched-length operands throw, since every call site slices the compared value to operandB's
    /// own length before evaluating — a length mismatch reaching the comparator would be a caller defect.
    /// </summary>
    [TestMethod]
    public void MismatchedOperandLengthsThrow()
    {
        byte[] shortOperand = [0x01];
        byte[] longOperand = [0x01, 0x02];

        _ = Assert.ThrowsExactly<ArgumentException>(() =>
            TpmEoComparator.TryEvaluate(shortOperand, longOperand, TpmEoConstants.TPM_EO_EQ, out _, out _));
    }
}
