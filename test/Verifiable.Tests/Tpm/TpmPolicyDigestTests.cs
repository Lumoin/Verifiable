using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Known-answer test for <see cref="TpmPolicyDigest.ExtendForSecret"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is the first independent known-answer test pinning <see cref="TpmPolicyDigest"/> to a published spec
/// vector: it reproduces the published endorsement authorization policy value ("PolicyA", TCG EK Credential
/// Profile, Annex B.6.2, Table 33) — <c>SHA256(SHA256(0x00{32} ‖ TPM_CC_PolicySecret ‖ TPM_RH_ENDORSEMENT))</c> —
/// from a fresh (all-zero) SHA-256 policyDigest, <c>authName</c> the 4 big-endian octets of
/// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/>, and an empty policyRef. The formula itself was already deliberately
/// built and verified stage-by-stage against this value (see the remarks on
/// <see cref="TpmPolicyDigest.ExtendForSecret"/>); this test is the durable regression pin, independent of any
/// caller (for example <see cref="Verifiable.Tpm.Infrastructure.Commands.CreatePrimaryInput.ForEndorsementKey"/>)
/// that later predicts the same value.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmPolicyDigestTests
{
    /// <summary>The published endorsement authorization policy value ("PolicyA"), TCG EK Credential Profile, Annex B.6.2, Table 33.</summary>
    private const string PolicyAHex = "837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa";

    /// <summary>The published Name of the well-known RSA EK Certificate NV Index I-1, TCG EK Credential Profile, Annex B.6.3, Table 34.</summary>
    private const string PolicyIndexNameHex = "000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f";

    /// <summary>The published TPM2_PolicyAuthorizeNV fold over NV Index I-1's Name ("PolicyC"), TCG EK Credential Profile, Annex B.6.4, Table 35.</summary>
    private const string PolicyCHex = "3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde";

    /// <summary>The published PolicyOR(PolicyA, PolicyC) value ("PolicyB"), TCG EK Credential Profile, Annex B.6.5, Table 36.</summary>
    private const string PolicyBHex = "ca3d0a99a2b93906f7a3342414efcfb3a385d44cd1fd459089d19b5071c0b7a0";

    /// <summary>NV Index I-1's handle value (TCG EK Credential Profile, Annex B.6.3, Table 34).</summary>
    private const uint NvIndexI1Handle = 0x01C07F01;

    /// <summary>NV Index I-1's TPMA_NV attributes (TCG EK Credential Profile, Annex B.6.3, Table 34).</summary>
    private const uint NvIndexI1Attributes = 0x220F1008;

    /// <summary>NV Index I-1's dataSize field, the reserved size of an RSA-2048 EK certificate (TCG EK Credential Profile, Annex B.6.3, Table 34).</summary>
    private const ushort NvIndexI1DataSize = 0x0022;

    /// <summary>
    /// Verifies <see cref="TpmPolicyDigest.ExtendForSecret"/> reproduces the published endorsement authorization
    /// policy value from a fresh policyDigest, the Endorsement Hierarchy's 4-octet Name, and an empty policyRef.
    /// </summary>
    [TestMethod]
    public void ExtendForSecretReproducesTheEndorsementPolicy()
    {
        Span<byte> current = stackalloc byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256)];
        Span<byte> authName = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, (uint)TpmRh.TPM_RH_ENDORSEMENT);
        Span<byte> destination = stackalloc byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256)];

        int written = TpmPolicyDigest.ExtendForSecret(
            current, authName, ReadOnlySpan<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256, destination);

        Assert.AreEqual(32, written, "SHA-256 PolicyA is 32 octets.");
        Assert.AreEqual(
            PolicyAHex,
            Convert.ToHexStringLower(destination),
            "ExtendForSecret over a fresh policyDigest, TPM_RH_ENDORSEMENT, and an empty policyRef must reproduce the published endorsement authorization policy.");
    }

    /// <summary>
    /// Verifies that an in-test transcription of the marshaled TPMS_NV_PUBLIC for the well-known RSA EK
    /// Certificate NV Index I-1 reproduces its published Name (TCG EK Credential Profile, Annex B.6.3, Table 34):
    /// <c>Name = nameAlg || H_nameAlg(nvIndex || nameAlg || attributes || authPolicy-with-size || dataSize)</c>,
    /// Part 1's Name computation applied to the marshaled public area. <see cref="PolicyAHex"/> is the Index's
    /// authPolicy (already pinned by <see cref="ExtendForSecretReproducesTheEndorsementPolicy"/>).
    /// </summary>
    [TestMethod]
    public void PolicyIndexNameMatchesThePublishedValue()
    {
        Span<byte> nvPublic = stackalloc byte[sizeof(uint) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + 32 + sizeof(ushort)];
        int offset = 0;
        BinaryPrimitives.WriteUInt32BigEndian(nvPublic[offset..], NvIndexI1Handle);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(nvPublic[offset..], (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt32BigEndian(nvPublic[offset..], NvIndexI1Attributes);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(nvPublic[offset..], 32);
        offset += sizeof(ushort);
        Convert.FromHexString(PolicyAHex).CopyTo(nvPublic[offset..]);
        offset += 32;
        BinaryPrimitives.WriteUInt16BigEndian(nvPublic[offset..], NvIndexI1DataSize);

        Span<byte> hash = stackalloc byte[32];
        _ = SHA256.HashData(nvPublic, hash);

        Span<byte> name = stackalloc byte[sizeof(ushort) + 32];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        hash.CopyTo(name[sizeof(ushort)..]);

        Assert.AreEqual(
            PolicyIndexNameHex,
            Convert.ToHexStringLower(name),
            "The marshaled TPMS_NV_PUBLIC's Name must reproduce the published NV Index I-1 Name.");
    }

    /// <summary>
    /// Verifies that an in-test transcription of the TPM2_PolicyAuthorizeNV fold over NV Index I-1's Name
    /// reproduces the published "PolicyC" value (TCG EK Credential Profile, Annex B.6.4, Table 35):
    /// <c>H_SHA256(0x00{32} || TPM_CC_PolicyAuthorizeNV || Name of Policy Index I-1)</c>. This is a one-off
    /// single hash (Part 3's TPM2_PolicyAuthorizeNV, not a reusable <see cref="TpmPolicyDigest"/> primitive), so
    /// no production method exists or is needed for it.
    /// </summary>
    [TestMethod]
    public void PolicyAuthorizeNvFoldMatchesThePublishedPolicyC()
    {
        Span<byte> input = stackalloc byte[32 + sizeof(uint) + 34];
        //The leading 32 octets are the fresh (all-zero) policyDigest PolicyUpdate starts from; they stay zero.
        int offset = 32;
        BinaryPrimitives.WriteUInt32BigEndian(input[offset..], (uint)TpmCcConstants.TPM_CC_PolicyAuthorizeNV);
        offset += sizeof(uint);
        Convert.FromHexString(PolicyIndexNameHex).CopyTo(input[offset..]);

        Span<byte> policyC = stackalloc byte[32];
        _ = SHA256.HashData(input, policyC);

        Assert.AreEqual(
            PolicyCHex,
            Convert.ToHexStringLower(policyC),
            "H(zeros || TPM_CC_PolicyAuthorizeNV || NV Index I-1 Name) must reproduce the published PolicyC.");
    }

    /// <summary>
    /// Verifies that <see cref="TpmPolicyDigest.ExtendForOr"/> over <c>[PolicyA, PolicyC]</c> reproduces the
    /// published "PolicyB" value (TCG EK Credential Profile, Annex B.6.5, Table 36) — a spec-published KAT for
    /// the OR fold itself (Part 3, §23.6, eqs. (17)(18)), as opposed to <see cref="PolicyAuthorizeNvFoldMatchesThePublishedPolicyC"/>,
    /// which pins the one-off hash that produces one of the OR fold's two inputs.
    /// </summary>
    /// <remarks>
    /// <see cref="TpmPolicyDigest.ExtendForOr"/>'s signature carries no "current policyDigest" parameter at all —
    /// unlike every other <c>Extend*</c> method here — because §23.6's Note 2 zero-reset semantics ("reset
    /// policyDigest to the Zero Digest" before hashing) are unconditional for PolicyOR. The omission itself is
    /// the observable proof: there is no way for a caller to make the OR fold depend on a prior digest, so this
    /// single published-vector KAT is already the reset-semantics test the API surface admits.
    /// </remarks>
    [TestMethod]
    public void ExtendForOrReproducesThePublishedPolicyB()
    {
        ReadOnlyMemory<byte> policyA = Convert.FromHexString(PolicyAHex);
        ReadOnlyMemory<byte> policyC = Convert.FromHexString(PolicyCHex);
        Span<byte> destination = stackalloc byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256)];

        int written = TpmPolicyDigest.ExtendForOr([policyA, policyC], TpmAlgIdConstants.TPM_ALG_SHA256, destination);

        Assert.AreEqual(32, written, "SHA-256 PolicyB is 32 octets.");
        Assert.AreEqual(
            PolicyBHex,
            Convert.ToHexStringLower(destination),
            "ExtendForOr over [PolicyA, PolicyC] must reproduce the published PolicyB.");
    }

    /// <summary>
    /// Verifies <see cref="TpmPolicyDigest.ExtendForCommandCode"/> (Part 3, §23.11 TPM2_PolicyCommandCode, eq.
    /// (26)) against an in-test SHA-256 transcription of <c>H(current || TPM_CC_PolicyCommandCode || code)</c>,
    /// across two different restricted command codes — a mismatch would expose a concatenation-order or
    /// field-width mistake in either implementation.
    /// </summary>
    [TestMethod]
    public void ExtendForCommandCodeMatchesAnIndependentTranscriptionAcrossCommandCodes()
    {
        Span<byte> current = stackalloc byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256)];
        Span<byte> destination = stackalloc byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256)];

        AssertCommandCodeFold(current, TpmCcConstants.TPM_CC_PolicyPCR, destination);
        AssertCommandCodeFold(current, TpmCcConstants.TPM_CC_PolicyNV, destination);

        static void AssertCommandCodeFold(ReadOnlySpan<byte> current, TpmCcConstants code, Span<byte> destination)
        {
            int written = TpmPolicyDigest.ExtendForCommandCode(current, code, TpmAlgIdConstants.TPM_ALG_SHA256, destination);

            Span<byte> transcription = stackalloc byte[current.Length + sizeof(uint) + sizeof(uint)];
            current.CopyTo(transcription);
            BinaryPrimitives.WriteUInt32BigEndian(transcription[current.Length..], (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
            BinaryPrimitives.WriteUInt32BigEndian(transcription[(current.Length + sizeof(uint))..], (uint)code);

            Span<byte> expected = stackalloc byte[32];
            _ = SHA256.HashData(transcription, expected);

            Assert.AreEqual(32, written);
            Assert.IsTrue(
                expected.SequenceEqual(destination[..written]),
                $"ExtendForCommandCode must match an independent SHA-256 transcription for code '{code}'.");
        }
    }

    /// <summary>
    /// Verifies <see cref="TpmPolicyDigest.ExtendForAuthValue"/> (Part 3, §23.17 TPM2_PolicyAuthValue, eq. (36))
    /// against an in-test SHA-256 transcription of <c>H(current || TPM_CC_PolicyAuthValue)</c>, from both a
    /// fresh (all-zero) policyDigest and a non-zero starting accumulator — the only free input this fold has,
    /// so exercising both is this fold's field-width/concatenation-order check.
    /// </summary>
    [TestMethod]
    public void ExtendForAuthValueMatchesAnIndependentTranscriptionFromZeroAndNonZeroAccumulators()
    {
        Span<byte> destination = stackalloc byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256)];

        Span<byte> zeroCurrent = stackalloc byte[32];
        AssertAuthValueFold(zeroCurrent, destination);

        Span<byte> nonZeroCurrent = stackalloc byte[32];
        _ = SHA256.HashData("wave6-authvalue-prior-stage"u8, nonZeroCurrent);
        AssertAuthValueFold(nonZeroCurrent, destination);

        static void AssertAuthValueFold(ReadOnlySpan<byte> current, Span<byte> destination)
        {
            int written = TpmPolicyDigest.ExtendForAuthValue(current, TpmAlgIdConstants.TPM_ALG_SHA256, destination);

            Span<byte> transcription = stackalloc byte[current.Length + sizeof(uint)];
            current.CopyTo(transcription);
            BinaryPrimitives.WriteUInt32BigEndian(transcription[current.Length..], (uint)TpmCcConstants.TPM_CC_PolicyAuthValue);

            Span<byte> expected = stackalloc byte[32];
            _ = SHA256.HashData(transcription, expected);

            Assert.AreEqual(32, written);
            Assert.IsTrue(
                expected.SequenceEqual(destination[..written]),
                "ExtendForAuthValue must match an independent SHA-256 transcription.");
        }
    }

    /// <summary>
    /// Verifies <see cref="TpmPolicyDigest.ExtendForPcr"/> (Part 3, §23.7 TPM2_PolicyPCR, eq. (20)) against an
    /// in-test SHA-256 transcription of <c>H(current || TPM_CC_PolicyPCR || pcrs || pcrDigest)</c>, across two
    /// different PCR selections and pcrDigest values, to catch a mistake in either the selection or digest field
    /// placement.
    /// </summary>
    [TestMethod]
    public void ExtendForPcrMatchesAnIndependentTranscriptionAcrossPcrSelections()
    {
        Span<byte> current = stackalloc byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256)];
        Span<byte> destination = stackalloc byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256)];

        //Variant one: a single SHA-256 bank, sizeofSelect 3, PCRs 0-2 selected (pcrSelect 0x07 0x00 0x00).
        ReadOnlySpan<byte> pcrsVariantOne = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, 0x03, 0x07, 0x00, 0x00];
        Span<byte> digestVariantOne = stackalloc byte[32];
        _ = SHA256.HashData("wave6-pcr-variant-one"u8, digestVariantOne);
        AssertPcrFold(current, pcrsVariantOne, digestVariantOne, destination);

        //Variant two: two banks (SHA-256 then SHA-1) with different selection masks and a different pcrDigest.
        ReadOnlySpan<byte> pcrsVariantTwo =
            [0x00, 0x00, 0x00, 0x02, 0x00, 0x0B, 0x03, 0x00, 0x00, 0x01, 0x00, 0x04, 0x03, 0x00, 0x01, 0x00];
        Span<byte> digestVariantTwo = stackalloc byte[32];
        _ = SHA256.HashData("wave6-pcr-variant-two"u8, digestVariantTwo);
        AssertPcrFold(current, pcrsVariantTwo, digestVariantTwo, destination);

        static void AssertPcrFold(
            ReadOnlySpan<byte> current, ReadOnlySpan<byte> marshaledPcrs, ReadOnlySpan<byte> pcrDigest, Span<byte> destination)
        {
            int written = TpmPolicyDigest.ExtendForPcr(current, marshaledPcrs, pcrDigest, TpmAlgIdConstants.TPM_ALG_SHA256, destination);

            Span<byte> transcription = stackalloc byte[current.Length + sizeof(uint) + marshaledPcrs.Length + pcrDigest.Length];
            int offset = 0;
            current.CopyTo(transcription);
            offset += current.Length;
            BinaryPrimitives.WriteUInt32BigEndian(transcription[offset..], (uint)TpmCcConstants.TPM_CC_PolicyPCR);
            offset += sizeof(uint);
            marshaledPcrs.CopyTo(transcription[offset..]);
            offset += marshaledPcrs.Length;
            pcrDigest.CopyTo(transcription[offset..]);

            Span<byte> expected = stackalloc byte[32];
            _ = SHA256.HashData(transcription, expected);

            Assert.AreEqual(32, written);
            Assert.IsTrue(
                expected.SequenceEqual(destination[..written]),
                "ExtendForPcr must match an independent SHA-256 transcription.");
        }
    }

    /// <summary>
    /// Verifies <see cref="TpmPolicyDigest.ExtendForNv"/> (Part 3, §23.9 TPM2_PolicyNV, eqs. (22)(23)) against an
    /// in-test SHA-256 transcription of <c>argHash = H(operandB || offset || operation)</c> followed by
    /// <c>H(current || TPM_CC_PolicyNV || argHash || nvName)</c>, across two variants that each change
    /// <c>operandB</c>, <c>offset</c>, and <c>operation</c> together.
    /// </summary>
    [TestMethod]
    public void ExtendForNvMatchesAnIndependentTranscriptionAcrossComparisonOperands()
    {
        Span<byte> current = stackalloc byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256)];
        Span<byte> destination = stackalloc byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256)];
        Span<byte> nvName = stackalloc byte[sizeof(ushort) + 32];
        BinaryPrimitives.WriteUInt16BigEndian(nvName, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        _ = SHA256.HashData("wave6-nv-index-name"u8, nvName[sizeof(ushort)..]);

        ReadOnlySpan<byte> operandOne = [0x00, 0x00, 0x00, 0x2A];
        AssertNvFold(current, operandOne, offset: 0, operation: (ushort)TpmEoConstants.TPM_EO_EQ, nvName, destination);

        ReadOnlySpan<byte> operandTwo = [0x01, 0x02, 0x03];
        AssertNvFold(current, operandTwo, offset: 12, operation: (ushort)TpmEoConstants.TPM_EO_UNSIGNED_GT, nvName, destination);

        static void AssertNvFold(
            ReadOnlySpan<byte> current, ReadOnlySpan<byte> operandB, ushort offset, ushort operation, ReadOnlySpan<byte> nvName, Span<byte> destination)
        {
            int written = TpmPolicyDigest.ExtendForNv(current, operandB, offset, operation, nvName, TpmAlgIdConstants.TPM_ALG_SHA256, destination);

            Span<byte> argInput = stackalloc byte[operandB.Length + sizeof(ushort) + sizeof(ushort)];
            operandB.CopyTo(argInput);
            BinaryPrimitives.WriteUInt16BigEndian(argInput[operandB.Length..], offset);
            BinaryPrimitives.WriteUInt16BigEndian(argInput[(operandB.Length + sizeof(ushort))..], operation);

            Span<byte> argHash = stackalloc byte[32];
            _ = SHA256.HashData(argInput, argHash);

            Span<byte> transcription = stackalloc byte[current.Length + sizeof(uint) + argHash.Length + nvName.Length];
            int off = 0;
            current.CopyTo(transcription);
            off += current.Length;
            BinaryPrimitives.WriteUInt32BigEndian(transcription[off..], (uint)TpmCcConstants.TPM_CC_PolicyNV);
            off += sizeof(uint);
            argHash.CopyTo(transcription[off..]);
            off += argHash.Length;
            nvName.CopyTo(transcription[off..]);

            Span<byte> expected = stackalloc byte[32];
            _ = SHA256.HashData(transcription, expected);

            Assert.AreEqual(32, written);
            Assert.IsTrue(
                expected.SequenceEqual(destination[..written]),
                "ExtendForNv must match an independent SHA-256 transcription.");
        }
    }
}
