using System;
using Verifiable.Tpm.Spec.Algorithms;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves how <see cref="TpmsTaggedPolicy"/> reads a policy slot that was never set. The structure is a value
/// type whose <c>policyHash</c> is a <c>TPMT_HA</c> reference (TPM 2.0 Library Part 2, clause 10.7.4, Table 119),
/// so <c>default(TpmsTaggedPolicy)</c> — the shape any array, collection slot, or uninitialized local takes —
/// leaves that reference unset. Every accessor reads it as <see cref="TpmtHa.Null"/>, which is exactly the value
/// the table gives a handle with no policy restriction, so the default-valued structure reports "no policy"
/// rather than faulting.
/// </summary>
[TestClass]
internal sealed class TpmsTaggedPolicyTests
{
    /// <summary>
    /// A default-valued <see cref="TpmsTaggedPolicy"/> reports an empty policy, an empty policy-hash rendering,
    /// and a description naming no policy — each read without throwing, so an unset slot is interpretable
    /// rather than a fault waiting on the first accessor.
    /// </summary>
    [TestMethod]
    public void DefaultTaggedPolicyReportsAnEmptyPolicyWithoutThrowing()
    {
        TpmsTaggedPolicy policy = default;

        Assert.IsTrue(
            policy.HasEmptyPolicy(),
            "An unset policyHash is TPM_ALG_NULL-shaped, which Table 119 gives a handle with no policy restriction.");

        Assert.AreEqual(
            string.Empty, policy.GetPolicyHashHex(),
            "A handle with no policy restriction has no digest octets to render.");

        Assert.Contains(
            "no policy", policy.GetDescription(),
            "The description of a handle with no policy restriction must say so rather than render a digest.");
    }

    /// <summary>
    /// A tagged policy carrying a real <c>TPMT_HA</c> is not read as empty, so the coalescing the default case
    /// relies on cannot be masking a genuinely present policy.
    /// </summary>
    [TestMethod]
    public void TaggedPolicyCarryingADigestIsNotReportedEmpty()
    {
        byte[] digest =
            [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
             0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30];

        using TpmtHa policyHash = TpmtHa.Create(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), digest, BaseMemoryPool.Shared);
        var policy = new TpmsTaggedPolicy((uint)TpmRh.TPM_RH_OWNER, policyHash);

        Assert.IsFalse(policy.HasEmptyPolicy(), "A SHA-256 policy digest is a policy restriction.");

        Assert.AreEqual(
            Convert.ToHexString(digest), policy.GetPolicyHashHex(),
            "The rendered policy hash is exactly the digest the structure carries.");
    }
}
