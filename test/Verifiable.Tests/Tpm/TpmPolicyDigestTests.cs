using System;
using System.Buffers.Binary;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

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
}
