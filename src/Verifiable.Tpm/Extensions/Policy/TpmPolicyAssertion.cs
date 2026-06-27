using System;
using System.Collections.Generic;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Extensions.Policy;

/// <summary>
/// A single assertion in a <see cref="TpmPolicy"/>. This is a closed data union (the concrete kinds below);
/// the behaviour — folding into a policyDigest and replaying on a session — lives in <see cref="TpmPolicy"/>,
/// not on the assertion, so the assertions stay pure descriptions.
/// </summary>
public abstract record TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyCommandCode assertion: restrict the session to a single command.
/// </summary>
/// <param name="CommandCode">The command code the policy is restricted to.</param>
public sealed record CommandCodePolicyAssertion(TpmCcConstants CommandCode): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyAuthValue assertion: require the authorized object's authorization value.
/// </summary>
public sealed record AuthValuePolicyAssertion: TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicySecret assertion against a permanent handle (whose Name is its 4-byte handle value), with an
/// empty policyRef — for example <c>TPM_RH_ENDORSEMENT</c> for the endorsement-key policy.
/// </summary>
/// <param name="AuthHandle">The permanent handle whose authorization the policy requires.</param>
public sealed record SecretPolicyAssertion(uint AuthHandle): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyPCR assertion: bind the policy to a set of PCRs.
/// </summary>
/// <param name="PcrBank">The PCR bank (hash algorithm).</param>
/// <param name="PcrIndices">The PCR indices (0-23) to bind to.</param>
/// <param name="PcrDigest">The expected digest of the selected PCR values, or empty to bind to the current state.</param>
public sealed record PcrPolicyAssertion(TpmAlgIdConstants PcrBank, int[] PcrIndices, ReadOnlyMemory<byte> PcrDigest): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyNV assertion: require the contents of an NV Index to compare to an operand.
/// </summary>
/// <param name="AuthHandle">The authorization handle for reading the Index.</param>
/// <param name="NvIndex">The NV Index whose contents are compared.</param>
/// <param name="OperandB">The value to compare against.</param>
/// <param name="Offset">The octet offset into the NV data.</param>
/// <param name="Operation">The TPM_EO comparison operation.</param>
/// <param name="NvName">The NV Index Name (<c>nameAlg || H(TPMS_NV_PUBLIC)</c>), needed to fold the digest.</param>
public sealed record NvPolicyAssertion(uint AuthHandle, uint NvIndex, ReadOnlyMemory<byte> OperandB, ushort Offset, TpmEoConstants Operation, ReadOnlyMemory<byte> NvName): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyOR assertion over precomputed branch digests. Build each branch as its own
/// <see cref="TpmPolicy"/> and pass its <see cref="TpmPolicy.ComputeDigest"/> result; nested OR is not modelled.
/// </summary>
/// <param name="BranchDigests">The OR branch policy digests (the alternatives).</param>
public sealed record OrPolicyAssertion(IReadOnlyList<ReadOnlyMemory<byte>> BranchDigests): TpmPolicyAssertion;
