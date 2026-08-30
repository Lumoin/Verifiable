using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Policy;

/// <summary>
/// Signs a TPM2_PolicySigned <c>aHash</c> for a <see cref="SignedPolicyAssertion"/>'s replay. The context is an
/// explicit parameter — never a captured closure — so a caller-supplied signing capability carries no ambient
/// state and every call site's data flows through the same, auditable path.
/// </summary>
/// <param name="aHash">The <c>aHash</c> to sign, already built under the assertion's scheme hash algorithm; a borrow the delegate must not retain.</param>
/// <param name="context">Caller-supplied context (for example, a signing backend and key handle), passed through verbatim.</param>
/// <param name="pool">The memory pool backing the returned signature.</param>
/// <param name="cancellationToken">A token observed across the exchange.</param>
/// <returns>The signature as a pooled carrier the caller owns and disposes: IEEE P1363 <c>r ‖ s</c> for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.</returns>
public delegate ValueTask<Signature> TpmPolicySignedSigningDelegate(DigestValue aHash, object? context, BaseMemoryPool pool, CancellationToken cancellationToken);

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
/// A TPM2_PolicyCounterTimer assertion: require the TPM's live TPMS_TIME_INFO to compare to an operand.
/// </summary>
/// <param name="OperandB">The value to compare the live TPMS_TIME_INFO against.</param>
/// <param name="Offset">The octet offset into the marshaled TPMS_TIME_INFO.</param>
/// <param name="Operation">The TPM_EO comparison operation.</param>
public sealed record CounterTimerPolicyAssertion(ReadOnlyMemory<byte> OperandB, ushort Offset, TpmEoConstants Operation): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyOR assertion over precomputed branch digests. Build each branch as its own
/// <see cref="TpmPolicy"/> and pass its <see cref="TpmPolicy.ComputeDigest"/> result; nested OR is not modelled.
/// </summary>
/// <param name="BranchDigests">The OR branch policy digests (the alternatives).</param>
public sealed record OrPolicyAssertion(IReadOnlyList<ReadOnlyMemory<byte>> BranchDigests): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyPassword assertion: require the authorized object's authorization value, presented as a
/// cleartext password rather than an HMAC over it.
/// </summary>
public sealed record PasswordPolicyAssertion: TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyCpHash assertion: restrict the session to the command whose parameters hash to
/// <see cref="CpHashA"/>.
/// </summary>
/// <param name="CpHashA">The command parameter digest the policy binds to.</param>
public sealed record CpHashPolicyAssertion(ReadOnlyMemory<byte> CpHashA): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyNameHash assertion: restrict the session to the command whose target entity's Name(s) hash to
/// <see cref="NameHash"/>.
/// </summary>
/// <param name="NameHash">The digest of the concatenated target Names the policy binds to.</param>
public sealed record NameHashPolicyAssertion(ReadOnlyMemory<byte> NameHash): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyDuplicationSelect assertion: qualify a duplication to the new parent named by
/// <see cref="NewParentName"/> — and, with <see cref="IsObjectIncluded"/> SET, to the object named by
/// <see cref="ObjectName"/> alone — restricting the session to <c>TPM_CC_Duplicate</c> of that pair.
/// </summary>
/// <param name="ObjectName">The Name of the object to be duplicated.</param>
/// <param name="NewParentName">The Name of the new parent.</param>
/// <param name="IsObjectIncluded">Whether the object Name is folded into the policyDigest.</param>
public sealed record DuplicationSelectPolicyAssertion(ReadOnlyMemory<byte> ObjectName, ReadOnlyMemory<byte> NewParentName, bool IsObjectIncluded): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyParameters assertion: restrict the session to the command whose command code and parameters
/// hash to <see cref="ParametersHash"/>, whatever objects it references.
/// </summary>
/// <param name="ParametersHash">The digest of the command code and parameters the policy binds to.</param>
public sealed record ParametersPolicyAssertion(ReadOnlyMemory<byte> ParametersHash): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyTemplate assertion: restrict object creation to the template whose digest is
/// <see cref="TemplateHash"/>.
/// </summary>
/// <param name="TemplateHash">The digest of the bound object template.</param>
public sealed record TemplatePolicyAssertion(ReadOnlyMemory<byte> TemplateHash): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyLocality assertion: restrict the session to commands issued from one of the localities in
/// <see cref="Locality"/>.
/// </summary>
/// <param name="Locality">The set of localities the policy admits (TPM 2.0 Part 2, Section 8.5, Table 39).</param>
public sealed record LocalityPolicyAssertion(TpmaLocality Locality): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyNvWritten assertion: require the target NV Index's TPMA_NV_WRITTEN attribute to match
/// <see cref="IsWrittenSet"/>.
/// </summary>
/// <param name="IsWrittenSet"><see langword="true"/> to require TPMA_NV_WRITTEN SET (YES); <see langword="false"/> to require it CLEAR (NO).</param>
public sealed record NvWrittenPolicyAssertion(bool IsWrittenSet): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyAuthorizeNV assertion: replace the policyDigest with the fold over an NV Index's own Name (TPM
/// 2.0 Part 3, Section 23.22, equation 9), letting the Index's held authPolicy stand in for the session's.
/// </summary>
/// <param name="AuthHandle">The authorization handle for reading the Index.</param>
/// <param name="NvIndex">The NV Index whose held authPolicy authorizes the session.</param>
/// <param name="NvName">The NV Index's Name (<c>nameAlg || H(TPMS_NV_PUBLIC)</c>), needed to fold the digest.</param>
public sealed record AuthorizeNvPolicyAssertion(uint AuthHandle, uint NvIndex, ReadOnlyMemory<byte> NvName): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicySigned assertion: bind the policy to a signature over <c>aHash</c> made by the key at
/// <see cref="AuthObject"/>. Replay always uses an empty caller nonceTPM and an empty cpHashA (a
/// session-unbound, command-unbound authorization) — the simplest form, mirroring how <see cref="WithSecret"/>'s
/// own <see cref="SecretPolicyAssertion"/> covers only permanent handles. The signing step is an explicit
/// delegate, never a captured closure: <see cref="Sign"/> receives <see cref="SigningContext"/> as a plain
/// parameter on every call.
/// </summary>
/// <param name="AuthObject">The handle of the key whose public part validates the signature.</param>
/// <param name="AuthName">The Name of that key (<c>nameAlg || H(TPMT_PUBLIC)</c>), folded into the predicted digest.</param>
/// <param name="PolicyRef">The opaque policy qualifier; empty for none (the second fold still runs).</param>
/// <param name="Expiration">The signed expiration; 0 = no expiry (an empty caller nonceTPM makes a non-zero value an absolute Time-base deadline).</param>
/// <param name="SignatureScheme">The signing scheme (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>).</param>
/// <param name="SchemeHashAlg">H_authAlg: the hash algorithm the signature carries, independent of the session's own policy hash algorithm.</param>
/// <param name="Sign">The signing delegate invoked at replay time with the freshly built <c>aHash</c>.</param>
/// <param name="SigningContext">Caller-supplied context passed to <see cref="Sign"/> verbatim (no closure capture).</param>
public sealed record SignedPolicyAssertion(
    uint AuthObject,
    ReadOnlyMemory<byte> AuthName,
    ReadOnlyMemory<byte> PolicyRef,
    int Expiration,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants SchemeHashAlg,
    TpmPolicySignedSigningDelegate Sign,
    object? SigningContext): TpmPolicyAssertion;

/// <summary>
/// A TPM2_PolicyAuthorize assertion: replace the policyDigest with a value that depends only on the authority's
/// key and the policy qualifier (TPM 2.0 Library Part 3, Section 23.16), letting the session accept a policy the
/// authority can revise at will.
/// </summary>
/// <param name="ApprovedPolicy">The policyDigest being approved; must equal the session's current policyDigest at replay time.</param>
/// <param name="PolicyRef">The opaque policy qualifier; empty for none (the second fold still runs).</param>
/// <param name="KeySign">The Name of the key that signed the approval (its first two octets select <c>aHash</c>'s hash algorithm).</param>
/// <param name="CheckTicket">The verification ticket (a genuine TPM2_VerifySignature() ticket, or <see cref="TpmtTkVerified.Null"/> for a trial session); a borrow whose owner outlives the replay.</param>
public sealed record AuthorizePolicyAssertion(
    ReadOnlyMemory<byte> ApprovedPolicy,
    ReadOnlyMemory<byte> PolicyRef,
    ReadOnlyMemory<byte> KeySign,
    TpmtTkVerified CheckTicket): TpmPolicyAssertion;
