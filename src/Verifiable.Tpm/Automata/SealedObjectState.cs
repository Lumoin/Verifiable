using System;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a loaded sealed data object: the sensitive data recovered from a wrapped blob by
/// <c>TPM2_Load()</c> and addressed by a transient handle (most-significant octet <c>TPM_HT_TRANSIENT</c>,
/// TPM 2.0 Library Part 2, clause 7.2). It is the smallest object model the seal-then-unseal path needs — the
/// retained sealed octets a subsequent <c>TPM2_Unseal()</c> returns.
/// </summary>
/// <remarks>
/// <para>
/// Like <see cref="TransientKeyState"/> and <see cref="NvIndexState"/>, the data is held as plain
/// <see cref="ReadOnlyMemory{T}"/> rather than pooled buffers: it is durable model state owned by the live
/// automaton for the lifetime of the simulated object, not hot wire-path memory. The sealed data is sensitive,
/// exactly as an object's private key or an NV Index authorization value is.
/// </para>
/// <para>
/// A real TPM recovers the sealed data by unwrapping the parent-encrypted, integrity-protected private blob; the
/// simulator does not model parent-key wrapping (it has no parent symmetric-key custody), so it recovers the data
/// from its own private-blob encoding (TPM 2.0 Library Part 1, clause 24; Part 3, clauses 12.1 / 12.7).
/// </para>
/// </remarks>
/// <param name="Handle">The transient handle assigned to the loaded object.</param>
/// <param name="Data">The recovered sealed data returned by <c>TPM2_Unseal()</c>.</param>
/// <param name="AuthPolicy">
/// The object's authorization policy digest, carried in its public area (empty when the object is authorized by
/// its authValue alone). A subsequent <c>TPM2_Unseal()</c> over a policy session is authorized only when the
/// session's accumulated policyDigest reproduces this value (TPM 2.0 Library Part 3, clause 12.7; Part 1, clause
/// 19.7); an empty authPolicy leaves the object outside the policy path.
/// </param>
public sealed record SealedObjectState(
    uint Handle,
    ReadOnlyMemory<byte> Data,
    ReadOnlyMemory<byte> AuthPolicy);
