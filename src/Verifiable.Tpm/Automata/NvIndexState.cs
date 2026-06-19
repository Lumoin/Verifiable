using System;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a single defined NV Index: the persistent identity, authorization value,
/// attributes, and size established by <c>TPM2_NV_DefineSpace()</c>. This is the smallest NV-Index model
/// the dictionary-attack/PIN flow needs — an NV Index is the lightest entity whose authValue can be made
/// dictionary-attack protected (TPM 2.0 Library Part 1, clause 17.8.1), which hierarchy authValues cannot.
/// </summary>
/// <remarks>
/// <para>
/// The authorization value is held as a plain <see cref="ReadOnlyMemory{T}"/> rather than a pooled buffer:
/// it is durable model state owned by the live automaton for the lifetime of the simulated TPM, mirroring
/// how <see cref="TpmExchange"/> holds recorded command/response octets. The hot command/response wire path
/// remains pool-backed; only the device's own persistent state lives here.
/// </para>
/// <para>
/// Written-ness (<c>TPMA_NV_WRITTEN</c>) and the data area itself are not modelled in this slice: there is
/// no <c>TPM2_NV_Write()</c> yet, so a defined Index is always uninitialized and a successful read returns
/// <c>TPM_RC_NV_UNINITIALIZED</c>. Both arrive with the write command.
/// </para>
/// </remarks>
/// <param name="NvIndex">The NV Index handle (its most-significant octet is <c>TPM_HT_NV_INDEX</c>).</param>
/// <param name="AuthValue">The Index authorization value supplied at definition; compared against a caller's authorization on access.</param>
/// <param name="Attributes">The Index attributes (<c>TPMA_NV</c>) set at definition.</param>
/// <param name="DataSize">The size in octets of the Index data area declared at definition.</param>
public sealed record NvIndexState(
    uint NvIndex,
    ReadOnlyMemory<byte> AuthValue,
    TpmaNv Attributes,
    ushort DataSize)
{
    /// <summary>
    /// Gets a value indicating whether this Index is dictionary-attack protected: an authorization
    /// failure against it feeds the lockout counter and is blocked in lockout, unless
    /// <see cref="TpmaNv.TPMA_NV_NO_DA"/> is set (TPM 2.0 Library Part 2, clause 13.4; Part 1, clause 17.8).
    /// </summary>
    public bool IsDaProtected => (Attributes & TpmaNv.TPMA_NV_NO_DA) == 0;

    /// <summary>
    /// Gets a value indicating whether this Index may be read using its authorization value: only when
    /// <see cref="TpmaNv.TPMA_NV_AUTHREAD"/> is set (TPM 2.0 Library Part 2, clause 13.4). With the bit
    /// clear the Index authValue cannot authorize a read, even when the supplied value matches.
    /// </summary>
    public bool IsAuthReadAllowed => (Attributes & TpmaNv.TPMA_NV_AUTHREAD) != 0;
}
