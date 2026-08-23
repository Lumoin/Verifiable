using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Extensions.Nv;

/// <summary>
/// NV Index public-metadata extensions for <see cref="TpmDevice"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Sessionless by spec, not by omission.</b> <c>TPM2_NV_ReadPublic</c> carries <c>Auth Index: None</c>
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, Section 31.6.1): the public area of an NV Index is not privacy-sensitive, so the
/// command needs no authorization session and is unconditionally world-readable, exactly like
/// <c>TPM2_PolicyTicket</c>/<c>TPM2_PolicySigned</c> (<c>Extensions/Policy</c>'s <c>PolicyTicketAsync</c>/
/// <c>PolicySignedAsync</c>). This is the one command in the
/// whole NV family a caller can issue against an Index that has never been written, is READLOCKED, or is
/// WRITELOCKED - none of those gates apply, because the command never touches the data area (Part 3, Section
/// 5.4's lock-gate clauses are conditioned on "the command requires read/write access to the index data", which
/// this command never does).
/// </para>
/// <para>
/// <b>Why this group exists.</b> An NV Index's Name is <c>nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)</c> (TPM
/// 2.0 Library Part 1, Section 14, Table 6), the digest covering the whole marshaled public area - whose own
/// first field is the Index handle, so the handle is hashed once as part of it and never prepended a second
/// time - a value only the TPM's own retained public area can produce,
/// because <c>TPMA_NV_WRITTEN</c> lives inside the hashed attributes field and flips the Name the moment the
/// Index is first written. Every HMAC-session authorization over a multi-handle NV command (<c>NV_Write</c>,
/// <c>NV_Read</c>, <c>NV_UndefineSpace</c>) needs that real, current Name to feed the command's cpHash (Part 1,
/// Section 16.7, equation 15) - a caller cannot safely recompute it blind from locally cached attributes, since a
/// stale WRITTEN flag alone would silently desynchronize the cpHash from what the TPM computes. <c>NvReadPublicAsync</c>
/// is that authoritative source; <c>Extensions/Pin</c>'s bound- and unbound-HMAC verbs compose it internally for
/// exactly this reason.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class TpmDeviceExtensions
{
    extension(TpmDevice device)
    {
        /// <summary>
        /// Runs <c>TPM2_NV_ReadPublic</c>, returning <paramref name="nvIndex"/>'s public area and its current
        /// Name.
        /// </summary>
        /// <remarks>
        /// <para>
        /// No authorization is presented or checked (<c>Auth Index: None</c>, TPM 2.0 Library Part 3, Section
        /// 31.6): the command is sent with <c>TPM_ST_NO_SESSIONS</c> and no auth area at all, mirroring
        /// <c>PolicyTicketAsync</c>/<c>PolicySignedAsync</c> in <c>Extensions/Policy</c>. The only failures
        /// are the generic handle-validation ladder (Part 3, Section 5.4): <c>TPM_RC_VALUE</c> when
        /// <paramref name="nvIndex"/> is outside the NV-Index handle range (caught at unmarshal time by
        /// <c>TPMI_RH_NV_INDEX</c>'s own interface-type check), or <c>TPM_RC_HANDLE</c> when it is in range but no
        /// Index is currently defined there. Success is unconditional otherwise - never gated on
        /// <c>TPMA_NV_WRITTEN</c>/<c>TPMA_NV_READLOCKED</c>/<c>TPMA_NV_WRITELOCKED</c>, which this command's own
        /// text explicitly does not check (it never accesses the data area those attributes protect).
        /// </para>
        /// <para>
        /// The returned Name (<c>nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)</c>, TPM 2.0 Library Part 1, Section
        /// 14, Table 6; Part 2, Section 13.6, Table 235) hashes the whole public area including
        /// <c>TPMA_NV_WRITTEN</c>, so it changes the instant the Index is first written - callers deriving a
        /// cpHash Name for this Index use <see cref="NvReadPublicResponse.NvName"/> verbatim rather than
        /// recomputing it from a locally cached copy of the attributes.
        /// </para>
        /// </remarks>
        /// <param name="nvIndex">The NV Index whose public area and Name are read.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the public area and Name (dispose the response to release it), or an error.</returns>
        public ValueTask<TpmResult<NvReadPublicResponse>> NvReadPublicAsync(
            uint nvIndex, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return NvReadPublicCoreAsync(device, nvIndex, cancellationToken);
        }
    }

    /// <summary>
    /// Composes <c>TPM2_NV_ReadPublic</c> against <paramref name="nvIndex"/> with no authorization area at all.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The NV Index to read.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The read result.</returns>
    private static async ValueTask<TpmResult<NvReadPublicResponse>> NvReadPublicCoreAsync(
        TpmDevice device, uint nvIndex, CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic);

        var input = new NvReadPublicInput(nvIndex);

        //NV_ReadPublic carries no authorization at all: nvIndex needs none (Auth Index: None, TPM 2.0 Library
        //Part 3, Section 31.6), so the executor is given no sessions and frames TPM_ST_NO_SESSIONS, exactly as
        //TPM2_PolicyTicket/TPM2_PolicySigned do.
        return await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }
}
