using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Shared plumbing for <c>TPM2_EvictControl()</c> across the simulator acceptance tests: one password-authorized
/// call that persists a loaded transient object at a persistent handle, or evicts a persistent object already
/// there, over the production wire path (<see cref="TpmCommandExecutor"/>, the real device verbs and codecs), so
/// each command's own class carries only its normative assertions rather than a copy of this plumbing.
/// </summary>
internal static class TpmEvictControlHarness
{
    /// <summary>
    /// Issues <c>TPM2_EvictControl()</c> under <paramref name="authHandle"/>'s authorization to persist
    /// <paramref name="objectHandle"/> at <paramref name="persistentHandle"/>, or to evict the persistent object
    /// <paramref name="objectHandle"/> already names, and returns the raw result for the caller to assert either
    /// the successful outcome or a specific refusal.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The transient object to persist, or the persistent object to evict.</param>
    /// <param name="persistentHandle">The persistent handle to assign or evict.</param>
    /// <param name="authHandle">The <c>TPMI_RH_PROVISION</c> handle named in the command's @auth slot; defaults to the owner hierarchy.</param>
    /// <param name="auth">The password authorizing <paramref name="authHandle"/>; empty (the default) authorizes with the Empty Buffer.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    public static async Task<TpmResult<EvictControlResponse>> EvictControlAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle, uint persistentHandle,
        TpmRh authHandle = TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte> auth = default, CancellationToken cancellationToken = default)
    {
        using TpmPasswordSession authSession = TpmPasswordSession.Create(auth.Span, pool);
        var input = new EvictControlInput(authHandle, objectHandle, persistentHandle);

        return await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
            tpm, input, [authSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }
}
