using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Extensions.DictionaryAttack;

/// <summary>
/// Dictionary-attack (lockout) extensions for <see cref="TpmDevice"/>.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class TpmDictionaryAttackExtensions
{
    extension(TpmDevice device)
    {
        /// <summary>
        /// Reads the TPM's dictionary-attack protection parameters (lockout counter, tolerated
        /// failures, decrement interval, recovery time) by querying the variable <c>TPM_PT</c>
        /// properties.
        /// </summary>
        /// <param name="pool">The memory pool for command and response buffers.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>
        /// The parsed DA parameters, or the TPM/transport error that prevented reading them.
        /// </returns>
        public ValueTask<TpmResult<TpmDictionaryAttackParameters>> GetDictionaryAttackParametersAsync(
            MemoryPool<byte> pool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(pool);

            return GetDictionaryAttackParametersCoreAsync(device, pool, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_DictionaryAttackLockReset</c>, resetting <c>failedTries</c> to zero and taking the TPM out
        /// of general Lockout mode, authorized by the lockout hierarchy's authorization value. Permitted even
        /// while the TPM is already in general Lockout mode; refused with <c>TPM_RC_LOCKOUT</c> instead when
        /// lockoutAuth itself is currently disabled by a prior failed attempt.
        /// </summary>
        /// <param name="lockoutAuthSupplied">The caller-supplied lockoutAuth value.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<DictionaryAttackLockResetResponse>> DictionaryAttackLockResetAsync(
            ReadOnlyMemory<byte> lockoutAuthSupplied,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return DictionaryAttackLockResetCoreAsync(device, lockoutAuthSupplied, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_DictionaryAttackParameters</c>, setting <c>maxTries</c>/<c>recoveryTime</c>/
        /// <c>lockoutRecovery</c>, authorized by the lockout hierarchy's authorization value. Deliberately does
        /// not reset <c>failedTries</c> — lowering <paramref name="newMaxTries"/> to at or below the current
        /// failure count takes the TPM into Lockout mode immediately, as a side effect.
        /// </summary>
        /// <param name="lockoutAuthSupplied">The caller-supplied lockoutAuth value.</param>
        /// <param name="newMaxTries">The new tolerated-failure count before Lockout mode engages.</param>
        /// <param name="newRecoveryTime">The new self-heal interval, in seconds; zero disables dictionary-attack protection.</param>
        /// <param name="newLockoutRecovery">The new lockoutAuth recovery wait, in seconds; zero means only a TPM Reset re-arms lockoutAuth.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<DictionaryAttackParametersResponse>> DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte> lockoutAuthSupplied,
            uint newMaxTries,
            uint newRecoveryTime,
            uint newLockoutRecovery,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return DictionaryAttackParametersCoreAsync(device, lockoutAuthSupplied, newMaxTries, newRecoveryTime, newLockoutRecovery, cancellationToken);
        }
    }

    private static async ValueTask<TpmResult<DictionaryAttackLockResetResponse>> DictionaryAttackLockResetCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> lockoutAuthSupplied,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_DictionaryAttackLockReset, TpmResponseCodec.DictionaryAttackLockReset);

        using TpmPasswordSession lockoutSession = TpmPasswordSession.Create(lockoutAuthSupplied.Span, pool);
        var input = new DictionaryAttackLockResetInput(TpmRh.TPM_RH_LOCKOUT);

        return await TpmCommandExecutor.ExecuteAsync<DictionaryAttackLockResetResponse>(
            device, input, [lockoutSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<DictionaryAttackParametersResponse>> DictionaryAttackParametersCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> lockoutAuthSupplied,
        uint newMaxTries,
        uint newRecoveryTime,
        uint newLockoutRecovery,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_DictionaryAttackParameters, TpmResponseCodec.DictionaryAttackParameters);

        using TpmPasswordSession lockoutSession = TpmPasswordSession.Create(lockoutAuthSupplied.Span, pool);
        var input = new DictionaryAttackParametersInput(TpmRh.TPM_RH_LOCKOUT, newMaxTries, newRecoveryTime, newLockoutRecovery);

        return await TpmCommandExecutor.ExecuteAsync<DictionaryAttackParametersResponse>(
            device, input, [lockoutSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<TpmDictionaryAttackParameters>> GetDictionaryAttackParametersCoreAsync(
        TpmDevice device,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        //The four lockout properties are consecutive in the variable property group. Read from the
        //first and follow MoreData until all four have been gathered.
        var properties = new Dictionary<uint, uint>();
        uint property = TpmPtConstants.TPM_PT_LOCKOUT_COUNTER;
        bool hasMoreData = true;

        while(hasMoreData && !HasAllLockoutProperties(properties))
        {
            GetCapabilityInput input = GetCapabilityInput.ForTpmProperties(property);

            TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
                device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

            if(!result.IsSuccess)
            {
                return result.Map<TpmDictionaryAttackParameters>(_ => null!);
            }

            using GetCapabilityResponse response = result.Value;

            hasMoreData = response.MoreData.IsYes;

            IReadOnlyList<TpmsTaggedProperty>? tpmProperties = response.CapabilityData.TpmProperties;
            if(tpmProperties is not { Count: > 0 })
            {
                break;
            }

            foreach(TpmsTaggedProperty taggedProperty in tpmProperties)
            {
                properties[taggedProperty.Property] = taggedProperty.Value;
                property = taggedProperty.Property + 1;
            }
        }

        if(!properties.TryGetValue(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, out uint lockoutCounter)
            || !properties.TryGetValue(TpmPtConstants.TPM_PT_MAX_AUTH_FAIL, out uint maxAuthFail)
            || !properties.TryGetValue(TpmPtConstants.TPM_PT_LOCKOUT_INTERVAL, out uint lockoutInterval)
            || !properties.TryGetValue(TpmPtConstants.TPM_PT_LOCKOUT_RECOVERY, out uint lockoutRecovery))
        {
            //A conformant TPM always reports these variable properties; their absence means the
            //response did not carry the expected lockout data.
            return TpmResult<TpmDictionaryAttackParameters>.TpmError(TpmRcConstants.TPM_RC_VALUE);
        }

        var parameters = new TpmDictionaryAttackParameters(
            lockoutCounter,
            maxAuthFail,
            TimeSpan.FromSeconds(lockoutInterval),
            TimeSpan.FromSeconds(lockoutRecovery));

        return TpmResult<TpmDictionaryAttackParameters>.Success(parameters);
    }

    private static bool HasAllLockoutProperties(Dictionary<uint, uint> properties)
    {
        return properties.ContainsKey(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER)
            && properties.ContainsKey(TpmPtConstants.TPM_PT_MAX_AUTH_FAIL)
            && properties.ContainsKey(TpmPtConstants.TPM_PT_LOCKOUT_INTERVAL)
            && properties.ContainsKey(TpmPtConstants.TPM_PT_LOCKOUT_RECOVERY);
    }
}
