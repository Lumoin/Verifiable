using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

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
                device, input, [], pool, registry, cancellationToken).ConfigureAwait(false);

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
