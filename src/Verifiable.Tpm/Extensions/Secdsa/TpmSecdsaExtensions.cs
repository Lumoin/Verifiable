using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Extensions.Secdsa;

/// <summary>
/// SECDSA operation extensions for <see cref="TpmDevice"/>.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class TpmSecdsaExtensions
{
    extension(TpmDevice device)
    {
        /// <summary>
        /// Performs an ECDH point multiplication using a TPM-bound key.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Executes TPM2_ECDH_ZGen (TPM 2.0 Part 3, Section 14.5), computing
        /// Z = [h·d<sub>S</sub>]Q<sub>B</sub> where d<sub>S</sub> is the private key
        /// bound to <paramref name="keyHandle"/> and Q<sub>B</sub> is
        /// <paramref name="inPoint"/>. The cofactor h is determined by the curve.
        /// </para>
        /// <para>
        /// The key referenced by <paramref name="keyHandle"/> must be an unrestricted
        /// ECC decryption key (DECRYPT attribute set, RESTRICTED attribute clear) with
        /// scheme TPM_ALG_ECDH or TPM_ALG_NULL. Use
        /// <see cref="CreatePrimaryInput.ForEccKeyAgreementKey"/> to create a suitable key.
        /// </para>
        /// <para>
        /// The caller is responsible for disposing the returned
        /// <see cref="EcdhZGenResponse"/> when the result is successful.
        /// </para>
        /// </remarks>
        /// <param name="keyHandle">The handle of the loaded ECC key.</param>
        /// <param name="inPoint">
        /// The input point Q<sub>B</sub> in uncompressed encoding
        /// (<c>0x04 || X || Y</c>). The point must lie on the curve of the key.
        /// </param>
        /// <param name="pool">The memory pool for coordinate buffer allocation.</param>
        /// <returns>
        /// A <see cref="TpmResult{T}"/> containing the output point on success,
        /// or a TPM or transport error.
        /// </returns>
        public TpmResult<EcdhZGenResponse> EcdhZGen(
            TpmiDhObject keyHandle,
            ReadOnlySpan<byte> inPoint,
            MemoryPool<byte> pool)
        {
            return ExecuteEcdhZGen(device, keyHandle, inPoint, pool);
        }
    }

    private static TpmResult<EcdhZGenResponse> ExecuteEcdhZGen(
        TpmDevice device,
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> inPoint,
        MemoryPool<byte> pool)
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_ECDH_ZGen, TpmResponseCodec.EcdhZGen);

        using EcdhZGenInput ecdhInput = EcdhZGenInput.FromUncompressedPoint(keyHandle, inPoint, pool);
        using var keyAuth = TpmPasswordSession.CreateEmpty(pool);

        return TpmCommandExecutor.Execute<EcdhZGenResponse>(
            device, ecdhInput, [keyAuth], pool, registry);
    }
}