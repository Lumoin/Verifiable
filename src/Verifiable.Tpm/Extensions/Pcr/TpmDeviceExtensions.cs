using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Extensions.Pcr;

/// <summary>
/// PCR-related extensions for <see cref="TpmDevice"/>.
/// </summary>
public static class TpmDeviceExtensions
{
    extension(TpmDevice device)
    {
        /// <summary>
        /// Reads all PCR values from all active banks.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Queries the TPM for available PCR banks and reads all allocated PCR values.
        /// Banks with no allocated PCRs are not included in the result.
        /// Pagination is handled automatically.
        /// </para>
        /// </remarks>
        /// <returns>A result containing the PCR snapshot or an error.</returns>
        public TpmResult<PcrSnapshot> ReadAllPcrs()
        {
            return ReadAllPcrsCore(device);
        }
    }

    private static TpmResult<PcrSnapshot> ReadAllPcrsCore(TpmDevice device)
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);

        //Discover available PCR banks.
        var capInput = GetCapabilityInput.ForPcrs();
        TpmResult<GetCapabilityResponse> capResult = TpmCommandExecutor.Execute<GetCapabilityResponse>(
            device, capInput, [], pool, registry);

        if(!capResult.IsSuccess)
        {
            return capResult.Map<PcrSnapshot>(_ => null!);
        }

        using GetCapabilityResponse capResponse = capResult.Value;

        if(capResponse.CapabilityData.PcrSelection == null)
        {
            //No PCR banks - return empty snapshot.
            return TpmResult<PcrSnapshot>.Success(new PcrSnapshot(
                [],
                updateCounter: 0,
                isConsistent: true));
        }

        var banks = new List<PcrBank>();
        uint? firstUpdateCounter = null;
        uint lastUpdateCounter = 0;
        bool isConsistent = true;

        //Read each bank that has allocated PCRs.
        foreach(var selection in capResponse.CapabilityData.PcrSelection.Selections)
        {
            //Get which PCRs are allocated in this bank.
            var allocatedPcrs = GetSelectedPcrIndices(selection);

            if(allocatedPcrs.Count == 0)
            {
                //Bank exists but has no PCRs allocated, skip it.
                continue;
            }

            var bankResult = ReadBankWithPagination(
                device, pool, registry, selection.HashAlgorithm, allocatedPcrs);

            if(!bankResult.IsSuccess)
            {
                return bankResult.Map<PcrSnapshot>(_ => null!);
            }

            var (bank, updateCounter, bankConsistent) = bankResult.Value;

            banks.Add(bank);
            lastUpdateCounter = updateCounter;

            if(!firstUpdateCounter.HasValue)
            {
                firstUpdateCounter = updateCounter;
            }
            else if(updateCounter != firstUpdateCounter.Value)
            {
                isConsistent = false;
            }

            if(!bankConsistent)
            {
                isConsistent = false;
            }
        }

        return TpmResult<PcrSnapshot>.Success(new PcrSnapshot(
            banks,
            lastUpdateCounter,
            isConsistent));
    }

    private static TpmResult<(PcrBank Bank, uint UpdateCounter, bool IsConsistent)> ReadBankWithPagination(
        TpmDevice device,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry,
        TpmAlgIdConstants hashAlgorithm,
        List<int> allocatedPcrs)
    {
        var values = new Dictionary<int, byte[]>();
        var remainingPcrs = new HashSet<int>(allocatedPcrs);

        uint? firstUpdateCounter = null;
        uint lastUpdateCounter = 0;
        bool isConsistent = true;
        int digestSize = 0;

        const int maxIterations = 10;

        for(int iteration = 0; iteration < maxIterations && remainingPcrs.Count > 0; iteration++)
        {
            int[] pcrArray = [.. remainingPcrs];
            Array.Sort(pcrArray);

            using var input = PcrReadInput.ForPcrs(hashAlgorithm, pcrArray, pool);

            TpmResult<PcrReadResponse> result = TpmCommandExecutor.Execute<PcrReadResponse>(
                device, input, [], pool, registry);

            if(!result.IsSuccess)
            {
                return result.Map<(PcrBank, uint, bool)>(_ => default);
            }

            using PcrReadResponse response = result.Value;

            lastUpdateCounter = response.PcrUpdateCounter;

            if(!firstUpdateCounter.HasValue)
            {
                firstUpdateCounter = lastUpdateCounter;
            }
            else if(lastUpdateCounter != firstUpdateCounter.Value)
            {
                isConsistent = false;
            }

            //Get which PCRs were actually returned.
            var readPcrs = new List<int>();
            foreach(var sel in response.PcrSelectionOut.Selections)
            {
                if(sel.HashAlgorithm == hashAlgorithm)
                {
                    readPcrs.AddRange(GetSelectedPcrIndices(sel));
                }
            }

            if(readPcrs.Count == 0)
            {
                break;
            }

            //Collect the values.
            for(int i = 0; i < response.PcrValues.Count && i < readPcrs.Count; i++)
            {
                var digest = response.PcrValues[i];
                int pcrIndex = readPcrs[i];

                //Copy the digest since the response will be disposed.
                byte[] digestCopy = digest.AsReadOnlySpan().ToArray();
                values[pcrIndex] = digestCopy;
                remainingPcrs.Remove(pcrIndex);

                if(digestSize == 0)
                {
                    digestSize = digestCopy.Length;
                }
            }
        }

        string algorithmName = GetAlgorithmName(hashAlgorithm);
        var bank = new PcrBank(algorithmName, digestSize, values);

        return TpmResult<(PcrBank, uint, bool)>.Success((bank, lastUpdateCounter, isConsistent));
    }

    private static List<int> GetSelectedPcrIndices(TpmsPcrSelection selection)
    {
        var indices = new List<int>();
        ReadOnlySpan<byte> bitmap = selection.PcrSelect.Span;

        for(int byteIndex = 0; byteIndex < bitmap.Length; byteIndex++)
        {
            for(int bitIndex = 0; bitIndex < 8; bitIndex++)
            {
                if((bitmap[byteIndex] & (1 << bitIndex)) != 0)
                {
                    indices.Add(byteIndex * 8 + bitIndex);
                }
            }
        }

        return indices;
    }

    private static string GetAlgorithmName(TpmAlgIdConstants algorithm)
    {
        return algorithm switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA1 => "SHA1",
            TpmAlgIdConstants.TPM_ALG_SHA256 => "SHA256",
            TpmAlgIdConstants.TPM_ALG_SHA384 => "SHA384",
            TpmAlgIdConstants.TPM_ALG_SHA512 => "SHA512",
            TpmAlgIdConstants.TPM_ALG_SM3_256 => "SM3_256",
            TpmAlgIdConstants.TPM_ALG_SHA3_256 => "SHA3_256",
            TpmAlgIdConstants.TPM_ALG_SHA3_384 => "SHA3_384",
            TpmAlgIdConstants.TPM_ALG_SHA3_512 => "SHA3_512",
            _ => $"ALG_0x{(ushort)algorithm:X4}"
        };
    }
}