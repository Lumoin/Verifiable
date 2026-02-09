using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Tpm.Extensions.Pcr;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Extensions.Info;

/// <summary>
/// TPM information extensions for <see cref="TpmDevice"/>.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not up to date with latest syntax.")]
public static class TpmDeviceExtensions
{
    extension(TpmDevice device)
    {
        /// <summary>
        /// Gets comprehensive information about the TPM.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Queries the TPM for identity, supported algorithms, ECC curves,
        /// and reads all PCR values. This provides a complete snapshot of
        /// the TPM's configuration and state.
        /// </para>
        /// </remarks>
        /// <returns>A result containing the TPM info or an error.</returns>
        public TpmResult<TpmInfo> GetInfo()
        {
            return GetInfoCore(device);
        }
    }


    private static TpmResult<TpmInfo> GetInfoCore(TpmDevice device)
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        //Get identity from fixed properties.
        var identityResult = GetIdentity(device, pool, registry);
        if(!identityResult.IsSuccess)
        {
            return identityResult.Map<TpmInfo>(_ => null!);
        }

        //Get supported algorithms.
        var algorithmsResult = GetSupportedAlgorithms(device, pool, registry);
        if(!algorithmsResult.IsSuccess)
        {
            return algorithmsResult.Map<TpmInfo>(_ => null!);
        }

        //Get supported ECC curves.
        var curvesResult = GetSupportedCurves(device, pool, registry);
        if(!curvesResult.IsSuccess)
        {
            return curvesResult.Map<TpmInfo>(_ => null!);
        }

        //Reuse the PCR extension.
        TpmResult<PcrSnapshot> pcrsResult = device.ReadAllPcrs();
        if(!pcrsResult.IsSuccess)
        {
            return pcrsResult.Map<TpmInfo>(_ => null!);
        }

        string platform = device.Platform switch
        {
            TpmPlatform.Windows => "Windows",
            TpmPlatform.Linux => "Linux",
            TpmPlatform.Virtual => "Virtual",
            _ => "Unknown"
        };

        var info = new TpmInfo(
            identityResult.Value,
            algorithmsResult.Value,
            curvesResult.Value,
            pcrsResult.Value,
            platform);

        return TpmResult<TpmInfo>.Success(info);
    }

    private static TpmResult<TpmIdentity> GetIdentity(
        TpmDevice device,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry)
    {
        var properties = new Dictionary<uint, uint>();

        //Read all fixed properties with pagination.
        uint property = TpmPtConstants.PT_FIXED;
        bool moreData = true;

        while(moreData)
        {
            var input = GetCapabilityInput.ForTpmProperties(property);

            TpmResult<GetCapabilityResponse> result = TpmCommandExecutor.Execute<GetCapabilityResponse>(
                device, input, [], pool, registry);

            if(!result.IsSuccess)
            {
                return result.Map<TpmIdentity>(_ => null!);
            }

            using GetCapabilityResponse response = result.Value;

            moreData = response.MoreData;

            if(response.CapabilityData.TpmProperties != null && response.CapabilityData.TpmProperties.Count > 0)
            {
                foreach(var prop in response.CapabilityData.TpmProperties)
                {
                    properties[prop.Property] = prop.Value;
                    property = prop.Property + 1;
                }
            }
            else
            {
                moreData = false;
            }
        }

        //Extract identity fields.
        string family = GetFamilyString(properties);
        int revision = (int)properties.GetValueOrDefault(TpmPtConstants.TPM_PT_REVISION, 0u);
        int level = (int)properties.GetValueOrDefault(TpmPtConstants.TPM_PT_LEVEL, 0u);
        string manufacturerId = GetManufacturerString(properties);
        string vendorString = GetVendorString(properties);
        int vendorTpmType = (int)properties.GetValueOrDefault(TpmPtConstants.TPM_PT_VENDOR_TPM_TYPE, 0u);

        //Firmware versions are packed as major.minor in high/low 16 bits.
        uint fwv1 = properties.GetValueOrDefault(TpmPtConstants.TPM_PT_FIRMWARE_VERSION_1, 0u);
        uint fwv2 = properties.GetValueOrDefault(TpmPtConstants.TPM_PT_FIRMWARE_VERSION_2, 0u);
        int fwMajor = (int)(fwv1 >> 16);
        int fwMinor = (int)(fwv1 & 0xFFFF);
        int fwBuild = (int)(fwv2 >> 16);
        int fwPatch = (int)(fwv2 & 0xFFFF);

        int year = (int)properties.GetValueOrDefault(TpmPtConstants.TPM_PT_YEAR, 0u);
        int dayOfYear = (int)properties.GetValueOrDefault(TpmPtConstants.TPM_PT_DAY_OF_YEAR, 0u);
        int pcrCount = (int)properties.GetValueOrDefault(TpmPtConstants.TPM_PT_PCR_COUNT, 0u);
        int maxInputBuffer = (int)properties.GetValueOrDefault(TpmPtConstants.TPM_PT_INPUT_BUFFER, 0u);
        int maxNvBuffer = (int)properties.GetValueOrDefault(TpmPtConstants.TPM_PT_NV_BUFFER_MAX, 0u);

        var identity = new TpmIdentity(
            family,
            revision,
            level,
            manufacturerId,
            vendorString,
            vendorTpmType,
            fwMajor,
            fwMinor,
            fwBuild,
            fwPatch,
            year,
            dayOfYear,
            pcrCount,
            maxInputBuffer,
            maxNvBuffer);

        return TpmResult<TpmIdentity>.Success(identity);
    }

    private static TpmResult<List<string>> GetSupportedAlgorithms(
        TpmDevice device,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry)
    {
        var input = GetCapabilityInput.ForAlgorithms();

        TpmResult<GetCapabilityResponse> result = TpmCommandExecutor.Execute<GetCapabilityResponse>(
            device, input, [], pool, registry);

        if(!result.IsSuccess)
        {
            return result.Map<List<string>>(_ => null!);
        }

        using GetCapabilityResponse response = result.Value;

        var algorithms = new List<string>();

        if(response.CapabilityData.Algorithms != null)
        {
            foreach(var alg in response.CapabilityData.Algorithms)
            {
                algorithms.Add(GetAlgorithmName(alg.Algorithm));
            }
        }

        return TpmResult<List<string>>.Success(algorithms);
    }

    private static TpmResult<List<string>> GetSupportedCurves(
        TpmDevice device,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry)
    {
        var input = GetCapabilityInput.ForEccCurves();

        TpmResult<GetCapabilityResponse> result = TpmCommandExecutor.Execute<GetCapabilityResponse>(
            device, input, [], pool, registry);

        if(!result.IsSuccess)
        {
            //ECC curves might not be supported - return empty list instead of error.
            if(result.IsTpmError)
            {
                return TpmResult<List<string>>.Success([]);
            }

            return result.Map<List<string>>(_ => null!);
        }

        using GetCapabilityResponse response = result.Value;

        var curves = new List<string>();

        if(response.CapabilityData.EccCurves != null)
        {
            foreach(var curve in response.CapabilityData.EccCurves)
            {
                curves.Add(GetCurveName(curve));
            }
        }

        return TpmResult<List<string>>.Success(curves);
    }

    private static string GetFamilyString(Dictionary<uint, uint> properties)
    {
        uint value = properties.GetValueOrDefault(TpmPtConstants.TPM_PT_FAMILY_INDICATOR, 0u);

        //Family indicator is a 4-octet ASCII string packed into uint32.
        //For TPM 2.0, this is "2.0\0" (0x322E3000).
        Span<byte> bytes = stackalloc byte[4];
        bytes[0] = (byte)(value >> 24);
        bytes[1] = (byte)(value >> 16);
        bytes[2] = (byte)(value >> 8);
        bytes[3] = (byte)value;

        return Encoding.ASCII.GetString(bytes).TrimEnd('\0');
    }

    private static string GetManufacturerString(Dictionary<uint, uint> properties)
    {
        uint value = properties.GetValueOrDefault(TpmPtConstants.TPM_PT_MANUFACTURER, 0u);

        Span<byte> bytes = [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value];
        return Encoding.ASCII.GetString(bytes);
    }

    private static string GetVendorString(Dictionary<uint, uint> properties)
    {
        var sb = new StringBuilder(16);

        uint[] vendorProps =
        [
            TpmPtConstants.TPM_PT_VENDOR_STRING_1,
            TpmPtConstants.TPM_PT_VENDOR_STRING_2,
            TpmPtConstants.TPM_PT_VENDOR_STRING_3,
            TpmPtConstants.TPM_PT_VENDOR_STRING_4
        ];

        Span<byte> bytes = stackalloc byte[4];

        foreach(uint prop in vendorProps)
        {
            uint value = properties.GetValueOrDefault(prop, 0u);

            if(value == 0)
            {
                continue;
            }

            bytes[0] = (byte)(value >> 24);
            bytes[1] = (byte)(value >> 16);
            bytes[2] = (byte)(value >> 8);
            bytes[3] = (byte)value;

            for(int i = 0; i < 4; i++)
            {
                if(bytes[i] != 0)
                {
                    sb.Append((char)bytes[i]);
                }
            }
        }

        return sb.ToString();
    }

    private static string GetAlgorithmName(TpmAlgIdConstants algorithm)
    {
        return algorithm switch
        {
            TpmAlgIdConstants.TPM_ALG_RSA => "RSA",
            TpmAlgIdConstants.TPM_ALG_SHA1 => "SHA1",
            TpmAlgIdConstants.TPM_ALG_HMAC => "HMAC",
            TpmAlgIdConstants.TPM_ALG_AES => "AES",
            TpmAlgIdConstants.TPM_ALG_MGF1 => "MGF1",
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH => "KEYEDHASH",
            TpmAlgIdConstants.TPM_ALG_XOR => "XOR",
            TpmAlgIdConstants.TPM_ALG_SHA256 => "SHA256",
            TpmAlgIdConstants.TPM_ALG_SHA384 => "SHA384",
            TpmAlgIdConstants.TPM_ALG_SHA512 => "SHA512",
            TpmAlgIdConstants.TPM_ALG_NULL => "NULL",
            TpmAlgIdConstants.TPM_ALG_SM3_256 => "SM3_256",
            TpmAlgIdConstants.TPM_ALG_SM4 => "SM4",
            TpmAlgIdConstants.TPM_ALG_RSASSA => "RSASSA",
            TpmAlgIdConstants.TPM_ALG_RSAES => "RSAES",
            TpmAlgIdConstants.TPM_ALG_RSAPSS => "RSAPSS",
            TpmAlgIdConstants.TPM_ALG_OAEP => "OAEP",
            TpmAlgIdConstants.TPM_ALG_ECDSA => "ECDSA",
            TpmAlgIdConstants.TPM_ALG_ECDH => "ECDH",
            TpmAlgIdConstants.TPM_ALG_ECDAA => "ECDAA",
            TpmAlgIdConstants.TPM_ALG_SM2 => "SM2",
            TpmAlgIdConstants.TPM_ALG_ECSCHNORR => "ECSCHNORR",
            TpmAlgIdConstants.TPM_ALG_ECMQV => "ECMQV",
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A => "KDF1_SP800_56A",
            TpmAlgIdConstants.TPM_ALG_KDF2 => "KDF2",
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 => "KDF1_SP800_108",
            TpmAlgIdConstants.TPM_ALG_ECC => "ECC",
            TpmAlgIdConstants.TPM_ALG_SYMCIPHER => "SYMCIPHER",
            TpmAlgIdConstants.TPM_ALG_CAMELLIA => "CAMELLIA",
            TpmAlgIdConstants.TPM_ALG_SHA3_256 => "SHA3_256",
            TpmAlgIdConstants.TPM_ALG_SHA3_384 => "SHA3_384",
            TpmAlgIdConstants.TPM_ALG_SHA3_512 => "SHA3_512",
            TpmAlgIdConstants.TPM_ALG_CTR => "CTR",
            TpmAlgIdConstants.TPM_ALG_OFB => "OFB",
            TpmAlgIdConstants.TPM_ALG_CBC => "CBC",
            TpmAlgIdConstants.TPM_ALG_CFB => "CFB",
            TpmAlgIdConstants.TPM_ALG_ECB => "ECB",
            _ => $"ALG_0x{(ushort)algorithm:X4}"
        };
    }

    private static string GetCurveName(TpmEccCurveConstants curve)
    {
        return curve switch
        {
            TpmEccCurveConstants.TPM_ECC_NIST_P192 => "NIST_P192",
            TpmEccCurveConstants.TPM_ECC_NIST_P224 => "NIST_P224",
            TpmEccCurveConstants.TPM_ECC_NIST_P256 => "NIST_P256",
            TpmEccCurveConstants.TPM_ECC_NIST_P384 => "NIST_P384",
            TpmEccCurveConstants.TPM_ECC_NIST_P521 => "NIST_P521",
            TpmEccCurveConstants.TPM_ECC_BN_P256 => "BN_P256",
            TpmEccCurveConstants.TPM_ECC_BN_P638 => "BN_P638",
            TpmEccCurveConstants.TPM_ECC_SM2_P256 => "SM2_P256",
            _ => $"CURVE_0x{(ushort)curve:X4}"
        };
    }
}