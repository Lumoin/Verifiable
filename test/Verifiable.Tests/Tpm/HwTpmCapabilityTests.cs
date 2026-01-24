using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Diagnostic tests that dump TPM capabilities and PCR values.
/// </summary>
[TestClass]
[DoNotParallelize]
[SkipIfNoTpm]
[TestCategory("RequiresHardwareTpm")]
public class HwTpmCapabilityTests
{
    /// <summary>
    /// The TPM device for the tests.
    /// </summary>
    private static TpmDevice Tpm { get; set; } = null!;

    /// <summary>
    /// Whether a TPM device is available.
    /// </summary>
    private static bool HasTpm { get; set; } = false;


    /// <summary>
    /// The test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    [ClassInitialize]
    public static void ClassInit(TestContext context)
    {
        if(TpmDevice.IsAvailable)
        {
            HasTpm = true;
            Tpm = TpmDevice.Open();
        }
    }


    [TestInitialize]
    public void TestInit()
    {
        if(!HasTpm)
        {
            Assert.Inconclusive(TestInfrastructureConstants.NoTpmDeviceAvailableMessage);
        }
    }


    [ClassCleanup]
    public static void ClassCleanup()
    {
        if(HasTpm)
        {
            Tpm.Dispose();
        }
    }


    [TestMethod]
    public void DumpTpmFixedProperties()
    {        
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        TestContext.WriteLine("=== TPM Fixed Properties (PT_FIXED) ===");
        TestContext.WriteLine("");

        //PT_FIXED starts at 0x100.
        DumpTpmProperties(Tpm, pool, registry, 0x100);
    }


    [TestMethod]
    public void DumpTpmVariableProperties()
    {        
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        TestContext.WriteLine("=== TPM Variable Properties (PT_VAR) ===");
        TestContext.WriteLine("");

        //PT_VAR starts at 0x200.
        DumpTpmProperties(Tpm, pool, registry, 0x200);
    }


    [TestMethod]
    public void DumpSupportedAlgorithms()
    {        
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        TestContext.WriteLine("=== Supported Algorithms ===");
        TestContext.WriteLine("");

        var input = GetCapabilityInput.ForAlgorithms();
        TpmResult<GetCapabilityResponse> result = TpmCommandExecutor.Execute<GetCapabilityResponse>(
            Tpm, input, [], pool, registry);

        AssertUtilities.AssertSuccess(result, "GetCapability(ALGS)");

        using GetCapabilityResponse response = result.Value;
        if(response.CapabilityData.Algorithms != null)
        {
            TestContext.WriteLine($"{"Algorithm",-25} {"Attributes"}");
            TestContext.WriteLine(new string('-', 50));

            foreach(var alg in response.CapabilityData.Algorithms)
            {
                TestContext.WriteLine($"{alg.Algorithm,-25} {alg.AlgorithmAttributes}");
            }
        }
    }


    [TestMethod]
    public void DumpSupportedEccCurves()
    {
        using TpmDevice device = TpmDevice.Open();
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        TestContext.WriteLine("=== Supported ECC Curves ===");
        TestContext.WriteLine("");

        var input = GetCapabilityInput.ForEccCurves();

        TpmResult<GetCapabilityResponse> result = TpmCommandExecutor.Execute<GetCapabilityResponse>(
            device, input, [], pool, registry);

        AssertUtilities.AssertSuccess(result, "GetCapability(ECC_CURVES)");

        using GetCapabilityResponse response = result.Value;

        if(response.CapabilityData.EccCurves != null)
        {
            foreach(var curve in response.CapabilityData.EccCurves)
            {
                TestContext.WriteLine($"  {curve} (0x{(ushort)curve:X4})");
            }
        }
    }


    [TestMethod]
    public void DumpPcrBanks()
    {        
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        TestContext.WriteLine("=== PCR Banks (Allocation) ===");
        TestContext.WriteLine("");

        var input = GetCapabilityInput.ForPcrs();
        TpmResult<GetCapabilityResponse> result = TpmCommandExecutor.Execute<GetCapabilityResponse>(
            Tpm, input, [], pool, registry);

        AssertUtilities.AssertSuccess(result, "GetCapability(PCRS)");

        using GetCapabilityResponse response = result.Value;
        if(response.CapabilityData.PcrSelection != null)
        {
            foreach(var selection in response.CapabilityData.PcrSelection.Selections)
            {
                var selectedPcrs = GetSelectedPcrIndices(selection);
                TestContext.WriteLine($"  {selection.HashAlgorithm}: PCRs {string.Join(", ", selectedPcrs)}");
            }
        }
    }

    [TestMethod]
    public void DumpPcrValues()
    {
        using TpmDevice device = TpmDevice.Open();
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);

        TestContext.WriteLine("=== PCR Values (SHA-256 Bank, All 24 PCRs) ===");
        TestContext.WriteLine("");
        TestContext.WriteLine("PCR Usage per TCG PC Client Platform TPM Profile:");
        TestContext.WriteLine("  0     - CRTM (Core Root of Trust for Measurement)");
        TestContext.WriteLine("  1     - Platform firmware");
        TestContext.WriteLine("  2     - Option ROM code");
        TestContext.WriteLine("  3     - Option ROM config");
        TestContext.WriteLine("  4     - Boot manager");
        TestContext.WriteLine("  5     - Boot configuration");
        TestContext.WriteLine("  6     - State transitions");
        TestContext.WriteLine("  7     - Secure Boot policy");
        TestContext.WriteLine("  8-15  - OS / loader defined");
        TestContext.WriteLine("  16-23 - Dynamic / OS / hypervisor");
        TestContext.WriteLine("");

        //Read all 24 PCRs with pagination.
        var allResults = ReadAllPcrs(device, pool, registry, TpmAlgIdConstants.TPM_ALG_SHA256, 24);

        if(allResults.Count > 0)
        {
            TestContext.WriteLine($"PCR Update Counter: {allResults[0].UpdateCounter}");
            TestContext.WriteLine("");
            foreach(var (pcrIndex, digest, _) in allResults)
            {
                bool isZero = IsAllZero(digest);
                bool isAllF = IsAllOnes(digest);

                string status = isZero ? " (zero - not extended)" : (isAllF ? " (all 0xFF - error/reset)" : "");

                TestContext.WriteLine($"PCR[{pcrIndex,2}]: {Convert.ToHexString(digest)}{status}");
            }
        }
    }


    [TestMethod]
    public void DumpAllPcrBanksAndValues()
    {        
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);

        TestContext.WriteLine("=== All PCR Banks and Values ===");
        TestContext.WriteLine("");

        //First, get the PCR allocation to see which banks exist.
        var capInput = GetCapabilityInput.ForPcrs();
        TpmResult<GetCapabilityResponse> capResult = TpmCommandExecutor.Execute<GetCapabilityResponse>(
            Tpm, capInput, [], pool, registry);

        AssertUtilities.AssertSuccess(capResult, "GetCapability(PCRS)");

        using GetCapabilityResponse capResponse = capResult.Value;
        if(capResponse.CapabilityData.PcrSelection == null)
        {
            TestContext.WriteLine("No PCR banks found.");
            return;
        }

        //For each bank, read all 24 PCRs with pagination.
        foreach(var selection in capResponse.CapabilityData.PcrSelection.Selections)
        {
            TestContext.WriteLine($"--- {selection.HashAlgorithm} Bank ---");

            var allResults = ReadAllPcrs(Tpm, pool, registry, (TpmAlgIdConstants)selection.HashAlgorithm, 24);

            if(allResults.Count > 0)
            {
                foreach(var (pcrIndex, digest, _) in allResults)
                {
                    TestContext.WriteLine($"  PCR[{pcrIndex,2}]: {Convert.ToHexString(digest)}");
                }
            }
            else
            {
                TestContext.WriteLine("  No PCR values returned.");
            }

            TestContext.WriteLine("");
        }
    }

    /// <summary>
    /// Reads all requested PCRs using pagination.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The TPM2_PCR_Read command may not return all requested PCRs in a single call
    /// if the response would exceed the maximum response size. This method handles
    /// pagination by comparing pcrSelectionOut with the requested selection and
    /// continuing until all PCRs are read.
    /// </para>
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response registry.</param>
    /// <param name="hashAlgorithm">The hash algorithm for the PCR bank.</param>
    /// <param name="pcrCount">The number of PCRs to read (starting from 0).</param>
    /// <returns>A list of tuples containing PCR index, digest bytes, and update counter.</returns>
    private List<(int PcrIndex, byte[] Digest, uint UpdateCounter)> ReadAllPcrs(
        TpmDevice device,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry,
        TpmAlgIdConstants hashAlgorithm,
        int pcrCount)
    {
        var results = new List<(int PcrIndex, byte[] Digest, uint UpdateCounter)>();

        //Build the set of PCRs we still need to read.
        var remainingPcrs = new HashSet<int>();
        for(int i = 0; i < pcrCount; i++)
        {
            remainingPcrs.Add(i);
        }

        int maxIterations = 10;
        int iteration = 0;

        while(remainingPcrs.Count > 0 && iteration < maxIterations)
        {
            iteration++;

            //Create input for remaining PCRs.
            int[] pcrArray = [.. remainingPcrs];
            Array.Sort(pcrArray);

            using var input = PcrReadInput.ForPcrs(hashAlgorithm, pcrArray, pool);

            TpmResult<PcrReadResponse> result = TpmCommandExecutor.Execute<PcrReadResponse>(
                device, input, [], pool, registry);

            if(!result.IsSuccess)
            {
                TestContext.WriteLine($"  PCR_Read failed: {(result.IsTpmError ? result.ResponseCode.ToString() : "transport error")}");
                break;
            }

            using PcrReadResponse response = result.Value;

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
                //No PCRs returned, stop.
                break;
            }

            //Pair up PCR indices with values and add to results.
            for(int i = 0; i < response.PcrValues.Count && i < readPcrs.Count; i++)
            {
                var digest = response.PcrValues[i];
                int pcrIndex = readPcrs[i];

                //Copy the digest since the response will be disposed.
                byte[] digestCopy = digest.AsReadOnlySpan().ToArray();

                results.Add((pcrIndex, digestCopy, response.PcrUpdateCounter));
                remainingPcrs.Remove(pcrIndex);
            }
        }

        //Sort results by PCR index.
        results.Sort((a, b) => a.PcrIndex.CompareTo(b.PcrIndex));

        return results;
    }

    private void DumpTpmProperties(TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry, uint startProperty)
    {
        uint property = startProperty;
        bool moreData = true;

        while(moreData)
        {
            var input = GetCapabilityInput.ForTpmProperties(property);

            TpmResult<GetCapabilityResponse> result = TpmCommandExecutor.Execute<GetCapabilityResponse>(
                device, input, [], pool, registry);

            AssertUtilities.AssertSuccess(result, $"GetCapability(TPM_PROPERTIES, 0x{property:X})");

            using GetCapabilityResponse response = result.Value;

            moreData = response.MoreData;

            if(response.CapabilityData.TpmProperties != null && response.CapabilityData.TpmProperties.Count > 0)
            {
                foreach(var prop in response.CapabilityData.TpmProperties)
                {
                    //Use the existing extension method for formatting.
                    TestContext.WriteLine($"  {prop.GetDescription()}");

                    //Update property for next iteration.
                    property = prop.Property + 1;
                }
            }
            else
            {
                moreData = false;
            }
        }
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

    private static bool IsAllZero(ReadOnlySpan<byte> data)
    {
        foreach(byte b in data)
        {
            if(b != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAllOnes(ReadOnlySpan<byte> data)
    {
        foreach(byte b in data)
        {
            if(b != 0xFF)
            {
                return false;
            }
        }

        return true;
    }    
}