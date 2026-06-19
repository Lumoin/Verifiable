using System;
using System.Buffers;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Globalization;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Core;
using Verifiable.Cryptography.Cbom;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Info;

namespace Verifiable;

/// <summary>
/// Shared operations for DID, VC, and TPM functionality.
/// Used by both CLI commands and MCP tools.
/// </summary>
internal static class VerifiableOperations
{
    /// <summary>
    /// Gets a description of the current operating system platform.
    /// </summary>
    public static string PlatformDescription => RuntimeInformation.OSDescription;


    /// <summary>
    /// Gets TPM information as a structured object.
    /// </summary>
    public static async Task<Result<TpmInfo, string>> GetTpmInfoAsync()
    {
        if(!TpmDevice.IsAvailable)
        {
            return Result.Failure<TpmInfo, string>("TPM is not available on this platform.");
        }

        try
        {
            using TpmDevice device = TpmDevice.Open();
            TpmResult<TpmInfo> result = await device.GetInfoAsync().ConfigureAwait(false);

            return result.Match(
                onSuccess: Result.Success<TpmInfo, string>,
                onTpmError: rc => Result.Failure<TpmInfo, string>($"TPM error: {rc}"),
                onTransportError: tc => Result.Failure<TpmInfo, string>($"Transport error: 0x{tc:X8}"));
        }
        catch(Exception ex)
        {
            return Result.Failure<TpmInfo, string>($"Error retrieving TPM information: {ex.Message}");
        }
    }


    /// <summary>
    /// Gets TPM information as a JSON string.
    /// </summary>
    public static async Task<Result<string, string>> GetTpmInfoAsJsonAsync()
    {
        var infoResult = await GetTpmInfoAsync().ConfigureAwait(false);

        if(!infoResult.IsSuccess)
        {
            return Result.Failure<string, string>(infoResult.Error!);
        }

        return Result.Success<string, string>(JsonSerializer.Serialize(infoResult.Value, TpmJsonContext.Default.TpmInfo));
    }


    /// <summary>
    /// Saves TPM information to a JSON file.
    /// </summary>
    public static async Task<Result<string, string>> SaveTpmInfoToFileAsync(string? filePath = null)
    {
        string targetPath = filePath ?? "tpm_data.json";
        var infoResult = await GetTpmInfoAsJsonAsync().ConfigureAwait(false);
        if(!infoResult.IsSuccess)
        {
            return Result.Failure<string, string>(infoResult.Error!);
        }

        try
        {
            await File.WriteAllTextAsync(targetPath, infoResult.Value).ConfigureAwait(false);
            return Result.Success<string, string>(Path.GetFullPath(targetPath));
        }
        catch(Exception ex)
        {
            return Result.Failure<string, string>($"Error saving TPM information: {ex.Message}");
        }
    }


    /// <summary>
    /// Checks if TPM is supported and available on this platform.
    /// </summary>
    /// <returns>A message describing TPM support status.</returns>
    public static string CheckTpmSupportMessage()
    {
        string os = PlatformDescription;
        if(TpmDevice.IsAvailable)
        {
            return $"TPM is supported and available on this platform ({os}).";
        }

        return $"TPM is not supported or not available on this platform ({os}).";
    }


    /// <summary>
    /// Emits the declarative ("capabilities") CBOM as CycloneDX 1.6 JSON: every
    /// cryptographic asset the library can describe, independent of the wired provider.
    /// </summary>
    public static Result<string, string> EmitDeclarativeCbom()
    {
        try
        {
            CbomDocument document = DeclarativeCbomGenerator.Generate(CurrentTimestamp(), ToolVersion);
            return Result.Success<string, string>(CbomJsonRenderer.Render(document));
        }
        catch(Exception ex)
        {
            return Result.Failure<string, string>($"Error generating declarative CBOM: {ex.Message}");
        }
    }


    /// <summary>
    /// Runs a small real cryptographic workload through the wired provider under a scoped
    /// observer and emits the observed ("runtime") CBOM as CycloneDX 1.6 JSON.
    /// </summary>
    /// <remarks>
    /// The workload exercises ECDSA P-256 sign and verify, a SHA-256 digest, and an
    /// entropy-backed salt and nonce — all through the registered Microsoft provider, so
    /// the captured <c>crypto.*</c> telemetry reflects work that actually executed.
    /// </remarks>
    public static async Task<Result<string, string>> EmitObservedCbomAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            CryptoProviderStartup.EnsureRegistered();

            using CbomObserver observer = new();
            CbomDocument document = await observer.ObserveAsync(
                () => RunObservableWorkloadAsync(cancellationToken),
                CurrentTimestamp(),
                ToolVersion).ConfigureAwait(false);

            return Result.Success<string, string>(CbomJsonRenderer.Render(document));
        }
        catch(Exception ex)
        {
            return Result.Failure<string, string>($"Error generating observed CBOM: {ex.Message}");
        }
    }


    //A minimal real workload that produces crypto.* telemetry spans: P-256 sign/verify,
    //a SHA-256 digest, and entropy-backed salt and nonce. Everything routes through the
    //registered Microsoft provider rather than System.Security.Cryptography directly.
    private static async Task RunObservableWorkloadAsync(CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] payload = Encoding.UTF8.GetBytes("Verifiable CBOM observed workload payload.");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            MicrosoftKeyMaterialCreator.CreateP256Keys(pool);

        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        using Signature signature = await MicrosoftCryptographicFunctions.SignP256Async(
            privateKey.AsReadOnlyMemory(), payload, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        _ = await MicrosoftCryptographicFunctions.VerifyP256Async(
            payload, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(), cancellationToken: cancellationToken).ConfigureAwait(false);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            payload, outputByteLength: 32, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        using Salt salt = CryptographicKeyEvents.GenerateSalt(32, CryptoTags.MdocIssuerSignedItemRandom, pool);

        using Nonce nonce = CryptographicKeyEvents.GenerateNonce(16, CryptoTags.AesGcmIv, pool);
        _ = nonce.UseNonce();
    }


    private static string CurrentTimestamp() =>
        TimeProvider.System.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);


    private static string ToolVersion =>
        typeof(VerifiableOperations).Assembly.GetName().Version?.ToString() ?? "0.0.0";


    public static Result<string, string> CreateDid(int id, string param, string? extraParam = null)
    {
        var result = new StringBuilder();
        result.Append("Created DID document with ID: ");
        result.Append(id.ToString(CultureInfo.InvariantCulture));
        result.AppendLine();
        result.Append("Parameter: ");
        result.Append(param);
        result.AppendLine();

        if(!string.IsNullOrEmpty(extraParam))
        {
            result.Append("Extra parameter: ");
            result.Append(extraParam);
            result.AppendLine();
        }

        //TODO: Implement actual DID creation logic.
        result.AppendLine("Note: This is a placeholder. Actual DID creation is not yet implemented.");

        return Result.Success<string, string>(result.ToString());
    }


    public static Result<string, string> RevokeDid(int id)
    {
        //TODO: Implement actual DID revocation logic.
        return Result.Success<string, string>(
            $"Revoked DID document with ID: {id}\nNote: This is a placeholder. Actual DID revocation is not yet implemented.");
    }


    public static Result<string, string> ListDids()
    {
        //TODO: Implement actual DID listing logic.
        return Result.Success<string, string>(
            "Listing all DID documents.\nNote: This is a placeholder. Actual DID listing is not yet implemented.");
    }


    public static Result<string, string> ViewDid(int id)
    {
        //TODO: Implement actual DID viewing logic.
        return Result.Success<string, string>(
            $"Viewing DID document with ID: {id}\nNote: This is a placeholder. Actual DID viewing is not yet implemented.");
    }
}
