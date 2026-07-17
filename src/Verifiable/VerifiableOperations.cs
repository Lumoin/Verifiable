using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
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
using Verifiable.Cryptography.Context;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Info;

namespace Verifiable;

/// <summary>
/// Shared operations for DID, VC, and TPM functionality.
/// Used by both CLI commands and MCP tools. The FIDO2/WebAuthn verbs live in the sibling partial
/// <c>VerifiableOperations.Fido2.cs</c>.
/// </summary>
internal static partial class VerifiableOperations
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
    /// <param name="includeEventProvenance">
    /// When <see langword="true"/>, subscribes to <see cref="CryptographicKeyEvents.Events"/> for exactly
    /// this workload run's duration (<see cref="CryptoEventProvenance.CaptureAsync{TResult}"/> disposes the
    /// subscription before returning) and appends a compact provenance summary — see
    /// <see cref="CryptoEventProvenance.RenderSummary"/> — after the CBOM JSON, separated by
    /// <see cref="CryptoEventProvenance.SectionHeader"/>. The CBOM JSON itself is identical either way;
    /// see <see cref="CryptoEventProvenance"/>'s remarks for why the two mechanisms are never merged.
    /// Defaults to <see langword="false"/>, which reproduces this method's pre-wave-7 output exactly.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the workload.</param>
    public static async Task<Result<string, string>> EmitObservedCbomAsync(
        bool includeEventProvenance = false,
        CancellationToken cancellationToken = default)
    {
        try
        {
            CryptoProviderStartup.EnsureRegistered();

            using CbomObserver observer = new();

            if(!includeEventProvenance)
            {
                CbomDocument document = await observer.ObserveAsync(
                    () => RunObservableWorkloadAsync(cancellationToken),
                    CurrentTimestamp(),
                    ToolVersion).ConfigureAwait(false);

                return Result.Success<string, string>(CbomJsonRenderer.Render(document));
            }

            (CbomDocument observedDocument, IReadOnlyList<CryptoEvent> events) = await CryptoEventProvenance.CaptureAsync(
                () => observer.ObserveAsync(
                    () => RunObservableWorkloadAsync(cancellationToken),
                    CurrentTimestamp(),
                    ToolVersion)).ConfigureAwait(false);

            string cbomJson = CbomJsonRenderer.Render(observedDocument);
            string summary = CryptoEventProvenance.RenderSummary(events);

            return Result.Success<string, string>(
                $"{cbomJson}{Environment.NewLine}{Environment.NewLine}{CryptoEventProvenance.SectionHeader}{Environment.NewLine}{summary}");
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

        //Routes through the CreateKeyPair choke point so the observed CBOM's provenance also carries the
        //KeyMaterialGeneratedEvent for this workload's mint step (the sign/verify events immediately below
        //are still discarded — see the comment there — because they call the backend function directly).
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Signing, pool);

        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        //Discards the SignatureProducedEvent/VerificationCompletedEvent: this synthetic workload calls the
        //backend function directly rather than through PrivateKey.SignAsync/PublicKey.VerifyAsync, and the
        //emit hook is internal to Verifiable.Cryptography. The Activity spans these calls emit are what
        //EmitCbom --observe actually reads (CBOM and CryptoEvent are separate mechanisms).
        (Signature signature, CryptoEvent? _) = await MicrosoftCryptographicFunctions.SignP256Async(
            privateKey.AsReadOnlyMemory(), payload, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        using(signature)
        {
            _ = await MicrosoftCryptographicFunctions.VerifyP256Async(
                payload, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(), cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        //JOSE-signed leg (wave-7 PKG-3): unlike the raw backend call directly above, Jws.SignAsync/
        //VerifyAsync resolve the registry delegate through the wave-7 CryptoEventSink seam (PKG-1), which
        //forwards to CryptographicKeyEvents.DefaultSink when no explicit sink is supplied — no eventSink
        //parameter is even passed here. This leg's SignatureProducedEvent/VerificationCompletedEvent
        //therefore DO reach the global stream by default, demonstrating the widened path alongside the
        //choke-point path the FIDO2 leg below already exercises (both land in the same CBOM --observe
        //--events provenance summary — see CryptoEventProvenance).
        using JwsMessage observedJws = await Jws.SignAsync(
            ObservedJoseWorkloadHeaderJson,
            ObservedJoseWorkloadPayloadJson,
            EncodeObservedJwtPart,
            Base64Url.EncodeToString,
            privateKey,
            pool,
            cancellationToken).ConfigureAwait(false);

        _ = await Jws.VerifyAsync(
            observedJws,
            Base64Url.EncodeToString,
            publicKey,
            pool,
            cancellationToken).ConfigureAwait(false);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            payload, outputByteLength: 32, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        using Salt salt = CryptographicKeyEvents.GenerateSalt(32, CryptoTags.MdocIssuerSignedItemRandom, pool);

        using Nonce nonce = CryptographicKeyEvents.GenerateNonce(16, CryptoTags.AesGcmIv, pool);
        _ = nonce.UseNonce();

        //A real FIDO2 assertion ceremony, so the observed CBOM also carries FIDO2 provenance
        //(the sign/verify Activity spans, and the SignatureProducedEvent/VerificationCompletedEvent this
        //ceremony emits via the PrivateKey.SignAsync/PublicKey.VerifyAsync choke point).
        await RunFido2ObservedWorkloadAsync(cancellationToken).ConfigureAwait(false);
    }


    //Pre-built JOSE header/payload JSON for the observed workload's JWS leg. Raw string literals rather
    //than JsonSerializer.Serialize<Dictionary<string, object>> — this project publishes with PublishAot,
    //and this content has no need for a dictionary round trip (nothing downstream inspects header claims;
    //the sole purpose is to drive a real sign/verify call through the wave-7 CryptoEventSink seam).
    private const string ObservedJoseWorkloadHeaderJson = """{"alg":"ES256","typ":"JWT"}""";
    private const string ObservedJoseWorkloadPayloadJson = """{"sub":"cbom-observed-workload"}""";


    /// <summary>Encodes a pre-built JSON string part for the observed workload's JOSE-signed leg.</summary>
    private static TaggedMemory<byte> EncodeObservedJwtPart(string json) =>
        new(Encoding.UTF8.GetBytes(json), BufferTags.Json);


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
