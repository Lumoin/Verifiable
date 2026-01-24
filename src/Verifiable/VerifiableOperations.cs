using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Info;

namespace Verifiable;

/// <summary>
/// Shared operations for DID, VC, and TPM functionality.
/// Used by both CLI commands and MCP tools.
/// </summary>
public static class VerifiableOperations
{
    public static string GetPlatformDescription() => RuntimeInformation.OSDescription;


    /// <summary>
    /// Gets TPM information as a structured object.
    /// </summary>
    public static Result<TpmInfo, string> GetTpmInfo()
    {
        if(!TpmDevice.IsAvailable)
        {
            return Result.Failure<TpmInfo, string>("TPM is not available on this platform.");
        }

        try
        {
            using TpmDevice device = TpmDevice.Open();
            TpmResult<TpmInfo> result = device.GetInfo();

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
    public static Result<string, string> GetTpmInfoAsJson()
    {
        var infoResult = GetTpmInfo();

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
        var infoResult = GetTpmInfoAsJson();
        if(!infoResult.IsSuccess)
        {
            return Result.Failure<string, string>(infoResult.Error!);
        }

        try
        {
            await File.WriteAllTextAsync(targetPath, infoResult.Value);
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
        string os = GetPlatformDescription();
        if(TpmDevice.IsAvailable)
        {
            return $"TPM is supported and available on this platform ({os}).";
        }

        return $"TPM is not supported or not available on this platform ({os}).";
    }


    public static Result<string, string> CreateDid(int id, string param, string? extraParam = null)
    {
        var result = new StringBuilder();
        result.AppendLine($"Created DID document with ID: {id}");
        result.AppendLine($"Parameter: {param}");

        if(!string.IsNullOrEmpty(extraParam))
        {
            result.AppendLine($"Extra parameter: {extraParam}");
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