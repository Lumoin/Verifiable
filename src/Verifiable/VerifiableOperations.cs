using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Tpm;

namespace Verifiable;

/// <summary>
/// Shared operations for DID, VC, and TPM functionality.
/// Used by both CLI commands and MCP tools.
/// </summary>
public static class VerifiableOperations
{
    public static bool IsTpmSupported() => TpmExtensions.IsTpmPlatformSupported();

    public static string GetPlatformDescription() => RuntimeInformation.OSDescription;


    public static Result<string, string> GetTpmInfoAsJson()
    {
        if(!IsTpmSupported())
        {
            return Result.Failure<string, string>(
                $"Trusted platform module (TPM) information is not supported on {GetPlatformDescription()}.");
        }

        try
        {
            var tpm = new TpmWrapper();
            var tpmInfo = TpmExtensions.GetAllTpmInfo(tpm.Tpm);
            string json = JsonSerializer.Serialize(tpmInfo, VerifiableJsonContext.Default.TpmInfo);

            return Result.Success<string, string>(json);
        }
        catch(Exception ex)
        {
            return Result.Failure<string, string>($"Error retrieving TPM information: {ex.Message}");
        }
    }


    public static async Task<Result<string, string>> SaveTpmInfoToFileAsync(string? filePath = null)
    {
        if(!IsTpmSupported())
        {
            return Result.Failure<string, string>(
                $"Trusted platform module (TPM) information is not supported on {GetPlatformDescription()}.");
        }

        try
        {
            var tpm = new TpmWrapper();
            var tpmInfo = TpmExtensions.GetAllTpmInfo(tpm.Tpm);

            string targetPath = filePath ?? "tpm_data.json";
            await using var stream = new FileStream(targetPath, FileMode.Create, FileAccess.Write);
            await JsonSerializer.SerializeAsync(stream, tpmInfo, VerifiableJsonContext.Default.TpmInfo);

            return Result.Success<string, string>(Path.GetFullPath(targetPath));
        }
        catch(Exception ex)
        {
            return Result.Failure<string, string>($"Error saving TPM information: {ex.Message}");
        }
    }


    public static string CheckTpmSupportMessage()
    {
        bool isSupported = IsTpmSupported();
        string os = GetPlatformDescription();

        return isSupported
            ? $"TPM is supported on this platform ({os})."
            : $"TPM is NOT supported on this platform ({os}).";
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