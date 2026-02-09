using ModelContextProtocol.Server;
using System.ComponentModel;
using System.Threading.Tasks;

namespace Verifiable;

/// <summary>
/// MCP Server tools for Verifiable functionality.
/// These tools are exposed to AI clients like GitHub Copilot when running in MCP mode.
/// </summary>
[McpServerToolType]
internal sealed class VerifiableMcpServer
{
    [McpServerTool(Name = McpToolNames.GetTpmInfo), Description("Get TPM (Trusted Platform Module) information from the current system. Returns JSON with TPM details or an error if TPM is not supported.")]
    public static string GetTpmInfo()
    {
        var result = VerifiableOperations.GetTpmInfoAsJson();

        return result.IsSuccess ? result.Value! : result.Error!;
    }


    [McpServerTool(Name = McpToolNames.SaveTpmInfoToFile), Description("Save TPM information to a JSON file on disk.")]
    public static async Task<string> SaveTpmInfoToFile(
        [Description("The file path where to save the TPM information JSON. Defaults to 'tpm_data.json' if not specified.")] string? filePath = null)
    {
        var result = await VerifiableOperations.SaveTpmInfoToFileAsync(filePath).ConfigureAwait(false);

        return result.IsSuccess
            ? $"TPM information saved to '{result.Value}'."
            : result.Error!;
    }


    [McpServerTool(Name = McpToolNames.CheckTpmSupport), Description("Check if the current platform supports TPM (Trusted Platform Module).")]
    public static string CheckTpmSupport()
    {
        return VerifiableOperations.CheckTpmSupportMessage();
    }


    [McpServerTool(Name = McpToolNames.CreateDid), Description("Create a new DID (Decentralized Identifier) document.")]
    public static string CreateDid(
        [Description("The unique identifier for the new DID document.")] int id,
        [Description("A parameter for the DID document.")] string param,
        [Description("An optional extra parameter.")] string? extraParam = null)
    {
        var result = VerifiableOperations.CreateDid(id, param, extraParam);

        return result.Value!;
    }


    [McpServerTool(Name = McpToolNames.RevokeDid), Description("Revoke an existing DID (Decentralized Identifier) document.")]
    public static string RevokeDid(
        [Description("The identifier of the DID document to revoke.")] int id)
    {
        var result = VerifiableOperations.RevokeDid(id);

        return result.Value!;
    }


    [McpServerTool(Name = McpToolNames.ListDids), Description("List all DID (Decentralized Identifier) documents.")]
    public static string ListDids()
    {
        var result = VerifiableOperations.ListDids();

        return result.Value!;
    }


    [McpServerTool(Name = McpToolNames.ViewDid), Description("View a specific DID (Decentralized Identifier) document.")]
    public static string ViewDid(
        [Description("The identifier of the DID document to view.")] int id)
    {
        var result = VerifiableOperations.ViewDid(id);

        return result.Value!;
    }
}