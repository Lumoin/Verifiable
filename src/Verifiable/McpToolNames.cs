namespace Verifiable;

/// <summary>
/// Constants for MCP tool names exposed by the Verifiable MCP server.
/// These names are used for tool registration and can be referenced in documentation.
/// </summary>
public static class McpToolNames
{
    /// <summary>
    /// Gets TPM (Trusted Platform Module) information from the current system.
    /// </summary>
    public const string GetTpmInfo = "GetTpmInfo";

    /// <summary>
    /// Saves TPM information to a JSON file on disk.
    /// </summary>
    public const string SaveTpmInfoToFile = "SaveTpmInfoToFile";

    /// <summary>
    /// Checks if the current platform supports TPM.
    /// </summary>
    public const string CheckTpmSupport = "CheckTpmSupport";

    /// <summary>
    /// Creates a new DID (Decentralized Identifier) document.
    /// </summary>
    public const string CreateDid = "CreateDid";

    /// <summary>
    /// Revokes an existing DID document.
    /// </summary>
    public const string RevokeDid = "RevokeDid";

    /// <summary>
    /// Lists all DID documents.
    /// </summary>
    public const string ListDids = "ListDids";

    /// <summary>
    /// Views a specific DID document.
    /// </summary>
    public const string ViewDid = "ViewDid";

    /// <summary>
    /// All available tool names.
    /// </summary>
    public static readonly string[] All =
    [
        GetTpmInfo,
        SaveTpmInfoToFile,
        CheckTpmSupport,
        CreateDid,
        RevokeDid,
        ListDids,
        ViewDid
    ];
}