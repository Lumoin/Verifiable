namespace Verifiable;

/// <summary>
/// Constants for MCP tool names exposed by the Verifiable MCP server.
/// These names are used for tool registration and can be referenced in documentation.
/// </summary>
internal static class McpToolNames
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
    /// Emits a CycloneDX cryptographic bill of materials (CBOM).
    /// </summary>
    public const string EmitCbom = "EmitCbom";

    /// <summary>
    /// Verifies a WebAuthn registration ceremony's attestation object.
    /// </summary>
    public const string VerifyFido2Registration = "VerifyFido2Registration";

    /// <summary>
    /// Verifies a WebAuthn authentication ceremony's assertion.
    /// </summary>
    public const string VerifyFido2Assertion = "VerifyFido2Assertion";

    /// <summary>
    /// Creates a WebAuthn cryptographic challenge.
    /// </summary>
    public const string CreateFido2Challenge = "CreateFido2Challenge";

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
        ViewDid,
        EmitCbom,
        VerifyFido2Registration,
        VerifyFido2Assertion,
        CreateFido2Challenge
    ];
}
