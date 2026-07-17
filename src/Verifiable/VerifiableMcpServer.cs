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
    public static async Task<string> GetTpmInfo()
    {
        var result = await VerifiableOperations.GetTpmInfoAsJsonAsync().ConfigureAwait(false);

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


    [McpServerTool(Name = McpToolNames.EmitCbom), Description("Emit a CycloneDX cryptographic bill of materials (CBOM). Use mode 'declarative' (default) for the library's full crypto capabilities, or 'observed' to run a real crypto workload and report what actually executed. Returns CycloneDX 1.6 JSON.")]
    public static async Task<string> EmitCbom(
        [Description("The CBOM mode: 'declarative' (default) or 'observed'.")] string? mode = null,
        [Description("With mode 'observed', also subscribe to the CryptoEvent stream for the workload's duration and append a compact provenance summary (counts by event type, algorithm, and backend) after the CBOM JSON. The CBOM JSON itself is unchanged. No effect with mode 'declarative'.")] bool events = false)
    {
        bool isObserved = string.Equals(mode, "observed", System.StringComparison.OrdinalIgnoreCase);

        var result = isObserved
            ? await VerifiableOperations.EmitObservedCbomAsync(includeEventProvenance: events).ConfigureAwait(false)
            : VerifiableOperations.EmitDeclarativeCbom();

        return result.IsSuccess ? result.Value! : result.Error!;
    }


    [McpServerTool(Name = McpToolNames.VerifyFido2Registration), Description("Verify a WebAuthn registration ceremony's attestation object (none/packed/android-key/fido-u2f) against the expected challenge, origin, and relying party ID, using either directly supplied trust anchor certificate files or a FIDO Metadata Service BLOB. Returns the credential record JSON to store for future authentication ceremonies, or the failing claim/attestation error identifier.")]
    public static async Task<string> VerifyFido2Registration(
        [Description("File path to the raw attestationObject CBOR bytes.")] string attestationObjectPath,
        [Description("File path to the raw clientDataJSON bytes.")] string clientDataJsonPath,
        [Description("The relying party ID whose SHA-256 hash is checked against authData.rpIdHash.")] string rpId,
        [Description("The single origin the relying party accepts for this ceremony.")] string origin,
        [Description("The base64url-encoded challenge exactly as issued to the client.")] string challenge,
        [Description("Repeatable PEM/DER attestation root certificate file paths. Mutually exclusive with mdsBlobPath/mdsRootPath.")] string[]? trustAnchorPaths = null,
        [Description("File path to a compact-JWS FIDO Metadata Service BLOB.")] string? mdsBlobPath = null,
        [Description("File path to the MDS root certificate mdsBlobPath chains to.")] string? mdsRootPath = null,
        [Description("The relying party's user-verification policy: required, preferred, or discouraged. Defaults to preferred.")] string? userVerification = null,
        [Description("The client-reported authenticatorAttachment value to store on the credential record: platform or cross-platform.")] string? authenticatorAttachment = null,
        [Description("For an android-key attestation, require the origin/purpose authorizations to be satisfied by the teeEnforced list alone (rejects a software-only key). Defaults to false (union of teeEnforced and softwareEnforced).")] bool requireTeeEnforcedAuthorizations = false)
    {
        var result = await VerifiableOperations.VerifyFido2RegistrationAsync(
            attestationObjectPath, clientDataJsonPath, rpId, origin, challenge, trustAnchorPaths, mdsBlobPath, mdsRootPath,
            requireTeeEnforcedAuthorizations: requireTeeEnforcedAuthorizations,
            userVerification: userVerification, authenticatorAttachment: authenticatorAttachment)
            .ConfigureAwait(false);

        return result.IsSuccess ? result.Value! : result.Error!;
    }


    [McpServerTool(Name = McpToolNames.VerifyFido2Assertion), Description("Verify a WebAuthn authentication ceremony's assertion against a previously stored credential record. Returns a compact JSON verdict (isAcceptable, signatureValid, signCount), or the failing claim.")]
    public static async Task<string> VerifyFido2Assertion(
        [Description("File path to the credential record JSON document produced by VerifyFido2Registration.")] string credentialRecordPath,
        [Description("File path to the raw authData bytes (response.authenticatorData).")] string authenticatorDataPath,
        [Description("File path to the raw assertion signature bytes (response.signature).")] string signaturePath,
        [Description("File path to the raw clientDataJSON bytes.")] string clientDataJsonPath,
        [Description("The relying party ID whose SHA-256 hash is checked against authData.rpIdHash.")] string rpId,
        [Description("The single origin the relying party accepts for this ceremony.")] string origin,
        [Description("The base64url-encoded challenge exactly as issued to the client.")] string challenge,
        [Description("The signature counter value stored for this credential from the previous ceremony. Defaults to 0.")] uint storedSignCount = 0,
        [Description("The relying party's user-verification policy: required, preferred, or discouraged. Defaults to preferred.")] string? userVerification = null,
        [Description("Optional file path to the raw response.userHandle bytes.")] string? userHandlePath = null)
    {
        var result = await VerifiableOperations.VerifyFido2AssertionAsync(
            credentialRecordPath, authenticatorDataPath, signaturePath, clientDataJsonPath, rpId, origin, challenge,
            storedSignCount, userVerification, userHandlePath)
            .ConfigureAwait(false);

        return result.IsSuccess ? result.Value! : result.Error!;
    }


    [McpServerTool(Name = McpToolNames.CreateFido2Challenge), Description("Create a WebAuthn cryptographic challenge through the registered entropy provider. Returns the base64url-encoded challenge.")]
    public static string CreateFido2Challenge(
        [Description("The challenge length in bytes. Defaults to 32; enforces a floor of 16.")] int? byteLength = null)
    {
        var result = VerifiableOperations.CreateFido2Challenge(byteLength);

        return result.IsSuccess ? result.Value! : result.Error!;
    }
}
