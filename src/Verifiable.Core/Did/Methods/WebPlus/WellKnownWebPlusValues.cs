namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// Well-known did:webplus string values: the published microledger file name and the DID-URL query
/// parameters fixed by the did:webplus specification (LedgerDomain Draft v0.4).
/// </summary>
/// <remarks>
/// Centralizing these keeps the DID-to-URL transform and the version-selection query parameters
/// consistent across the resolver and tests.
/// </remarks>
public static class WellKnownWebPlusValues
{
    /// <summary>
    /// The microledger file name served at the DID's web location: <c>did-documents.jsonl</c> — a
    /// newline-delimited concatenation of the ordered, JCS-serialized DID documents.
    /// </summary>
    public static string DidDocumentsFile { get; } = "did-documents.jsonl";

    /// <summary>The DID-URL query parameter selecting a specific DID document by its self-hash: <c>selfHash</c>.</summary>
    public static string SelfHashQueryParameter { get; } = "selfHash";

    /// <summary>The DID-URL query parameter selecting a specific DID document by its version: <c>versionId</c>.</summary>
    public static string VersionIdQueryParameter { get; } = "versionId";

    /// <summary>The DID document <c>id</c> field name.</summary>
    public static string IdField { get; } = "id";

    /// <summary>The DID document <c>selfHash</c> field name (an MBHash self-hash).</summary>
    public static string SelfHashField { get; } = "selfHash";

    /// <summary>The DID document <c>prevDIDDocumentSelfHash</c> field name (absent on a root document).</summary>
    public static string PrevDidDocumentSelfHashField { get; } = "prevDIDDocumentSelfHash";

    /// <summary>The DID document <c>updateRules</c> field name (the update-authorization policy).</summary>
    public static string UpdateRulesField { get; } = "updateRules";

    /// <summary>The DID document <c>validFrom</c> field name (the document's RFC 3339 valid-from timestamp).</summary>
    public static string ValidFromField { get; } = "validFrom";

    /// <summary>The DID document <c>versionId</c> field name (the microledger version, an unsigned integer).</summary>
    public static string VersionIdField { get; } = "versionId";

    /// <summary>The DID document <c>verificationMethod</c> field name.</summary>
    public static string VerificationMethodField { get; } = "verificationMethod";

    /// <summary>The DID document <c>proofs</c> field name (the detached-JWS update-authorization proofs).</summary>
    public static string ProofsField { get; } = "proofs";

    /// <summary>The <c>updateRules</c> <c>key</c> member: a rule satisfied by a signature from the named MBPubKey (WP-UR-3).</summary>
    public static string UpdateRuleKey { get; } = "key";

    /// <summary>The <c>updateRules</c> <c>hashedKey</c> member: a rule satisfied by a signature from a key with the named MBHash (WP-UR-4).</summary>
    public static string UpdateRuleHashedKey { get; } = "hashedKey";

    /// <summary>The <c>updateRules</c> <c>any</c> member: a rule satisfied if any sub-rule is (WP-UR-5).</summary>
    public static string UpdateRuleAny { get; } = "any";

    /// <summary>The <c>updateRules</c> <c>all</c> member: a rule satisfied if every sub-rule is (WP-UR-6).</summary>
    public static string UpdateRuleAll { get; } = "all";

    /// <summary>The <c>updateRules</c> <c>atLeast</c> member: the weight threshold of a weighted rule (WP-UR-7).</summary>
    public static string UpdateRuleAtLeast { get; } = "atLeast";

    /// <summary>The <c>updateRules</c> <c>of</c> member: the weighted sub-rules of an <c>atLeast</c> rule (WP-UR-7).</summary>
    public static string UpdateRuleOf { get; } = "of";

    /// <summary>The <c>updateRules</c> <c>weight</c> member: the weight of a weighted sub-rule (defaults to 1 when absent).</summary>
    public static string UpdateRuleWeight { get; } = "weight";

    /// <summary>The did:webplus JWS proof <c>alg</c> value for an Ed25519 signing key (Draft v0.4 worked example).</summary>
    public static string Ed25519SignatureAlgorithm { get; } = "Ed25519";
}
