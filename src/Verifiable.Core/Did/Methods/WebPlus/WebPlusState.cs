namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// The accumulated did:webplus resolution state after a verified DID document: the control fields a successor
/// document is checked against (did:webplus Draft v0.4, Validation of DID Documents, step 7 — non-root branch).
/// </summary>
/// <remarks>
/// This is the domain state the <see cref="Verifiable.Cryptography.EventLogs.LogReplayer{TState,TOperation,TProof,TContext}"/> carries
/// forward. A successor document MUST keep the same <see cref="Id"/> (WP-VAL-7a), reference this
/// <see cref="SelfHash"/> as its <c>prevDIDDocumentSelfHash</c> (WP-VAL-7b), carry a strictly later
/// <see cref="ValidFrom"/> (WP-VAL-7c), increment this <see cref="VersionId"/> by one (WP-VAL-7d), and present
/// proofs that satisfy these <see cref="UpdateRules"/> (WP-VAL-7e).
/// </remarks>
/// <param name="Id">The DID document <c>id</c> (identical across the whole history).</param>
/// <param name="SelfHash">The document's <c>selfHash</c>, which the successor references as its <c>prevDIDDocumentSelfHash</c>.</param>
/// <param name="ValidFrom">The document's <c>validFrom</c>, which the successor's MUST be strictly later than.</param>
/// <param name="VersionId">The document's <c>versionId</c>, which the successor's MUST be one greater than.</param>
/// <param name="UpdateRules">The document's parsed <c>updateRules</c>, which the successor's proofs MUST satisfy.</param>
public sealed record WebPlusState(string Id, string SelfHash, string ValidFrom, ulong VersionId, WebPlusUpdateRule UpdateRules);


/// <summary>
/// A parsed did:webplus microledger entry: the typed DID document and its parsed <c>updateRules</c>, the operation
/// the <see cref="Verifiable.Cryptography.EventLogs.LogReplayer{TState,TOperation,TProof,TContext}"/> carries for each
/// <c>did-documents.jsonl</c> line. The proofs and the canonical bytes ride on the
/// <see cref="Verifiable.Cryptography.EventLogs.LogEntry{TOperation,TProof}"/> itself.
/// </summary>
/// <param name="Document">The strictly-parsed DID document.</param>
/// <param name="UpdateRules">The document's parsed <c>updateRules</c> expression.</param>
public sealed record WebPlusRawEntry(WebPlusDidDocument Document, WebPlusUpdateRule UpdateRules);
