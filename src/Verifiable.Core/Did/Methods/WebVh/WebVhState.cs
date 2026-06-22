namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// The accumulated did:webvh resolution state after a verified log entry: the active processing
/// parameters, the entry's <c>versionId</c>, and its <c>versionTime</c>.
/// </summary>
/// <remarks>
/// This is the domain state the <see cref="EventLogs.LogReplayer{TState,TOperation,TProof,TContext}"/>
/// carries forward. The active <see cref="WebVhParameters"/> drive verification of the next entry (the
/// authorized <c>updateKeys</c>, the pre-rotation commitments), and the <see cref="VersionTime"/> anchors
/// the monotonic <c>versionTime</c> check (did:webvh v1.0, Read (Resolve)).
/// </remarks>
/// <param name="Parameters">The active processing parameters after folding this entry.</param>
/// <param name="VersionId">The entry's <c>versionId</c> (the version number, a dash, and the entryHash).</param>
/// <param name="VersionTime">The entry's <c>versionTime</c>, or <see langword="null"/> when absent.</param>
public sealed record WebVhState(WebVhParameters Parameters, string VersionId, string? VersionTime);
