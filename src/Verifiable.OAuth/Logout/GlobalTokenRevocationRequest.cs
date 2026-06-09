using System.Diagnostics;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.OAuth.Logout;

/// <summary>
/// A parsed Global Token Revocation request body per
/// <see href="https://datatracker.ietf.org/doc/draft-parecki-oauth-global-token-revocation/">draft-parecki-oauth-global-token-revocation §3</see>
/// — a single <c>sub_id</c> member carrying the RFC 9493 Subject Identifier
/// whose tokens are to be revoked.
/// </summary>
/// <remarks>
/// The library owns the wire (endpoint matching, client authentication, the
/// status-code outcomes) but not JSON: the body is deserialized by the
/// application's JSON stack behind <c>ParseGlobalTokenRevocationRequestDelegate</c>,
/// which projects the <c>sub_id</c> object into the neutral
/// <see cref="SubjectIdentifier"/> reused from the Shared Signals subsystem.
/// </remarks>
[DebuggerDisplay("GlobalTokenRevocationRequest Format={SubId.Format}")]
public sealed record GlobalTokenRevocationRequest
{
    /// <summary>The Subject Identifier (the <c>sub_id</c> member) whose tokens are to be revoked.</summary>
    public required SubjectIdentifier SubId { get; init; }
}
