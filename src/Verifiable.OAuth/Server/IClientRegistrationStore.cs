using Verifiable.Core;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The authoritative registration storage boundary, shared by registration reads and writes.
/// Completion means the record, routing indexes and protected management credential are committed.
/// </summary>
/// <remarks>
/// Operations run under traffic, independently of wiring alterations. Implementations synchronize
/// all indexes and reads in one storage domain. Exceptions propagate before event delivery.
/// </remarks>
public interface IClientRegistrationStore
{
    /// <summary>
    /// Commits a new registration and its management credential atomically before notification.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 §3.2.1</see>
    /// says "The successful registration response uses an HTTP 201 Created status code".
    /// Store a hash or protected credential for subsequent bearer validation; do not log plaintext.
    /// </summary>
    /// <param name="registration">The record to commit.</param>
    /// <param name="accessToken">The credential issued only to the client and this required store.</param>
    /// <param name="context">The operation context, retained only for the duration of this call.</param>
    /// <param name="cancellationToken">Cancellation before commitment.</param>
    ValueTask CreateAsync(ClientRecord registration, RegistrationAccessToken accessToken,
        ExchangeContext context, CancellationToken cancellationToken);


    /// <summary>
    /// Commits the replacement only if the stored revision equals the expected revision.
    /// The replacement revision must be exactly one greater; false commits nothing and emits nothing.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 §2.2</see>
    /// says the client identifier "MUST NOT change from the initial registration response".
    /// Conditional replacement prevents concurrent requests from silently overwriting each other.
    /// </summary>
    /// <param name="registration">The replacement record with unchanged tenant and client identifiers.</param>
    /// <param name="expectedRevision">The revision read by this operation.</param>
    /// <param name="context">The operation context.</param>
    /// <param name="cancellationToken">Cancellation before commitment.</param>
    /// <returns>Whether this operation committed the replacement and all routing indexes.</returns>
    ValueTask<bool> TryUpdateAsync(ClientRecord registration, long expectedRevision,
        ExchangeContext context, CancellationToken cancellationToken);


    /// <summary>
    /// Conditionally removes the authenticated identity only at its expected revision, atomically
    /// removing all routing indexes, grants and the management credential. Returns the final removed
    /// record, or null without mutation when identity or revision changed. The caller reloads the same
    /// identity after a lost race; an absent or replaced client receives HTTP 401. The deletion event
    /// uses the removed record's revision plus one as a monotonic tombstone.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.3">RFC 7592 §2.3</see>
    /// says the server "MUST respond with an HTTP 204 No Content message" after successful deletion.
    /// </summary>
    /// <param name="registration">The authenticated registration to remove.</param>
    /// <param name="context">The operation context.</param>
    /// <param name="cancellationToken">Cancellation before commitment.</param>
    /// <param name="expectedRevision">The revision authenticated and loaded by this attempt.</param>
    /// <returns>The atomically removed record, or null when this attempt committed nothing.</returns>
    ValueTask<ClientRecord?> DeleteAsync(ClientRecord registration, long expectedRevision,
        ExchangeContext context, CancellationToken cancellationToken);
}
