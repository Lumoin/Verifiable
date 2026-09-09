using System;
using System.Buffers;
using System.Collections.Generic;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Intermediate state from SD-JWT structural verification, exposed by the
/// <c>VerifyVerboseAsync</c> sibling for spec-vector validation and debugging. Production
/// callers use <c>VerifyAsync</c>, which discards this.
/// </summary>
/// <remarks>
/// <para>
/// Owns the decoded redacted JWT payload buffer rented from the verification pool — the caller
/// disposes this context, which returns the buffer. <see cref="Payload"/> (the redacted JWT
/// claims set as UTF-8 JSON) is valid only until disposal.
/// </para>
/// </remarks>
public sealed class SdJwtVerificationContext: IDisposable
{
    /// <summary>The pooled buffer holding the decoded redacted payload, owned by this context.</summary>
    private IMemoryOwner<byte> PayloadOwner { get; }

    /// <summary>Whether the payload buffer has already been returned to the pool.</summary>
    private bool disposed;


    /// <summary>
    /// Creates the intermediate state the structural verification produced.
    /// </summary>
    /// <param name="payloadOwner">The pooled buffer holding the decoded redacted payload.</param>
    /// <param name="boundPaths">The positions the holder-selected disclosures bound to.</param>
    internal SdJwtVerificationContext(
        IMemoryOwner<byte> payloadOwner,
        SdDisclosurePaths boundPaths)
    {
        this.PayloadOwner = payloadOwner;
        BoundPaths = boundPaths;
    }

    /// <summary>
    /// The redacted JWT payload (UTF-8 JSON, with the <c>_sd</c> digest arrays) the signature
    /// covers. Backed by a pooled buffer this context owns; valid until <see cref="Dispose"/>.
    /// </summary>
    public ReadOnlyMemory<byte> Payload => PayloadOwner.Memory;

    /// <summary>
    /// The disclosures that bound to a path in the payload, keyed to their credential path.
    /// A holder-selected disclosure absent from this map had no matching digest in the payload.
    /// </summary>
    /// <remarks>
    /// The keys are the caller's own <see cref="SdToken{TEnvelope}"/> disclosure instances,
    /// borrowed rather than copied: identity here is reference identity, so a lookup answers only
    /// for the very instances the verification was handed, and the map is meaningful only while
    /// that token is alive.
    /// </remarks>
    public SdDisclosurePaths BoundPaths { get; }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        PayloadOwner.Dispose();
        disposed = true;
    }
}
