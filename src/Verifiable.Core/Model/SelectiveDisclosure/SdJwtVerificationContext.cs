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
    private readonly IMemoryOwner<byte> payloadOwner;
    private bool disposed;

    internal SdJwtVerificationContext(
        IMemoryOwner<byte> payloadOwner,
        IReadOnlyDictionary<SdDisclosure, CredentialPath> boundPaths)
    {
        this.payloadOwner = payloadOwner;
        BoundPaths = boundPaths;
    }

    /// <summary>
    /// The redacted JWT payload (UTF-8 JSON, with the <c>_sd</c> digest arrays) the signature
    /// covers. Backed by a pooled buffer this context owns; valid until <see cref="Dispose"/>.
    /// </summary>
    public ReadOnlyMemory<byte> Payload => payloadOwner.Memory;

    /// <summary>
    /// The disclosures that bound to a path in the payload, keyed to their credential path.
    /// A holder-selected disclosure absent from this map had no matching digest in the payload.
    /// </summary>
    public IReadOnlyDictionary<SdDisclosure, CredentialPath> BoundPaths { get; }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        payloadOwner.Dispose();
        disposed = true;
    }
}
