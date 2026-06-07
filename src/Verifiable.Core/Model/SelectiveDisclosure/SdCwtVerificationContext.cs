using System;
using System.Collections.Generic;
using Verifiable.JCose;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Intermediate state from SD-CWT structural verification, exposed by the
/// <c>VerifyVerboseAsync</c> sibling for spec-vector validation and debugging. Production
/// callers use <c>VerifyAsync</c>, which discards this.
/// </summary>
/// <remarks>
/// <para>
/// Owns the parsed <see cref="CoseSign1Message"/> — the caller disposes this context, which
/// disposes the message. <see cref="Message"/> (and any <see cref="ReadOnlyMemory{T}"/> read
/// from it, such as the redacted payload) is valid only until disposal.
/// </para>
/// </remarks>
public sealed class SdCwtVerificationContext: IDisposable
{
    private bool disposed;

    internal SdCwtVerificationContext(
        CoseSign1Message message,
        IReadOnlyDictionary<SdDisclosure, CredentialPath> boundPaths)
    {
        Message = message;
        BoundPaths = boundPaths;
    }

    /// <summary>
    /// The parsed COSE_Sign1 message whose payload is the redacted CWT claims set the
    /// signature covers. Owned by this context; valid until <see cref="Dispose"/>.
    /// </summary>
    public CoseSign1Message Message { get; }

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

        Message.Dispose();
        disposed = true;
    }
}
