using Verifiable.JCose;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Intermediate state from mdoc <c>issuerAuth</c> signature verification, exposed by the
/// <c>VerifyIssuerAuthVerboseAsync</c> sibling for spec-vector validation and debugging.
/// Production callers use <c>VerifyIssuerAuthAsync</c>, which discards this.
/// </summary>
/// <remarks>
/// <para>
/// Owns the parsed <see cref="CoseSign1Message"/> the signature check ran against — the caller
/// disposes this context, which disposes the message. <see cref="Message"/> (and any
/// <see cref="System.ReadOnlyMemory{T}"/> read from it, such as the Tag 24-wrapped MSO payload)
/// is valid only until disposal.
/// </para>
/// <para>
/// When the trust-resolver overload produced this context, the context also owns the successful
/// <see cref="MdocIacaTrustResolution"/> (and the resolved issuer key inside it) — disposing the
/// context disposes the resolution. The direct-key overload leaves <see cref="TrustResolution"/>
/// <see langword="null"/>. A failed trust resolution never reaches a context: callers that need
/// the per-failure IACA detail run the <see cref="ResolveMdocIssuerKeyDelegate"/> directly, as
/// the trust-resolver overload's documentation already directs.
/// </para>
/// </remarks>
public sealed class MdocIssuerAuthVerificationContext: IDisposable
{
    private bool disposed;

    internal MdocIssuerAuthVerificationContext(
        CoseSign1Message message,
        MdocMobileSecurityObject mso,
        MdocIacaTrustResolution? trustResolution = null)
    {
        Message = message;
        Mso = mso;
        TrustResolution = trustResolution;
    }

    /// <summary>
    /// The parsed COSE_Sign1 message whose payload is the Tag 24-wrapped MSO the issuer signature
    /// covers. Owned by this context; valid until <see cref="Dispose"/>.
    /// </summary>
    public CoseSign1Message Message { get; }

    /// <summary>
    /// The parsed Mobile Security Object carried on the verified <c>issuerAuth</c> — the same
    /// reference the document's <see cref="MdocIssuerAuth.Mso"/> exposes, surfaced here so a
    /// spec-vector check has the signed-payload view alongside the parsed message.
    /// </summary>
    public MdocMobileSecurityObject Mso { get; }

    /// <summary>
    /// The successful IACA trust resolution when the trust-resolver overload produced this
    /// context; <see langword="null"/> for the direct-key overload. Owned by this context (it
    /// owns the resolved issuer key); valid until <see cref="Dispose"/>.
    /// </summary>
    public MdocIacaTrustResolution? TrustResolution { get; }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        Message.Dispose();
        TrustResolution?.Dispose();
        disposed = true;
    }
}
