using System;
using Verifiable.Core.Model.Mdoc;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The outcome of <see cref="MdocVpTokenVerification.VerifyAsync"/>: the parsed and
/// cryptographically verified presentation together with the IACA trust resolution whose key the
/// issuer signature was checked under.
/// </summary>
/// <remarks>
/// <para>
/// The two travel together because of ownership: <see cref="ResolveMdocIssuerKeyDelegate"/>
/// transfers ownership of the resolution it returns, and the resolved key must outlive the parse —
/// <see cref="VpTokenParsed.CredentialIssuerKey"/> borrows it for the credential-status step that
/// reads the Referenced Token's issuer key. This result owns <see cref="IssuerTrust"/>, so the
/// caller disposes the result once the flow step reading the borrowed key is done; every earlier
/// failure path inside the verification releases the resolution before throwing.
/// </para>
/// </remarks>
public sealed record MdocVpVerificationResult: IDisposable
{
    /// <summary>The parsed and cryptographically verified VP token contents.</summary>
    public required VpTokenParsed Parsed { get; init; }

    /// <summary>
    /// The IACA trust resolution whose <see cref="MdocIacaTrustResolution.IssuerVerificationKey"/>
    /// the issuer-auth signature was checked under and
    /// <see cref="VpTokenParsed.CredentialIssuerKey"/> borrows, or <see langword="null"/> when the
    /// response carried no document to resolve a key for. Owned by this result; released by
    /// <see cref="Dispose"/>.
    /// </summary>
    public MdocIacaTrustResolution? IssuerTrust { get; init; }


    /// <summary>Releases the owned <see cref="IssuerTrust"/> resolution and the key it holds.</summary>
    public void Dispose()
    {
        IssuerTrust?.Dispose();
    }
}
