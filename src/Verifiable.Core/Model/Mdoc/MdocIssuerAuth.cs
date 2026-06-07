using JCoseEncodedCoseSign1 = Verifiable.JCose.EncodedCoseSign1;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// The semantic carrier for the <c>issuerAuth</c> slot in
/// <see cref="MdocIssuerSigned"/> — pairs the parsed
/// <see cref="MdocMobileSecurityObject"/> view with the original
/// COSE_Sign1 wire bytes the issuer signed.
/// </summary>
/// <remarks>
/// <para>
/// On the wire <c>issuerAuth</c> is a COSE_Sign1 (RFC 9052) whose payload
/// is the MSO encoded as a CBOR map. Two pieces of state survive into the
/// data model:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <see cref="Mso"/> — the parsed MSO. Reading it doesn't require
///     re-parsing the COSE_Sign1 each time.
///   </description></item>
///   <item><description>
///     <see cref="EncodedCoseSign1"/> — the original COSE_Sign1 wire bytes
///     in a pool-routed, CBOM-tagged carrier. Required for signature
///     verification (the verifier hashes them via the Sig_structure) and
///     for any forwarder that re-emits the credential verbatim.
///   </description></item>
/// </list>
/// <para>
/// Both are present on the parse path; the build path attaches
/// <see cref="EncodedCoseSign1"/> after the COSE signing step. Disposing
/// the <see cref="MdocIssuerAuth"/> returns the wire-bytes carrier to its
/// pool.
/// </para>
/// </remarks>
public sealed class MdocIssuerAuth: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes an <c>issuerAuth</c> carrier from a parsed MSO and the
    /// COSE_Sign1 wire bytes. Ownership of
    /// <paramref name="encodedCoseSign1"/> transfers to the new instance;
    /// disposing the instance disposes the carrier.
    /// </summary>
    /// <param name="mso">The parsed Mobile Security Object.</param>
    /// <param name="encodedCoseSign1">The original COSE_Sign1 wire-bytes carrier (pool-routed).</param>
    public MdocIssuerAuth(
        MdocMobileSecurityObject mso,
        JCoseEncodedCoseSign1 encodedCoseSign1)
    {
        ArgumentNullException.ThrowIfNull(mso);
        ArgumentNullException.ThrowIfNull(encodedCoseSign1);

        Mso = mso;
        EncodedCoseSign1 = encodedCoseSign1;
    }


    /// <summary>The parsed Mobile Security Object.</summary>
    public MdocMobileSecurityObject Mso { get; }

    /// <summary>
    /// The original COSE_Sign1 wire-bytes carrier (pool-routed,
    /// CBOM-tagged). Signature verification hashes the underlying bytes
    /// via the COSE Sig_structure; forwarders re-emit them verbatim to
    /// preserve the issuer's signature.
    /// </summary>
    public JCoseEncodedCoseSign1 EncodedCoseSign1 { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        EncodedCoseSign1.Dispose();
        disposed = true;
    }
}
