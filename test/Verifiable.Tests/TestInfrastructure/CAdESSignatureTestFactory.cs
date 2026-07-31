using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.X509;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using SignerInformation = Org.BouncyCastle.Cms.SignerInformation;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Mints the Signed Data Objects the validation examples of ETSI EN 319 102-1 Annex A need: a CAdES-B-B
/// signature over the identity of an <see cref="X509ChainTestRing"/> leaf, the same signature carrying a
/// signature time-stamp from a Time-Stamping Authority leg of that ring (CAdES-B-T), and either of those
/// carrying an archive time-stamp as well.
/// </summary>
/// <remarks>
/// <para>
/// The signature itself is produced by the framework's own CMS signer through
/// <see cref="CmsSignedDataTestFactory"/>, and every time-stamp token by the independent time-stamp protocol
/// oracle of <see cref="X509ChainTestRingTimestamping"/>. The octets a signature time-stamp is taken over — the
/// <c>SignerInfo.signature</c> value — are read back out of the encoded signature by an independent CMS reader
/// rather than remembered from the signing call, so a token binds what a validator will actually find.
/// </para>
/// <para>
/// Instants are the caller's, derived from <see cref="TestClock.CanonicalEpoch"/>; nothing here reads a clock.
/// </para>
/// </remarks>
internal static class CAdESSignatureTestFactory
{
    /// <summary>
    /// The address the archive time-stamp's transport delegate is handed. Nothing dials it: the delegate
    /// answers from the in-process authority oracle, and the value exists because the shipped surface requires
    /// the caller to name the authority it is talking to.
    /// </summary>
    private static string ArchiveTimestampAuthorityAddress => "https://archive-authority.example.test/tsa";


    /// <summary>
    /// Signs <paramref name="content"/> as a CAdES-B-B signature — the CMS signed attributes plus a signing-time
    /// attribute and the ESS signing-certificate-v2 reference binding the signer's certificate.
    /// </summary>
    /// <param name="content">The content the signature encapsulates and covers.</param>
    /// <param name="signer">The ring leaf whose key signs.</param>
    /// <param name="signingTime">The claimed signing time the signed attribute states.</param>
    /// <returns>The pooled Signed Data Object; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static CmsSignedData SignBaseline(
        ReadOnlyMemory<byte> content,
        X509ChainTestRingNode signer,
        DateTimeOffset signingTime)
    {
        ArgumentNullException.ThrowIfNull(signer);

        using X509Certificate2 signerWithKey = signer.Certificate.CopyWithPrivateKey(signer.SigningKey);

        return CmsSignedDataTestFactory.SignAsCAdES(content.Span, signerWithKey, signingTime);
    }


    /// <summary>
    /// Signs <paramref name="content"/> as a detached CAdES-B-B signature — the same signed attributes, with an
    /// <c>encapContentInfo</c> that carries no content, so the content stays a data object beside the CMS object
    /// rather than inside it.
    /// </summary>
    /// <param name="content">The content the signature covers without carrying it.</param>
    /// <param name="signer">The ring leaf whose key signs.</param>
    /// <param name="signingTime">The claimed signing time the signed attribute states.</param>
    /// <returns>The pooled Signed Data Object; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// The second selection method of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">IETF RFC 4998 Appendix A</see> archives "the
    /// CMS Object and the signed or encrypted content ... as separated objects", which only means anything when
    /// the content is separate from the object.
    /// </remarks>
    internal static CmsSignedData SignBaselineDetached(
        ReadOnlyMemory<byte> content,
        X509ChainTestRingNode signer,
        DateTimeOffset signingTime)
    {
        ArgumentNullException.ThrowIfNull(signer);

        using X509Certificate2 signerWithKey = signer.Certificate.CopyWithPrivateKey(signer.SigningKey);

        return CmsSignedDataTestFactory.SignAsCAdESDetached(content.Span, signerWithKey, signingTime);
    }


    /// <summary>
    /// Adds certificates to a signature's own certificate set, so that a time-stamp attached afterwards protects
    /// them and a validator can build a chain offline from the signature alone. The certificate set is outside
    /// what the signature covers, so adding to it leaves the signature verifiable.
    /// </summary>
    /// <param name="signature">The signature to extend; not disposed by this call.</param>
    /// <param name="certificates">The ring nodes whose certificates are added.</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <returns>The pooled Signed Data Object carrying the certificates; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static CmsSignedData EmbedCertificates(
        CmsSignedData signature,
        IReadOnlyList<X509ChainTestRingNode> certificates,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(pool);

        var signedCms = new SignedCms();
        signedCms.Decode(signature.AsReadOnlySpan());
        for(int i = 0; i < certificates.Count; ++i)
        {
            signedCms.AddCertificate(certificates[i].Certificate);
        }

        return CmsSignedData.FromBytes(signedCms.Encode(), pool);
    }


    /// <summary>
    /// Attaches a signature time-stamp to <paramref name="signature"/> as the signature-time-stamp-token
    /// unsigned attribute — a time-stamp token whose message imprint is taken over the signature value, which is
    /// what makes the signature one with time and what step 3)a) of clause 5.5.4 of ETSI EN 319 102-1 re-derives
    /// and checks.
    /// </summary>
    /// <param name="signature">The signature to attach the attribute to; not disposed by this call.</param>
    /// <param name="timestampAuthority">The Time-Stamping Authority node that produces the token.</param>
    /// <param name="timestampAuthorityChain">The certificates the token carries, the authority's own first.</param>
    /// <param name="timestampTime">The generation time the authority states.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled Signed Data Object carrying the attribute; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static async ValueTask<CmsSignedData> AttachSignatureTimestampAsync(
        CmsSignedData signature,
        X509ChainTestRingNode timestampAuthority,
        IReadOnlyList<X509ChainTestRingNode> timestampAuthorityChain,
        DateTimeOffset timestampTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(timestampAuthority);
        ArgumentNullException.ThrowIfNull(timestampAuthorityChain);
        ArgumentNullException.ThrowIfNull(pool);

        using SignedContentMemory signatureValue = ReadSignatureValue(signature, pool);
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            timestampAuthority, timestampAuthorityChain, signatureValue.AsReadOnlyMemory(), timestampTime, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return AttachUnsignedAttribute(signature, CAdESSignatureFacts.SignatureTimestampAttributeOid, token, pool);
    }


    /// <summary>
    /// Signs <paramref name="content"/> as a CAdES-B-T signature in one call: a CAdES-B-B signature carrying a
    /// signature time-stamp from the supplied authority.
    /// </summary>
    /// <param name="content">The content the signature encapsulates and covers.</param>
    /// <param name="signer">The ring leaf whose key signs.</param>
    /// <param name="signingTime">The claimed signing time the signed attribute states.</param>
    /// <param name="timestampAuthority">The Time-Stamping Authority node that produces the token.</param>
    /// <param name="timestampAuthorityChain">The certificates the token carries, the authority's own first.</param>
    /// <param name="timestampTime">The generation time the authority states.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled Signed Data Object; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned carrier transfers to the caller, which disposes it.")]
    internal static async ValueTask<CmsSignedData> SignWithSignatureTimestampAsync(
        ReadOnlyMemory<byte> content,
        X509ChainTestRingNode signer,
        DateTimeOffset signingTime,
        X509ChainTestRingNode timestampAuthority,
        IReadOnlyList<X509ChainTestRingNode> timestampAuthorityChain,
        DateTimeOffset timestampTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        using CmsSignedData baseline = SignBaseline(content, signer, signingTime);

        return await AttachSignatureTimestampAsync(
            baseline, timestampAuthority, timestampAuthorityChain, timestampTime, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Attaches an archive time-stamp to <paramref name="signature"/> as the archive-time-stamp-v3 unsigned
    /// attribute, which is what makes a signature one providing Long Term Availability and Integrity of
    /// Validation Material.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The attribute is produced by the shipped augmentation surface
    /// (<see cref="CAdESSignatureAugmentation.AddArchiveTimestampAsync"/>), so the message imprint is the
    /// four-part concatenation of ETSI EN 319 122-1 clause 5.5.3 and the token carries the
    /// <c>ats-hash-index-v3</c> of clause 5.5.2 that names what it covers — the coverage the shipped CAdES
    /// binding restates and the proof-of-existence extraction building block of ETSI EN 319 102-1 clause 5.6.2.3
    /// verifies the token's <c>messageImprint</c> against. A world minted here therefore needs no declaration
    /// that the Driving Application establishes the binding by other means.
    /// </para>
    /// <para>
    /// The token itself still comes from the independent time-stamp protocol oracle, which answers the
    /// <c>TimeStampReq</c> the library writes by decoding it with its own reader
    /// (<see cref="MintingTimestampResponder"/>): the octets of the request and the response cross the shipped
    /// transport seam exactly as they would against a real authority.
    /// </para>
    /// </remarks>
    /// <param name="signature">The signature to attach the attribute to; not disposed by this call.</param>
    /// <param name="timestampAuthority">The Time-Stamping Authority node that produces the token.</param>
    /// <param name="timestampAuthorityChain">The certificates the token carries, the authority's own first.</param>
    /// <param name="generationTime">The generation time the authority states.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled Signed Data Object carrying the attribute; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static async ValueTask<CmsSignedData> AttachArchiveTimestampAsync(
        CmsSignedData signature,
        X509ChainTestRingNode timestampAuthority,
        IReadOnlyList<X509ChainTestRingNode> timestampAuthorityChain,
        DateTimeOffset generationTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(timestampAuthority);
        ArgumentNullException.ThrowIfNull(timestampAuthorityChain);
        ArgumentNullException.ThrowIfNull(pool);

        var authority = new MintingTimestampResponder(timestampAuthority, timestampAuthorityChain, generationTime);

        return await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = signature,
                SignerIndex = 0,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = ArchiveTimestampAuthorityAddress,
                FetchResponse = authority.FetchAsync,
                ValidationMaterial = CAdESValidationMaterial.None,
                //This shared fixture has no signing-certificate parameter and is reused across scenarios that
                //are not about requirement m) (e.g. post-expiry long-term-preservation worlds); requirement m)
                //itself is exercised by its own dedicated tests against the production context directly.
                EnforceSigningCertificateValidity = false
            },
            pool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Attaches a time-stamp token that a Time-Stamping Authority produced over octets other than the ones the
    /// attribute's own class binds — the shape of a party who obtains a genuine token from a trusted authority
    /// over unrelated data and appends it to someone else's signature, which the CMS encoding permits because an
    /// unsigned attribute is outside what the signature covers.
    /// </summary>
    /// <param name="signature">The signature to attach the attribute to; not disposed by this call.</param>
    /// <param name="attributeOid">The unsigned attribute's object identifier.</param>
    /// <param name="timestampAuthority">The Time-Stamping Authority node that produces the token.</param>
    /// <param name="timestampAuthorityChain">The certificates the token carries, the authority's own first.</param>
    /// <param name="timestampedOctets">The octets the authority actually time-stamps, which are not the ones the attribute's class binds.</param>
    /// <param name="timestampTime">The generation time the authority states.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled Signed Data Object carrying the attribute; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static async ValueTask<CmsSignedData> AttachUnboundTimestampAsync(
        CmsSignedData signature,
        string attributeOid,
        X509ChainTestRingNode timestampAuthority,
        IReadOnlyList<X509ChainTestRingNode> timestampAuthorityChain,
        ReadOnlyMemory<byte> timestampedOctets,
        DateTimeOffset timestampTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(attributeOid);
        ArgumentNullException.ThrowIfNull(timestampAuthority);
        ArgumentNullException.ThrowIfNull(timestampAuthorityChain);
        ArgumentNullException.ThrowIfNull(pool);

        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            timestampAuthority, timestampAuthorityChain, timestampedOctets, timestampTime, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return AttachUnsignedAttribute(signature, attributeOid, token, pool);
    }


    /// <summary>
    /// Reads the <c>SignerInfo.signature</c> octets of a signature — what a signature time-stamp's message
    /// imprint is taken over, and what the shipped CAdES binding surfaces as the signature value — with an
    /// independent CMS reader, since the framework's own <see cref="SignerInfo"/> does not expose them.
    /// </summary>
    /// <param name="signature">The signature to read.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The signature value; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static SignedContentMemory ReadSignatureValue(CmsSignedData signature, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(pool);

        SignerInformation reader = new BcCmsSignedData(signature.AsReadOnlySpan().ToArray())
            .GetSignerInfos()
            .GetSigners()
            .Cast<SignerInformation>()
            .First();

        return SignedContentMemory.FromBytes(reader.GetSignature(), pool);
    }


    /// <summary>
    /// Adds one unsigned attribute carrying a time-stamp token to a signature. An unsigned attribute is outside
    /// what the signature covers, so attaching it leaves the signature verifiable.
    /// </summary>
    /// <param name="signature">The signature to extend; not disposed by this call.</param>
    /// <param name="attributeOid">The attribute's object identifier.</param>
    /// <param name="token">The DER-encoded token to carry.</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <returns>The extended Signed Data Object; the caller disposes it.</returns>
    private static CmsSignedData AttachUnsignedAttribute(
        CmsSignedData signature,
        string attributeOid,
        PkiCertificateMemory token,
        MemoryPool<byte> pool)
    {
        var signedCms = new SignedCms();
        signedCms.Decode(signature.AsReadOnlySpan());
        signedCms.SignerInfos[0].AddUnsignedAttribute(
            new AsnEncodedData(new Oid(attributeOid), token.AsReadOnlySpan().ToArray()));

        return CmsSignedData.FromBytes(signedCms.Encode(), pool);
    }
}
