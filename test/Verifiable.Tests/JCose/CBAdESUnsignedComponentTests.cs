using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Model-invariant tests for the CB-AdES stage-2 unsigned components this agent owns — <c>sigPSt</c>
/// (<see cref="CBAdESSignaturePolicyStore"/>), <c>valData</c> (<see cref="CBAdESValidationData"/>), <c>refs</c>
/// (<see cref="CBAdESReferences"/> and its sub-types), and the four <see cref="CBAdESTimestampContainer"/> alias
/// wrappers (<see cref="CBAdESSignatureTimestamp"/>, <see cref="CBAdESArchiveTimestamp"/>,
/// <see cref="CBAdESSignatureAndReferencesTimestamp"/>, <see cref="CBAdESReferencesTimestamp"/>) — per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clauses 5.3.2, 5.3.4, Annex A.1.1, and the <c>tstContainer</c> occurrences at
/// clauses 5.3.3, 5.3.5.1, Annex A.1.2.1.1, Annex A.1.2.2.1.
/// </summary>
/// <remarks>
/// This file exercises construction-time invariants only (guard clauses, disposal idempotency) — the CDDL wire
/// shape, round-trip byte-exactness, and strict-parse negatives for the same components live in
/// <c>CBAdESUnsignedComponentSerializationTests</c>. <see cref="DigestValue"/> fixtures are real SHA-256 digests
/// computed through the registered <see cref="CryptographicKeyEvents"/> digest delegate seam (via
/// <see cref="CreateDigestAsync"/>), never a hand-rolled hash, matching <c>CBAdESSignedHeaderModelTests</c>'s
/// own convention.
/// </remarks>
[TestClass]
internal sealed class CBAdESUnsignedComponentTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// CB-5.3.2-01: <c>sigPSt</c> requires a <c>docOrLocalUri</c> choice; constructing
    /// <see cref="CBAdESSignaturePolicyStore"/> with a <see langword="null"/> content throws.
    /// </summary>
    [TestMethod]
    public void ConstructingSignaturePolicyStoreWithNullContentThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESSignaturePolicyStore(null!));
    }


    /// <summary>
    /// CB-5.3.4-01/02: CB-AdES signatures shall not incorporate empty <c>valData</c> maps; constructing
    /// <see cref="CBAdESValidationData"/> with neither <c>xVals</c> nor <c>rVals</c> throws.
    /// </summary>
    [TestMethod]
    public void ConstructingValidationDataWithNeitherCertificateNorRevocationValuesThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESValidationData());
    }


    /// <summary>
    /// CB-5.3.4-03: a present <c>xVals</c> member shall be non-empty; constructing
    /// <see cref="CBAdESValidationData"/> with an empty <c>certificateValues</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingValidationDataWithEmptyCertificateValuesArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESValidationData(certificateValues: []));
    }


    /// <summary>
    /// CB-5.3.4-05: <c>rVals</c> shall have at least one member; constructing
    /// <see cref="CBAdESRevocationValues"/> with every member absent throws.
    /// </summary>
    [TestMethod]
    public void ConstructingRevocationValuesWithEveryMemberAbsentThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESRevocationValues());
    }


    /// <summary>
    /// CB-5.3.4-06: a present <c>crlVals</c> member shall be non-empty; constructing
    /// <see cref="CBAdESRevocationValues"/> with an empty <c>crlValues</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingRevocationValuesWithEmptyCrlValuesArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESRevocationValues(crlValues: []));
    }


    /// <summary>
    /// CB-5.3.4-09: a present <c>ocspVals</c> member shall be non-empty; constructing
    /// <see cref="CBAdESRevocationValues"/> with an empty <c>ocspValues</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingRevocationValuesWithEmptyOcspValuesArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESRevocationValues(ocspValues: []));
    }


    /// <summary>
    /// The CDDL's <c>+</c> cardinality on <c>otherVals</c>: a present member shall be non-empty; constructing
    /// <see cref="CBAdESRevocationValues"/> with an empty <c>otherValues</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingRevocationValuesWithEmptyOtherValuesArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESRevocationValues(otherValues: []));
    }


    /// <summary>
    /// CB-A.1.1-04: CB-AdES signatures shall not incorporate empty <c>refs</c> CBOR maps; constructing
    /// <see cref="CBAdESReferences"/> with neither <c>xRefs</c> nor <c>rRefs</c> throws.
    /// </summary>
    [TestMethod]
    public void ConstructingReferencesWithNeitherCertificateNorRevocationReferencesThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESReferences());
    }


    /// <summary>
    /// CB-A.1.1-05: empty <c>xRefs</c> shall not be incorporated; constructing <see cref="CBAdESReferences"/>
    /// with an empty <c>certificateReferences</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingReferencesWithEmptyCertificateReferencesArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESReferences(certificateReferences: []));
    }


    /// <summary>
    /// CB-A.1.1-09: empty <c>rRefs</c> shall not be incorporated; constructing
    /// <see cref="CBAdESRevocationReferences"/> with every member absent throws.
    /// </summary>
    [TestMethod]
    public void ConstructingRevocationReferencesWithEveryMemberAbsentThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESRevocationReferences());
    }


    /// <summary>
    /// CB-A.1.1-10: a present <c>crlRefs</c> member shall be non-empty; constructing
    /// <see cref="CBAdESRevocationReferences"/> with an empty <c>crlReferences</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingRevocationReferencesWithEmptyCrlReferencesArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESRevocationReferences(crlReferences: []));
    }


    /// <summary>
    /// CB-A.1.1-19: a present <c>ocspRefs</c> member shall be non-empty; constructing
    /// <see cref="CBAdESRevocationReferences"/> with an empty <c>ocspReferences</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingRevocationReferencesWithEmptyOcspReferencesArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESRevocationReferences(ocspReferences: []));
    }


    /// <summary>
    /// The CDDL's <c>+</c> cardinality on <c>otherRefs</c> (leg-5 trap 3: not OCSP-only): a present member
    /// shall be non-empty; constructing <see cref="CBAdESRevocationReferences"/> with an empty
    /// <c>otherReferences</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingRevocationReferencesWithEmptyOtherReferencesArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESRevocationReferences(otherReferences: []));
    }


    /// <summary>
    /// <c>CertId</c>'s <c>x5t</c> member is mandatory (Annex A.1.1); constructing
    /// <see cref="CBAdESCertificateReference"/> with a <see langword="null"/> thumbprint throws.
    /// </summary>
    [TestMethod]
    public void ConstructingCertificateReferenceWithNullThumbprintThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESCertificateReference(null!));
    }


    /// <summary>
    /// CB-A.1.1-12: <c>CRLRef.digAlgVal</c>'s algorithm element is mandatory; constructing
    /// <see cref="CBAdESCrlReference"/> with a <see langword="null"/> hash algorithm throws.
    /// </summary>
    [TestMethod]
    public async Task ConstructingCrlReferenceWithNullHashAlgorithmThrows()
    {
        DigestValue digest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "crl reference digest"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESCrlReference(null!, digest));
        }
        finally
        {
            digest.Dispose();
        }
    }


    /// <summary>
    /// CB-A.1.1-12: <c>CRLRef.digAlgVal</c>'s digest element is mandatory; constructing
    /// <see cref="CBAdESCrlReference"/> with a <see langword="null"/> digest throws.
    /// </summary>
    [TestMethod]
    public void ConstructingCrlReferenceWithNullDigestThrows()
    {
        var hashAlgorithm = new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256);

        Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESCrlReference(hashAlgorithm, null!));
    }


    /// <summary>
    /// CB-A.1.1-28: <c>OCSPRef.digAlgVal</c>'s algorithm element is mandatory; constructing
    /// <see cref="CBAdESOcspReference"/> with a <see langword="null"/> hash algorithm throws.
    /// </summary>
    [TestMethod]
    public async Task ConstructingOcspReferenceWithNullHashAlgorithmThrows()
    {
        DigestValue digest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "ocsp reference digest"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESOcspReference(null!, digest, CreateOcspIdentifierFixture()));
        }
        finally
        {
            digest.Dispose();
        }
    }


    /// <summary>
    /// CB-A.1.1-28: <c>OCSPRef.digAlgVal</c>'s digest element is mandatory; constructing
    /// <see cref="CBAdESOcspReference"/> with a <see langword="null"/> digest throws.
    /// </summary>
    [TestMethod]
    public void ConstructingOcspReferenceWithNullDigestThrows()
    {
        var hashAlgorithm = new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256);

        Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESOcspReference(hashAlgorithm, null!, CreateOcspIdentifierFixture()));
    }


    /// <summary>
    /// CB-A.1.1-21: <c>OCSPRef.ocspId</c> is mandatory (unlike <c>CRLRef.crlId</c>); constructing
    /// <see cref="CBAdESOcspReference"/> with a <see langword="null"/> <c>ocspIdentifier</c> throws.
    /// </summary>
    [TestMethod]
    public async Task ConstructingOcspReferenceWithNullOcspIdentifierThrows()
    {
        DigestValue digest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "ocsp reference digest"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        var hashAlgorithm = new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256);
        try
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESOcspReference(hashAlgorithm, digest, null!));
        }
        finally
        {
            digest.Dispose();
        }
    }


    /// <summary>
    /// CB-A.1.1-21: <c>OCSPId.responderChoice</c> is mandatory; constructing
    /// <see cref="CBAdESOcspIdentifier"/> with a <see langword="null"/> responder throws.
    /// </summary>
    [TestMethod]
    public void ConstructingOcspIdentifierWithNullResponderThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESOcspIdentifier(null!, TestClock.CanonicalEpoch));
    }


    /// <summary>
    /// <see cref="CBAdESReferences.Dispose"/> forwards to every owned <see cref="CBAdESCertificateReference"/>
    /// and to <see cref="CBAdESRevocationReferences"/>; calling it twice must not throw, relying on the owned
    /// <see cref="DigestValue"/> instances' own idempotent disposal.
    /// </summary>
    [TestMethod]
    public async Task DisposingReferencesIsIdempotentAcrossCertificateAndRevocationReferences()
    {
        DigestValue certificateDigest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "certificate reference"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        DigestValue crlDigest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "crl reference"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);

        //CA2000: ownership of certificateDigest/crlDigest transfers immediately into the thumbprint/CRL
        //reference below, which in turn transfer into 'references' below; the explicit double-Dispose call
        //at the end of this test is this test's disposal point, not a 'using' statement.
#pragma warning disable CA2000 // Dispose objects before losing scope
        var certificateReference = new CBAdESCertificateReference(
            new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), certificateDigest));
        var crlReference = new CBAdESCrlReference(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), crlDigest);
        var revocationReferences = new CBAdESRevocationReferences(crlReferences: [crlReference]);
        var references = new CBAdESReferences(certificateReferences: [certificateReference], revocationReferences: revocationReferences);
#pragma warning restore CA2000 // Dispose objects before losing scope

        references.Dispose();
        references.Dispose();

        Assert.HasCount(1, references.CertificateReferences!, "Disposal must not clear the owned collection references.");
    }


    /// <summary>
    /// CB-5.3.3-01: <c>sigTst</c> requires a <c>tstContainer</c>; constructing
    /// <see cref="CBAdESSignatureTimestamp"/> with a <see langword="null"/> container throws.
    /// </summary>
    [TestMethod]
    public void ConstructingSignatureTimestampWithNullContainerThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESSignatureTimestamp(null!));
    }


    /// <summary>
    /// CB-5.3.5.1-04: <c>arcTst</c> requires a <c>tstContainer</c>; constructing
    /// <see cref="CBAdESArchiveTimestamp"/> with a <see langword="null"/> container throws.
    /// </summary>
    [TestMethod]
    public void ConstructingArchiveTimestampWithNullContainerThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESArchiveTimestamp(null!));
    }


    /// <summary>
    /// CB-A.1.2.1-01: <c>sigRTst</c> requires a <c>tstContainer</c>; constructing
    /// <see cref="CBAdESSignatureAndReferencesTimestamp"/> with a <see langword="null"/> container throws.
    /// </summary>
    [TestMethod]
    public void ConstructingSignatureAndReferencesTimestampWithNullContainerThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESSignatureAndReferencesTimestamp(null!));
    }


    /// <summary>
    /// CB-A.1.2.2-01: <c>rfsTst</c> requires a <c>tstContainer</c>; constructing
    /// <see cref="CBAdESReferencesTimestamp"/> with a <see langword="null"/> container throws.
    /// </summary>
    [TestMethod]
    public void ConstructingReferencesTimestampWithNullContainerThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESReferencesTimestamp(null!));
    }


    /// <summary>
    /// <see cref="CBAdESSignatureTimestamp.Dispose"/> forwards to its <see cref="CBAdESTimestampContainer"/>
    /// unconditionally (no disposed-flag field, per the type's own remarks); calling it twice must not throw.
    /// </summary>
    [TestMethod]
    public void DisposingSignatureTimestampIsIdempotent()
    {
        //CA2000: ownership of the inline CBAdESTimestampContainer transfers immediately into 'wrapper';
        //the explicit double-Dispose call below is this test's disposal point, not a 'using' statement.
#pragma warning disable CA2000 // Dispose objects before losing scope
        var wrapper = new CBAdESSignatureTimestamp(CreateTimestampContainerFixture());
#pragma warning restore CA2000 // Dispose objects before losing scope

        wrapper.Dispose();
        wrapper.Dispose();

        Assert.IsNotNull(wrapper.TimestampContainer, "Disposal must not null out the wrapped container reference.");
    }


    /// <summary>
    /// <see cref="CBAdESArchiveTimestamp.Dispose"/> forwards to its <see cref="CBAdESTimestampContainer"/>
    /// unconditionally; calling it twice must not throw.
    /// </summary>
    [TestMethod]
    public void DisposingArchiveTimestampIsIdempotent()
    {
        //CA2000: ownership of the inline CBAdESTimestampContainer transfers immediately into 'wrapper';
        //the explicit double-Dispose call below is this test's disposal point, not a 'using' statement.
#pragma warning disable CA2000 // Dispose objects before losing scope
        var wrapper = new CBAdESArchiveTimestamp(CreateTimestampContainerFixture());
#pragma warning restore CA2000 // Dispose objects before losing scope

        wrapper.Dispose();
        wrapper.Dispose();

        Assert.IsNotNull(wrapper.TimestampContainer, "Disposal must not null out the wrapped container reference.");
    }


    /// <summary>
    /// <see cref="CBAdESSignatureAndReferencesTimestamp.Dispose"/> forwards to its
    /// <see cref="CBAdESTimestampContainer"/> unconditionally; calling it twice must not throw.
    /// </summary>
    [TestMethod]
    public void DisposingSignatureAndReferencesTimestampIsIdempotent()
    {
        //CA2000: ownership of the inline CBAdESTimestampContainer transfers immediately into 'wrapper';
        //the explicit double-Dispose call below is this test's disposal point, not a 'using' statement.
#pragma warning disable CA2000 // Dispose objects before losing scope
        var wrapper = new CBAdESSignatureAndReferencesTimestamp(CreateTimestampContainerFixture());
#pragma warning restore CA2000 // Dispose objects before losing scope

        wrapper.Dispose();
        wrapper.Dispose();

        Assert.IsNotNull(wrapper.TimestampContainer, "Disposal must not null out the wrapped container reference.");
    }


    /// <summary>
    /// <see cref="CBAdESReferencesTimestamp.Dispose"/> forwards to its <see cref="CBAdESTimestampContainer"/>
    /// unconditionally; calling it twice must not throw.
    /// </summary>
    [TestMethod]
    public void DisposingReferencesTimestampIsIdempotent()
    {
        //CA2000: ownership of the inline CBAdESTimestampContainer transfers immediately into 'wrapper';
        //the explicit double-Dispose call below is this test's disposal point, not a 'using' statement.
#pragma warning disable CA2000 // Dispose objects before losing scope
        var wrapper = new CBAdESReferencesTimestamp(CreateTimestampContainerFixture());
#pragma warning restore CA2000 // Dispose objects before losing scope

        wrapper.Dispose();
        wrapper.Dispose();

        Assert.IsNotNull(wrapper.TimestampContainer, "Disposal must not null out the wrapped container reference.");
    }


    /// <summary>
    /// Builds a minimal, single-token <see cref="CBAdESTimestampContainer"/> fixture — the legacy RFC 3161
    /// shape (only <c>val</c> present) — shared by every wrapper disposal test in this file.
    /// </summary>
    /// <returns>The built fixture.</returns>
    private static CBAdESTimestampContainer CreateTimestampContainerFixture() =>
        new() { TstTokens = [new CBAdESTimestampToken { Val = new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 } }] };


    /// <summary>
    /// Builds a minimal <see cref="CBAdESOcspIdentifier"/> fixture (a by-name responder, produced "now") for
    /// the <see cref="CBAdESOcspReference"/> guard tests that need a valid, non-null third constructor argument.
    /// </summary>
    /// <returns>The built fixture.</returns>
    private static CBAdESOcspIdentifier CreateOcspIdentifierFixture() =>
        new(new CBAdESOcspResponderIdentifierByName(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }), TestClock.CanonicalEpoch);


    /// <summary>
    /// Computes a real SHA-256 digest over <paramref name="input"/> through the registered digest delegate,
    /// tagged with <see cref="CryptoTags.Sha256Digest"/> — the fixture every digest-carrying test in this file
    /// builds from, rather than a hand-rolled hash.
    /// </summary>
    /// <param name="coseHashAlgorithm">One of <see cref="WellKnownCoseAlgorithms.Sha256"/>.</param>
    /// <param name="input">The bytes to digest.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The owned digest, tagged with the algorithm's <see cref="CryptoTags"/> entry.</returns>
    private static async ValueTask<DigestValue> CreateDigestAsync(int coseHashAlgorithm, byte[] input, CancellationToken cancellationToken)
    {
        (Tag tag, int outputByteLength) = coseHashAlgorithm switch
        {
            WellKnownCoseAlgorithms.Sha256 => (CryptoTags.Sha256Digest, 32),
            _ => throw new ArgumentOutOfRangeException(nameof(coseHashAlgorithm), coseHashAlgorithm, "Unsupported test digest algorithm.")
        };

        return await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(input), outputByteLength, tag, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
