using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The firewalled capstone for the signature validation algorithm of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5</see>: a signing party mints the world of clause A.3 example 1 and emits
/// nothing but wire octets and public instants; a verifying party that never saw the signing party's objects
/// reconstructs every input from those octets through the shipped parsers, runs the shipped CAdES binding of the
/// format-facts seam through the validation processes of clauses 5.3 and 5.5, and reaches the conclusions clauses
/// A.3.2 and A.3.3 state.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The firewall.</strong> <see cref="MintRevokedCertificateWorldAsync"/> builds the world, copies out the
/// DER octets, and <em>disposes the world before returning</em>. Nothing but an
/// <see cref="AnnexAValidationWireMessage"/> survives that call: no certificate carrier, no signing key, no memory
/// pool rental, no <see cref="SignatureValidationInputs"/>, no <see cref="RevocationStatusInformation"/> record.
/// The verifying party's own carriers are rented from its own pool and built from the octets alone, so an
/// assertion that passes here cannot be passing because the two sides share an object.
/// </para>
/// <para>
/// <strong>The public instants.</strong> The message carries the timeline instants of clause A.3.1 as plain
/// values. They are public facts of the example — a verifier learns the revocation instant from the revocation
/// list it was handed and the time-stamp instant from the token inside the signature — and each is additionally
/// re-derived on the verifying side from the octets themselves and cross-checked against the transmitted value,
/// so the assertions never rest on the transmitted value alone.
/// </para>
/// <para>
/// <strong>The revocation status information is derived from the wire, not transmitted.</strong> NOTE 7 of clause
/// 5.2.6.4 states that the process assumes revocation data is supplied by the Driving Application, and Table 6
/// mandates the revocation time and reason, which the three-valued
/// <see cref="CheckCertificateRevocationStatusAsyncDelegate"/> cannot carry. The verifying party therefore plays
/// the Driving Application: the <em>status</em> is decided by the shipped <see cref="CrlRevocationChecker"/> over
/// the received list, and the entry particulars RFC 5280 §5.3 defines are read out of the same octets with an
/// independent reader (this library ships no certificate-revocation-list entry reader — see the build log).
/// </para>
/// </remarks>
[TestClass]
internal sealed class AnnexAValidationFirewalledFlowTests
{
    /// <summary>
    /// The signature algorithm identifier the verifying party's own cryptographic constraints declare reliable —
    /// <c>ecdsa-with-SHA256</c> of <see href="https://www.rfc-editor.org/rfc/rfc5758#section-3.2">RFC 5758
    /// §3.2</see>. A verifier policy, stated by the verifying party from the public algorithm registry rather
    /// than learned from the signing party.
    /// </summary>
    private const string EcdsaWithSha256Oid = "1.2.840.10045.4.3.2";

    /// <summary>The minimum elliptic curve key size the verifying party's cryptographic constraints accept.</summary>
    private const int MinimumEllipticCurveKeySizeBits = 256;


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Clause A.3.2 across the firewall: the verifying party reconstructs the Signed Data Object, the trust
    /// anchor and the revocation lists from octets, runs the validation process for Basic Signatures of clause
    /// 5.3, and reports <c>INDETERMINATE</c>/<c>REVOKED_NO_POE</c> with the chain, the revocation time and the
    /// revocation reason Table 6 mandates — every one of them derived from the octets it received.
    /// </summary>
    [TestMethod]
    public async Task FirewalledBasicValidationReportsRevokedNoProofOfExistenceFromWireOctetsAlone()
    {
        AnnexAValidationWireMessage message = await MintRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using var verifier = await ReconstructedVerifyingParty.CreateAsync(message, TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            verifier.Inputs, verifier.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, message.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationConclusion conclusion = outcome.Conclusion;
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, conclusion.Indication,
            "Clause A.3.2 states the expected result INDETERMINATE.");
        Assert.HasCount(1, conclusion.SubIndications, "One sub-indication explains one reason.");
        Assert.AreEqual(SignatureValidationSubIndication.RevokedNoProofOfExistence, conclusion.SubIndications[0],
            "Clause A.3.2 states the expected sub-indication REVOKED_NO_POE.");

        Assert.HasCount(1, conclusion.ReportData, "Table 6 mandates one associated validation report data item for REVOKED_NO_POE.");
        Assert.IsInstanceOfType<CertificateRevocationReportData>(conclusion.ReportData[0],
            "Table 6 mandates the chain together with the time and the reason of revocation for REVOKED_NO_POE.");
        var revocation = (CertificateRevocationReportData)conclusion.ReportData[0];
        Assert.HasCount(3, revocation.CertificateChain,
            "The chain reconstructed from the octets is the signing certificate and its certification authority, both carried inside the signature, plus the received trust anchor.");
        Assert.AreEqual(verifier.SigningCertificate, revocation.CertificateChain[0],
            "The chain starts at the signing certificate the shipped CAdES binding surfaced from the received Signed Data Object.");
        Assert.AreEqual(verifier.TrustAnchors[0], revocation.CertificateChain[2],
            "The chain ends at the trust anchor the verifying party was handed as octets.");
        Assert.AreEqual(verifier.SigningCertificate, revocation.RevokedCertificate,
            "The revoked certificate of example 1 is the signing certificate itself.");
        Assert.AreEqual(verifier.SigningCertificateRevokedPerWire, revocation.RevocationTime,
            "The reported revocation time is the revocationDate the received revocation list states, read by the verifying party's own reader.");
        Assert.AreEqual(message.SigningCertificateRevoked, revocation.RevocationTime,
            "That instant is the t4 of the timeline of clause A.3.1.");
        Assert.AreEqual(KeyCompromiseReasonCode, revocation.RevocationReason,
            "The reported reason is the CRLReason the received revocation list states for the entry.");

        Assert.AreEqual(message.ValidationTime, conclusion.ValidationTime, "Clause 5.1.3's date and time is the current time the verifying party used.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.Basic, conclusion.ProcessIdentifier, "The process that ran is the one of clause 5.3.");
    }


    /// <summary>
    /// Clause A.3.3 across the firewall: the same reconstructed inputs run through the validation process of
    /// clause 5.5 reach <c>TOTAL-PASSED</c>, with best-signature-time at the generation time of the signature
    /// time-stamp token the received Signed Data Object carries — a value the verifying party reads out of those
    /// octets itself and cross-checks against the transmitted public instant.
    /// </summary>
    [TestMethod]
    public async Task FirewalledValidationWithTimeReportsTotalPassedAtTheReceivedTokenGenerationTime()
    {
        AnnexAValidationWireMessage message = await MintRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using var verifier = await ReconstructedVerifyingParty.CreateAsync(message, TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            verifier.Inputs, verifier.Seams, SignatureValidationProcessSelection.SignaturesWithTime,
            SignatureValidationCapabilities.All, message.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationConclusion conclusion = outcome.Conclusion;
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, conclusion.Indication,
            "Clause A.3.3 states the expected result TOTAL-PASSED once the signature time-stamp places the signing before the revocation.");
        Assert.IsEmpty(conclusion.SubIndications, "Table 5 names no sub-indication for TOTAL-PASSED.");
        Assert.AreEqual(verifier.SignatureTimestampGenerationTimePerWire, conclusion.BestSignatureTime,
            "Step 3)b) of clause 5.5.4 lowers best-signature-time to the generation time the received token itself states.");
        Assert.AreEqual(message.SignatureTimestampCreated, conclusion.BestSignatureTime,
            "That instant is the t3 of the timeline of clause A.3.1.");
        Assert.HasCount(3, conclusion.ValidatedCertificateChain,
            "Table 5 mandates the validated certificate chain including the signing certificate on TOTAL-PASSED.");
        Assert.HasCount(1, outcome.SignatureWithTimeValidation!.AcceptedSignatureTimestamps,
            "The single received signature time-stamp token binds the signature value and validates under the received trust anchor.");
        Assert.AreEqual(SignatureValidationSubIndication.RevokedNoProofOfExistence,
            outcome.SignatureWithTimeValidation!.BasicValidation.Conclusion.SubIndications[0],
            "Step 2) of clause 5.5.4 continues from exactly the conclusion clause A.3.2 states.");
    }


    /// <summary>
    /// The <c>CRLReason</c> value <c>keyCompromise</c> of
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1">RFC 5280 §5.3.1</see>, which the
    /// verifying party recognizes from the registry rather than from the signing party.
    /// </summary>
    private static int KeyCompromiseReasonCode => 1;


    /// <summary>
    /// The signing party: it mints the world of clause A.3 example 1, copies the octets a verifier would receive,
    /// and releases the world before returning, so nothing but octets and public instants can cross.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The wire message.</returns>
    private static async ValueTask<AnnexAValidationWireMessage> MintRevokedCertificateWorldAsync(CancellationToken cancellationToken)
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(cancellationToken).ConfigureAwait(false);

        List<byte[]> revocationLists = [];
        for(int i = 0; i < scenario.CertificateRevocationLists.Count; ++i)
        {
            revocationLists.Add(scenario.CertificateRevocationLists[i].AsReadOnlySpan().ToArray());
        }

        List<byte[]> trustAnchors = [];
        for(int i = 0; i < scenario.TrustAnchorCertificates.Count; ++i)
        {
            trustAnchors.Add(scenario.TrustAnchorCertificates[i].AsReadOnlySpan().ToArray());
        }

        return new AnnexAValidationWireMessage
        {
            SignedDataObject = scenario.SignedDataObject.AsReadOnlySpan().ToArray(),
            TrustAnchorCertificates = [.. trustAnchors],
            CertificateRevocationLists = [.. revocationLists],
            ValidationTime = scenario.ValidationTime,
            SignatureTimestampCreated = scenario.SignatureTimestampCreated,
            SigningCertificateRevoked = scenario.SigningCertificateRevoked!.Value
        };
    }


    /// <summary>
    /// Everything that crosses the firewall: the DER octets of the Signed Data Object, of the trust anchors and
    /// of the certificate revocation lists, plus the public instants of the timeline of clause A.3.1.
    /// </summary>
    /// <remarks>
    /// Deliberately nothing but octets and instants — no carrier, no key, no record of the validation model. Any
    /// member added here has to be something a verifier could genuinely receive over a wire.
    /// </remarks>
    private sealed record AnnexAValidationWireMessage
    {
        /// <summary>The DER-encoded CMS <c>SignedData</c> the signing party produced.</summary>
        public required byte[] SignedDataObject { get; init; }

        /// <summary>The DER-encoded certificates the verifier is configured to trust.</summary>
        public required byte[][] TrustAnchorCertificates { get; init; }

        /// <summary>The DER-encoded <c>CertificateList</c> structures of RFC 5280 §5 the verifier was handed.</summary>
        public required byte[][] CertificateRevocationLists { get; init; }

        /// <summary>The instant the verifier validates at — <c>t5</c> of clause A.3.1.</summary>
        public required DateTimeOffset ValidationTime { get; init; }

        /// <summary>The instant the signature time-stamp was created — <c>t3</c> of clause A.3.1.</summary>
        public required DateTimeOffset SignatureTimestampCreated { get; init; }

        /// <summary>The instant the signing certificate was revoked — <c>t4</c> of clause A.3.1.</summary>
        public required DateTimeOffset SigningCertificateRevoked { get; init; }
    }


    /// <summary>
    /// The verifying party: it owns everything it built from the received octets and nothing else, and exposes
    /// the inputs and seams one run of the validation algorithm of clause 5 takes.
    /// </summary>
    private sealed class ReconstructedVerifyingParty: IDisposable
    {
        /// <summary>The carriers this party rented, released in reverse order.</summary>
        private readonly List<IDisposable> owned = [];

        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>The Signed Data Object rebuilt from the received octets.</summary>
        public CmsSignedData SignedDataObject { get; private set; } = null!;

        /// <summary>The trust anchors rebuilt from the received octets.</summary>
        public PkiCertificateMemory[] TrustAnchors { get; private set; } = [];

        /// <summary>The certificate revocation lists rebuilt from the received octets.</summary>
        public PkiCertificateMemory[] CertificateRevocationLists { get; private set; } = [];

        /// <summary>The signing certificate, copied out of the received Signed Data Object by the shipped CAdES binding.</summary>
        public PkiCertificateMemory SigningCertificate { get; private set; } = null!;

        /// <summary>The certification authority certificate the signing certificate names as its issuer, copied out of the same Signed Data Object.</summary>
        public PkiCertificateMemory SigningCertificateIssuer { get; private set; } = null!;

        /// <summary>The revocation instant this party read out of the received revocation list, independently of anything the signing party stated.</summary>
        public DateTimeOffset SigningCertificateRevokedPerWire { get; private set; }

        /// <summary>The generation time this party read out of the signature time-stamp token inside the received Signed Data Object.</summary>
        public DateTimeOffset SignatureTimestampGenerationTimePerWire { get; private set; }

        /// <summary>The inputs of Tables 18 and 20, assembled from the received octets alone.</summary>
        public SignatureValidationInputs Inputs { get; private set; } = null!;

        /// <summary>The seams the run composes: the shipped CAdES binding, the offline chain completer over the received certificates, the platform path validator, and the shipped offline revocation checker over the received lists.</summary>
        public SignatureValidationSeams Seams { get; private set; } = null!;


        /// <summary>
        /// Reconstructs a verifying party from a wire message.
        /// </summary>
        /// <param name="message">The octets and public instants the party received.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The party, which the caller disposes.</returns>
        public static async ValueTask<ReconstructedVerifyingParty> CreateAsync(
            AnnexAValidationWireMessage message,
            CancellationToken cancellationToken)
        {
            var party = new ReconstructedVerifyingParty();
            try
            {
                await party.BuildAsync(message, cancellationToken).ConfigureAwait(false);

                return party;
            }
            catch
            {
                party.Dispose();

                throw;
            }
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            disposed = true;
            for(int i = owned.Count - 1; i >= 0; --i)
            {
                owned[i].Dispose();
            }

            owned.Clear();
        }


        /// <summary>
        /// Rebuilds every carrier, derives the facts a Driving Application supplies, and assembles the inputs and
        /// seams.
        /// </summary>
        /// <param name="message">The received message.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        private async ValueTask BuildAsync(AnnexAValidationWireMessage message, CancellationToken cancellationToken)
        {
            SignedDataObject = Own(CmsSignedData.FromBytes(message.SignedDataObject, BaseMemoryPool.Shared));

            List<PkiCertificateMemory> anchors = [];
            for(int i = 0; i < message.TrustAnchorCertificates.Length; ++i)
            {
                anchors.Add(Own(ToCarrier(message.TrustAnchorCertificates[i], PkiCertificateTags.X509Certificate)));
            }

            TrustAnchors = [.. anchors];

            List<PkiCertificateMemory> lists = [];
            for(int i = 0; i < message.CertificateRevocationLists.Length; ++i)
            {
                lists.Add(Own(ToCarrier(message.CertificateRevocationLists[i], PkiCertificateTags.X509Crl)));
            }

            CertificateRevocationLists = [.. lists];

            await ReadSignatureAsync(cancellationToken).ConfigureAwait(false);
            await DescribeRevocationAsync(message.ValidationTime, cancellationToken).ConfigureAwait(false);
            AssembleInputs();
        }


        /// <summary>
        /// Opens the received Signed Data Object through the shipped CAdES binding of the format-facts seam, takes
        /// its own copies of the signing certificate and of the certification authority certificate the signature
        /// carries, and reads the generation time of the signature time-stamp token.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        private async ValueTask ReadSignatureAsync(CancellationToken cancellationToken)
        {
            using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
                new SignatureFactsExtractionContext { SignedDataObject = SignedDataObject },
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status,
                "The received octets have to be a CMS SignedData the shipped CAdES binding can read; nothing else can be asserted otherwise.");
            Assert.IsNotNull(facts.SigningCertificate, "Clause 5.2.3 identifies the signing certificate from the signature's own certificate set.");

            SigningCertificate = Own(ToCarrier(facts.SigningCertificate!.AsReadOnlySpan().ToArray(), PkiCertificateTags.X509Certificate));

            BcX509Certificate signer = ReadCertificate(SigningCertificate);
            PkiCertificateMemory? issuer = null;
            for(int i = 0; i < facts.EmbeddedCertificates.Count; ++i)
            {
                BcX509Certificate candidate = ReadCertificate(facts.EmbeddedCertificates[i]);
                if(!candidate.SubjectDN.Equivalent(signer.SubjectDN) && candidate.SubjectDN.Equivalent(signer.IssuerDN))
                {
                    issuer = Own(ToCarrier(facts.EmbeddedCertificates[i].AsReadOnlySpan().ToArray(), PkiCertificateTags.X509Certificate));

                    break;
                }
            }

            Assert.IsNotNull(issuer, "The signature of example 1 carries the certification authority certificate that issued the signing certificate.");
            SigningCertificateIssuer = issuer!;

            IReadOnlyList<EmbeddedTimestamp> tokens = facts.TimestampsOfClass(SignatureTimestampClass.SignatureTimestamp);
            Assert.HasCount(1, tokens, "The signature of clause A.3.1 carries exactly one signature time-stamp attribute.");

            DateTimeOffset? generationTime = await TimestampValidation.ReadGenerationTimeAsync(
                tokens[0].Token, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            Assert.IsNotNull(generationTime, "The received token's TSTInfo states a generation time.");
            SignatureTimestampGenerationTimePerWire = generationTime!.Value;
        }


        /// <summary>
        /// Plays the Driving Application of NOTE 7 of clause 5.2.6.4: it decides the revocation status of the
        /// signing certificate with the shipped offline checker over the received lists, and reads the entry
        /// particulars Table 6 mandates — the revocation date and the <c>CRLReason</c> — out of the same octets.
        /// </summary>
        /// <param name="validationTime">The instant the lists' own validity windows are judged at.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        private async ValueTask DescribeRevocationAsync(DateTimeOffset validationTime, CancellationToken cancellationToken)
        {
            BcX509Certificate signer = ReadCertificate(SigningCertificate);
            BcX509Certificate issuer = ReadCertificate(SigningCertificateIssuer);

            var parser = new X509CrlParser();
            List<RevocationStatusInformation> statuses = [];
            for(int i = 0; i < CertificateRevocationLists.Length; ++i)
            {
                PkiCertificateMemory listCarrier = CertificateRevocationLists[i];
                X509Crl list = parser.ReadCrl(listCarrier.AsReadOnlySpan().ToArray());
                if(!list.IssuerDN.Equivalent(issuer.SubjectDN))
                {
                    continue;
                }

                CertificateRevocationStatus status = await new CrlRevocationChecker([listCarrier]).CheckAsync(
                    SigningCertificate, [SigningCertificateIssuer], validationTime, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

                X509CrlEntry? entry = list.GetRevokedCertificate(signer.SerialNumber);
                statuses.Add(new RevocationStatusInformation
                {
                    RevocationData = listCarrier,
                    SubjectCertificate = SigningCertificate,
                    Status = status,
                    ThisUpdate = list.ThisUpdate,
                    NextUpdate = list.NextUpdate,
                    RevocationTime = entry is null ? null : new DateTimeOffset(entry.RevocationDate, TimeSpan.Zero),
                    RevocationReason = entry is null ? null : ReadReasonCode(entry),
                    SignatureAlgorithm = new PkiAlgorithmIdentifier(list.SigAlgOid),
                    SignatureKeySizeBits = MinimumEllipticCurveKeySizeBits,
                    IssuerCertificate = SigningCertificateIssuer
                });

                if(entry is not null)
                {
                    SigningCertificateRevokedPerWire = new DateTimeOffset(entry.RevocationDate, TimeSpan.Zero);
                }
            }

            Assert.IsNotEmpty(statuses, "The received revocation lists have to include one issued by the signing certificate's own certification authority.");
            ReceivedRevocationStatusInformation = statuses;
        }


        /// <summary>The revocation status information this party derived from the received lists.</summary>
        private IReadOnlyList<RevocationStatusInformation> ReceivedRevocationStatusInformation { get; set; } = [];


        /// <summary>
        /// Assembles the verifier's own constraints, the inputs of Tables 18 and 20, and the seams the run
        /// composes.
        /// </summary>
        private void AssembleInputs()
        {
            List<TrustAnchorConstraint> anchorConstraints = [];
            for(int i = 0; i < TrustAnchors.Length; ++i)
            {
                anchorConstraints.Add(new TrustAnchorConstraint(TrustAnchors[i], SunsetDate: null));
            }

            var x509Constraints = new X509ValidationConstraints
            {
                TrustAnchors = anchorConstraints,
                ValidityModel = CertificateValidityModel.Shell
            };

            var cryptographicConstraints = new CryptographicConstraints
            {
                Entries =
                [
                    new AlgorithmReliabilityEntry(
                        new PkiAlgorithmIdentifier(EcdsaWithSha256Oid),
                        MinimumKeySizeBits: MinimumEllipticCurveKeySizeBits,
                        TrustedUntil: null),
                    new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null)
                ]
            };

            var constraints = new SignatureValidationConstraints
            {
                Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
                X509 = x509Constraints,
                Cryptographic = cryptographicConstraints,
                SignatureElements = new SignatureElementsConstraints()
            };

            List<PkiCertificateMemory> validationData = [.. TrustAnchors];
            validationData.AddRange(CertificateRevocationLists);

            var completer = new CertificateChainCompleter(validationData);
            var revocationChecker = new CrlRevocationChecker(CertificateRevocationLists);

            Seams = new SignatureValidationSeams
            {
                Format = CAdESSignatureFacts.Seam,
                CompleteCertificateChain = completer.CompleteAsync,
                ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync,
                CheckRevocation = revocationChecker.CheckAsync
            };

            Inputs = new SignatureValidationInputs
            {
                SignedDataObject = SignedDataObject,
                Constraints = constraints,
                CertificateValidationData = validationData,
                RevocationStatusInformation = ReceivedRevocationStatusInformation,
                TimestampConstraints = constraints
            };
        }


        /// <summary>Takes ownership of one carrier.</summary>
        /// <typeparam name="T">The carrier's type.</typeparam>
        /// <param name="carrier">The carrier.</param>
        /// <returns>The same carrier.</returns>
        private T Own<T>(T carrier) where T: IDisposable
        {
            owned.Add(carrier);

            return carrier;
        }


        /// <summary>Copies received octets into a pooled carrier of the stated kind.</summary>
        /// <param name="derBytes">The received DER octets.</param>
        /// <param name="tag">The kind discriminator the carrier states.</param>
        /// <returns>The carrier; the caller disposes it.</returns>
        private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
        {
            IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
            derBytes.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, tag);
        }


        /// <summary>Reads a received certificate with the verifying party's own independent reader.</summary>
        /// <param name="certificate">The carrier to read.</param>
        /// <returns>The parsed certificate.</returns>
        private static BcX509Certificate ReadCertificate(PkiCertificateMemory certificate) =>
            new X509CertificateParser().ReadCertificate(certificate.AsReadOnlySpan().ToArray());


        /// <summary>
        /// Reads the <c>CRLReason</c> of a revocation list entry
        /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1">RFC 5280 §5.3.1</see>).
        /// </summary>
        /// <param name="entry">The entry naming the revoked certificate.</param>
        /// <returns>The enumerated reason value, or <see langword="null"/> when the entry states none.</returns>
        private static int? ReadReasonCode(X509CrlEntry entry)
        {
            Asn1OctetString? encoded = entry.GetExtensionValue(X509Extensions.ReasonCode);

            return encoded is null
                ? null
                : DerEnumerated.GetInstance(Asn1Object.FromByteArray(encoded.GetOctets())).IntValueExact;
        }
    }
}
