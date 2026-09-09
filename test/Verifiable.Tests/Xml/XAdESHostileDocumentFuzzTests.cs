using System.Globalization;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// A deterministic, seeded, in-process hostile-document generator over the qualifying-properties grammar
/// (the "fuzz-shaped round-trips" item, mirroring its <see cref="XmlDifferentialCorpusGenerator"/>
/// seeded-xorshift idiom): combines a curated pool of valid AND deliberately-broken
/// <c>QualifyingProperties</c> fragments, then applies one of a small set of byte-level mutations
/// (truncation, single-byte corruption, fragment duplication) to each — no corpora, no external files,
/// everything generated in-process from a fixed seed so a failing document's index is always reproducible.
/// </summary>
[TestClass]
internal sealed class XAdESHostileDocumentFuzzTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    /// <summary>The xorshift64* seed every generation starts from, fixed so the corpus is identical on every run.</summary>
    private const ulong Seed = 0x584144455348554E;

    /// <summary>The number of hostile documents generated and exercised.</summary>
    private const int DocumentCount = 400;

    private static string[] FragmentPool { get; } =
    [
        //Valid-shaped SignedProperties with a SigningTime.
        """<SignedProperties Id="sp1"><SignedSignatureProperties><SigningTime>2024-01-01T00:00:00Z</SigningTime></SignedSignatureProperties></SignedProperties>""",
        //Empty SignedProperties -- a named "shall not incorporate empty X" refusal.
        """<SignedProperties Id="sp2"></SignedProperties>""",
        //Valid-shaped UnsignedProperties carrying an unrecognized entry (tolerated) and a malformed CounterSignature.
        """<UnsignedProperties><UnsignedSignatureProperties><f:Filler xmlns:f="urn:filler"/><CounterSignature/></UnsignedSignatureProperties></UnsignedProperties>""",
        //Empty UnsignedSignatureProperties -- refused (XA-4.3.6-10).
        """<UnsignedProperties><UnsignedSignatureProperties></UnsignedSignatureProperties></UnsignedProperties>""",
        //Deprecated v1.3.2-namespace ArchiveTimeStamp -- named refusal.
        """<UnsignedProperties><UnsignedSignatureProperties><ArchiveTimeStamp/></UnsignedSignatureProperties></UnsignedProperties>""",
        //A SigningCertificateV2 with a malformed Cert (missing CertDigest).
        """<SignedProperties Id="sp3"><SignedSignatureProperties><SigningCertificateV2><Cert/></SigningCertificateV2></SignedSignatureProperties></SignedProperties>""",
        //A well-formed SigningCertificateV2 with one Cert.
        $"""<SignedProperties Id="sp4"><SignedSignatureProperties><SigningCertificateV2><Cert><CertDigest><ds:DigestMethod xmlns:ds="{DsNamespace}" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue xmlns:ds="{DsNamespace}">AQ==</ds:DigestValue></CertDigest></Cert></SigningCertificateV2></SignedSignatureProperties></SignedProperties>""",
        //Duplicate Id across two sibling elements -- ambiguous-Id shape.
        """<SignedProperties Id="dup"><SignedSignatureProperties><SigningTime>2024-01-01T00:00:00Z</SigningTime></SignedSignatureProperties></SignedProperties><UnsignedProperties Id="dup"><UnsignedSignatureProperties><f:Filler xmlns:f="urn:filler"/></UnsignedSignatureProperties></UnsignedProperties>""",
        //A CommitmentTypeIndication carrying a disallowed Qualifier on its Identifier.
        """<SignedProperties Id="sp5"><SignedDataObjectProperties><CommitmentTypeIndication><CommitmentTypeId><Identifier Qualifier="OIDAsURI">urn:x</Identifier></CommitmentTypeId><ObjectReference>#ref1</ObjectReference></CommitmentTypeIndication></SignedDataObjectProperties></SignedProperties>""",
        //Foreign-namespace unknown content directly in SignedSignatureProperties -- fail-closed.
        """<SignedProperties Id="sp6"><SignedSignatureProperties><f:Foreign xmlns:f="urn:foreign"/></SignedSignatureProperties></SignedProperties>""",
        //A well-formed CertificateValues with one pooled EncapsulatedX509Certificate entry -- drives a
        //POOLED reader (XAdESCertificateValues.TryRead) through the fuzzer, not just the index-based structural
        //containers XAdESQualifyingProperties.TryRead alone reaches.
        """<UnsignedProperties><UnsignedSignatureProperties><CertificateValues><EncapsulatedX509Certificate>MAMCAQI=</EncapsulatedX509Certificate></CertificateValues></UnsignedSignatureProperties></UnsignedProperties>""",
        //A CertificateValues whose first EncapsulatedX509Certificate entry decodes (renting a pooled buffer)
        //before an unrecognized trailing child refuses the read -- the "rented, then refused" custody path.
        """<UnsignedProperties><UnsignedSignatureProperties><CertificateValues><EncapsulatedX509Certificate>MAMCAQI=</EncapsulatedX509Certificate><Bogus/></CertificateValues></UnsignedSignatureProperties></UnsignedProperties>""",
    ];


    private static string BuildBaseDocument(ulong[] state, int index)
    {
        int fragmentCount = 1 + (int)(NextRandom(state) % 3);
        var builder = new StringBuilder();
        builder.Append(CultureInfo.InvariantCulture, $"""<QualifyingProperties xmlns="{V132}" xmlns:ds="{DsNamespace}" Target="#sig{index}">""");
        for(int i = 0; i < fragmentCount; ++i)
        {
            builder.Append(FragmentPool[NextRandom(state) % (ulong)FragmentPool.Length]);
        }

        builder.Append("</QualifyingProperties>");

        return builder.ToString();
    }


    private static ulong NextRandom(ulong[] state)
    {
        ulong x = state[0];
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state[0] = x;

        return x * 0x2545F4914F6CDD1D;
    }


    private static byte[] Mutate(byte[] baseOctets, ulong[] state)
    {
        int mutationKind = (int)(NextRandom(state) % 4);
        switch(mutationKind)
        {
            case 0:
                //No mutation -- the base fragment combination on its own.
                return baseOctets;

            case 1:
                //Truncate at a random prefix length -- exercises UnexpectedEndOfDocument refusals across
                //every boundary class the nesting reaches.
                {
                    int cut = baseOctets.Length == 0 ? 0 : (int)(NextRandom(state) % (ulong)baseOctets.Length);

                    return baseOctets[..cut];
                }

            case 2:
                //Corrupt a single byte -- classic bit-level fuzzing, exercises ill-formed-UTF-8/malformed-markup
                //paths the byte-level reader must refuse rather than crash on.
                {
                    if(baseOctets.Length == 0)
                    {
                        return baseOctets;
                    }

                    byte[] mutated = (byte[])baseOctets.Clone();
                    int position = (int)(NextRandom(state) % (ulong)mutated.Length);
                    mutated[position] = (byte)(NextRandom(state) % 256);

                    return mutated;
                }

            default:
                //Duplicate a random-length slice in place -- produces duplicate/unbalanced tag shapes.
                {
                    if(baseOctets.Length == 0)
                    {
                        return baseOctets;
                    }

                    int sliceLength = 1 + (int)(NextRandom(state) % (ulong)baseOctets.Length);
                    int start = (int)(NextRandom(state) % (ulong)baseOctets.Length);
                    int actualLength = Math.Min(sliceLength, baseOctets.Length - start);
                    byte[] slice = baseOctets[start..(start + actualLength)];
                    byte[] duplicated = new byte[baseOctets.Length + slice.Length];
                    baseOctets.CopyTo(duplicated, 0);
                    slice.CopyTo(duplicated, baseOctets.Length);

                    return duplicated;
                }
        }
    }


    /// <summary>
    /// Generates <see cref="DocumentCount"/> hostile documents from <see cref="Seed"/> and feeds each through
    /// <see cref="XmlNodeTable.TryParse"/>, <see cref="XAdESQualifyingProperties.TryRead"/> (index-based,
    /// pool-less structural read) and, for every element locally named <c>CertificateValues</c> the table
    /// carries regardless of where the structural read stopped, the POOLED
    /// <see cref="XAdESCertificateValues.TryRead(XmlNodeTable, int, BaseMemoryPool, out XAdESCertificateValues?, out XAdESReadError)"/>
    /// reader (the fragment pool's <c>CertificateValues</c> entries drive both a clean decode and a decode-then-refuse shape, so custody
    /// balance is proven over a reader that actually rents, not only over the index-based containers). None of the three ever throws (an unhandled
    /// exception fails this test loudly, the crash-proof this contract item asks for), and every path — refusal or acceptance — returns every pooled
    /// buffer it rented, observed per-document through <see cref="MeteredHousePool"/> accounting. Proves the "fuzz-shaped round-trips" item over the
    /// qualifying-properties grammar of <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void HostileQualifyingPropertiesDocumentsNeverCrashAndAlwaysBalanceCustody()
    {
        ulong[] state = [Seed];
        for(int index = 0; index < DocumentCount; ++index)
        {
            string baseDocument = BuildBaseDocument(state, index);
            byte[] documentOctets = Mutate(Encoding.UTF8.GetBytes(baseDocument), state);

            using var metered = new MeteredHousePool();
            //table is declared null and assigned through TryParse's out parameter below; a using
            //declaration cannot target a variable assigned after its declaration (CS1656).
            XmlNodeTable? table = null;
            try
            {
                bool isParsed = XmlNodeTable.TryParse(documentOctets, metered.Pool, out table, out XmlReadError parseError);
                if(isParsed && table!.DocumentElementIndex >= 0)
                {
                    _ = XAdESQualifyingProperties.TryRead(table, table.DocumentElementIndex, out XAdESQualifyingProperties _, out XAdESReadError _);

                    for(int nodeIndex = 0; nodeIndex < table.Count; ++nodeIndex)
                    {
                        if(table.KindOf(nodeIndex) != XmlNodeKind.Element || !table.LocalNameOf(nodeIndex).SequenceEqual("CertificateValues"u8))
                        {
                            continue;
                        }

                        //certificateValues is an out-parameter target; a using declaration cannot target a
                        //variable assigned through an out parameter after declaration.
                        bool isCertificateValuesRead = XAdESCertificateValues.TryRead(table, nodeIndex, metered.Pool, out XAdESCertificateValues? certificateValues, out XAdESReadError _);
                        try
                        {
                            Assert.AreEqual(isCertificateValuesRead, certificateValues is not null);
                        }
                        finally
                        {
                            certificateValues?.Dispose();
                        }
                    }
                }
            }
            finally
            {
                table?.Dispose();
            }

            Assert.AreEqual(0L, metered.OutstandingCount, $"Document #{index} left {metered.OutstandingCount} pooled buffer(s) outstanding.");
        }
    }
}
