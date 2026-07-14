using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// The shipped default for <see cref="ParseAndroidKeyAttestationStatementDelegate"/>: decodes an
/// <c>android-key</c> attestation statement's CBOR bytes using System.Formats.Cbor.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication
/// Level 3, section 8.4: Android Key Attestation Statement Format</see> defines the <c>attStmt</c>
/// syntax as a CBOR map with the required members <c>alg</c>, <c>sig</c>, and <c>x5c</c> — unlike
/// <c>packed</c>'s optional <c>x5c</c>, the <c>android-key</c> format has no self-attestation
/// branch, so <c>x5c</c> is always required on the wire; a map omitting it is rejected here exactly
/// like a map omitting <c>alg</c> or <c>sig</c>. Per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All
/// Conformance Classes</see>'s CTAP2 canonical CBOR encoding requirement, this reader reads with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, which already rejects a duplicate or
/// out-of-order map key at the framework level; this reader additionally rejects an unrecognised
/// member, a missing required member, or trailing bytes beyond the single root-level map —
/// violations the conformance mode itself does not know to check — naming the specific violation in
/// every case. A present-but-empty <c>x5c</c> array decodes successfully here (the CDDL's
/// <c>≥1</c>-element shape is <see cref="AndroidKeyAttestation"/>'s verification-procedure concern,
/// not this codec's, mirroring how <see cref="PackedAttestationStatementCborReader"/> defers the
/// same check). Each <c>x5c</c> entry is copied into a pooled
/// <see cref="PkiCertificateMemory"/> tagged <see cref="PkiCertificateTags.X509Certificate"/>; on
/// any failure after one or more entries have been acquired, every acquired entry is disposed
/// before the exception propagates, so a rejected statement never leaks pooled memory.
/// </para>
/// </remarks>
public static class AndroidKeyAttestationStatementCborReader
{
    /// <summary>The CBOR map key for the COSE algorithm identifier.</summary>
    private const string AlgKey = "alg";

    /// <summary>The CBOR map key for the attestation signature.</summary>
    private const string SigKey = "sig";

    /// <summary>The CBOR map key for the mandatory certificate chain.</summary>
    private const string X5cKey = "x5c";


    /// <summary>
    /// Decodes <paramref name="attestationStatement"/> into an <see cref="AndroidKeyAttestationStatement"/>.
    /// Method-group-compatible with <see cref="ParseAndroidKeyAttestationStatementDelegate"/>.
    /// </summary>
    /// <param name="attestationStatement">The raw <c>attStmt</c> CBOR bytes.</param>
    /// <param name="pool">The memory pool the decoded <c>x5c</c> entries' certificate carriers rent from.</param>
    /// <returns>The decoded statement.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="attestationStatement"/> is not a CTAP2 canonical CBOR map conforming to the
    /// android-key <c>attStmt</c> syntax.
    /// </exception>
    public static AndroidKeyAttestationStatement Parse(ReadOnlyMemory<byte> attestationStatement, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        List<PkiCertificateMemory>? x5c = null;
        try
        {
            var reader = new CborReader(attestationStatement, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            int? alg = null;
            ReadOnlyMemory<byte>? sig = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string key = reader.ReadTextString();
                entriesRead++;

                _ = key switch
                {
                    AlgKey => AssignAlg(reader, ref alg),
                    SigKey => AssignSig(reader, ref sig),
                    X5cKey => AssignX5c(reader, pool, ref x5c),
                    _ => throw new Fido2FormatException($"The android-key attestation statement carries the unrecognised member '{key}'; only 'alg', 'sig', and 'x5c' are permitted.")
                };
            }

            reader.ReadEndMap();

            if(reader.BytesRemaining != 0)
            {
                throw new Fido2FormatException($"The android-key attestation statement buffer carries {reader.BytesRemaining} trailing byte(s) beyond its single CBOR map.");
            }

            if(alg is null || sig is null)
            {
                throw new Fido2FormatException("The android-key attestation statement is missing one or more of the required 'alg' and 'sig' members.");
            }

            if(x5c is null)
            {
                throw new Fido2FormatException("The android-key attestation statement is missing the required 'x5c' member; android-key has no self-attestation branch.");
            }

            return new AndroidKeyAttestationStatement(alg.Value, sig.Value, x5c);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException or FormatException)
        {
            DisposeAll(x5c);
            throw new Fido2FormatException("The android-key attestation statement bytes are not valid CTAP2 canonical CBOR conforming to the android-key attStmt syntax.", exception);
        }
        catch
        {
            DisposeAll(x5c);
            throw;
        }

        //Reads the CBOR array of DER-encoded certificate byte strings at the reader's current position
        //into pooled PkiCertificateMemory carriers, leaf/credCert first, per the android-key x5c CDDL.
        static List<PkiCertificateMemory> ReadCertificateChain(CborReader reader, MemoryPool<byte> pool)
        {
            var certificates = new List<PkiCertificateMemory>();
            int? elementCount = reader.ReadStartArray();

            int elementsRead = 0;
            while(elementCount is null ? reader.PeekState() != CborReaderState.EndArray : elementsRead < elementCount.Value)
            {
                byte[] derBytes = reader.ReadByteString();
                elementsRead++;

                IMemoryOwner<byte> owner = pool.Rent(derBytes.Length);
                derBytes.CopyTo(owner.Memory.Span);
                certificates.Add(new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate));
            }

            reader.ReadEndArray();

            return certificates;
        }

        //Disposes every certificate carrier acquired so far. Called on every failure path so a
        //rejected or malformed statement never leaks pooled memory.
        static void DisposeAll(List<PkiCertificateMemory>? certificates)
        {
            if(certificates is not null)
            {
                foreach(PkiCertificateMemory certificate in certificates)
                {
                    certificate.Dispose();
                }
            }
        }

        //Assigns the decoded COSE algorithm identifier to alg.
        static bool AssignAlg(CborReader reader, ref int? alg)
        {
            alg = checked((int)reader.ReadInt64());

            return true;
        }

        //Assigns the decoded attestation signature to sig.
        static bool AssignSig(CborReader reader, ref ReadOnlyMemory<byte>? sig)
        {
            sig = reader.ReadByteString();

            return true;
        }

        //Assigns the decoded certificate chain to x5c.
        static bool AssignX5c(CborReader reader, MemoryPool<byte> pool, ref List<PkiCertificateMemory>? x5c)
        {
            x5c = ReadCertificateChain(reader, pool);

            return true;
        }
    }
}
