using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// The shipped default for <see cref="ParseFidoU2fAttestationStatementDelegate"/>: decodes a
/// <c>fido-u2f</c> attestation statement's CBOR bytes using System.Formats.Cbor.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication Level
/// 3, section 8.6: FIDO U2F Attestation Statement Format</see> defines the <c>attStmt</c> syntax as a
/// CBOR map with exactly the required members <c>x5c</c> (a single-element array of one DER-encoded
/// certificate) and <c>sig</c> — unlike <c>packed</c>'s <c>attStmt</c>, there is no <c>alg</c> member
/// and <c>x5c</c> is mandatory rather than optional. Per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All
/// Conformance Classes</see>'s CTAP2 canonical CBOR encoding requirement, this reader reads with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, which already rejects a duplicate or out-of-order
/// map key at the framework level; this reader additionally rejects an unrecognised member, a missing
/// required member, an <c>x5c</c> array whose element count is not exactly one (section 8.6
/// verification procedure step 2: "Check that x5c has exactly one element"), or trailing bytes beyond
/// the single root-level map — violations the conformance mode itself does not know to check — naming
/// the specific violation in every case. The single <c>x5c</c> entry is copied into a pooled
/// <see cref="PkiCertificateMemory"/> tagged <see cref="PkiCertificateTags.X509Certificate"/>.
/// </para>
/// </remarks>
public static class FidoU2fAttestationStatementCborReader
{
    /// <summary>The CBOR map key for the mandatory single-element certificate array.</summary>
    private const string X5cKey = "x5c";

    /// <summary>The CBOR map key for the attestation signature.</summary>
    private const string SigKey = "sig";

    /// <summary>The exact element count section 8.6 verification procedure step 2 requires of <c>x5c</c>.</summary>
    private const int RequiredX5cElementCount = 1;


    /// <summary>
    /// Decodes <paramref name="attestationStatement"/> into a <see cref="FidoU2fAttestationStatement"/>.
    /// Method-group-compatible with <see cref="ParseFidoU2fAttestationStatementDelegate"/>.
    /// </summary>
    /// <param name="attestationStatement">The raw <c>attStmt</c> CBOR bytes.</param>
    /// <param name="pool">The memory pool the decoded <c>x5c</c> entry's certificate carrier rents from.</param>
    /// <returns>The decoded statement.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="attestationStatement"/> is not a CTAP2 canonical CBOR map conforming to the
    /// fido-u2f <c>attStmt</c> syntax, including when <c>x5c</c> does not carry exactly one element.
    /// </exception>
    public static FidoU2fAttestationStatement Parse(ReadOnlyMemory<byte> attestationStatement, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        List<PkiCertificateMemory>? x5c = null;
        try
        {
            var reader = new CborReader(attestationStatement, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            ReadOnlyMemory<byte>? sig = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string key = reader.ReadTextString();
                entriesRead++;

                switch(key)
                {
                    case(X5cKey):
                    {
                        x5c = ReadCertificateChain(reader, pool);
                        break;
                    }
                    case(SigKey):
                    {
                        sig = reader.ReadByteString();
                        break;
                    }
                    default:
                    {
                        throw new Fido2FormatException($"The fido-u2f attestation statement carries the unrecognised member '{key}'; only 'x5c' and 'sig' are permitted.");
                    }
                }
            }

            reader.ReadEndMap();

            if(reader.BytesRemaining != 0)
            {
                throw new Fido2FormatException($"The fido-u2f attestation statement buffer carries {reader.BytesRemaining} trailing byte(s) beyond its single CBOR map.");
            }

            if(x5c is null || sig is null)
            {
                throw new Fido2FormatException("The fido-u2f attestation statement is missing one or both of the required 'x5c' and 'sig' members.");
            }

            if(x5c.Count != RequiredX5cElementCount)
            {
                throw new Fido2FormatException($"The fido-u2f attestation statement's x5c must contain exactly one element, but {x5c.Count} were found.");
            }

            return new FidoU2fAttestationStatement(sig.Value, x5c);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException or FormatException)
        {
            DisposeAll(x5c);
            throw new Fido2FormatException("The fido-u2f attestation statement bytes are not valid CTAP2 canonical CBOR conforming to the fido-u2f attStmt syntax.", exception);
        }
        catch
        {
            DisposeAll(x5c);
            throw;
        }

        //Reads the CBOR array of DER-encoded certificate byte strings at the reader's current position
        //into pooled PkiCertificateMemory carriers, per the fido-u2f x5c CDDL.
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
    }
}
