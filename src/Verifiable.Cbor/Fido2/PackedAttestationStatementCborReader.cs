using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// The shipped default for <see cref="ParsePackedAttestationStatementDelegate"/>: decodes a
/// <c>packed</c> attestation statement's CBOR bytes using System.Formats.Cbor.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level
/// 3, section 8.2: Packed Attestation Statement Format</see> defines the <c>attStmt</c> syntax as a
/// CBOR map with the required members <c>alg</c> and <c>sig</c>, and an optional <c>x5c</c> member (an
/// array of at least one DER-encoded certificate, leaf first, present only for a certified — not self
/// — attestation). Per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All
/// Conformance Classes</see>'s CTAP2 canonical CBOR encoding requirement, this reader reads with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, which already rejects a duplicate or out-of-order
/// map key at the framework level; this reader additionally rejects an unrecognised member, a missing
/// required member, or trailing bytes beyond the single root-level map — violations the conformance
/// mode itself does not know to check — naming the specific violation in every case. Each <c>x5c</c>
/// entry is copied into a pooled
/// <see cref="PkiCertificateMemory"/> tagged <see cref="PkiCertificateTags.X509Certificate"/>; on any
/// failure after one or more entries have been acquired, every acquired entry is disposed before the
/// exception propagates, so a rejected statement never leaks pooled memory.
/// </para>
/// </remarks>
public static class PackedAttestationStatementCborReader
{
    /// <summary>The CBOR map key for the COSE algorithm identifier.</summary>
    private const string AlgKey = "alg";

    /// <summary>The CBOR map key for the attestation signature.</summary>
    private const string SigKey = "sig";

    /// <summary>The CBOR map key for the optional certificate chain.</summary>
    private const string X5cKey = "x5c";


    /// <summary>
    /// Decodes <paramref name="attestationStatement"/> into a <see cref="PackedAttestationStatement"/>.
    /// Method-group-compatible with <see cref="ParsePackedAttestationStatementDelegate"/>.
    /// </summary>
    /// <param name="attestationStatement">The raw <c>attStmt</c> CBOR bytes.</param>
    /// <param name="pool">The memory pool the decoded <c>x5c</c> entries' certificate carriers rent from.</param>
    /// <returns>The decoded statement.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="attestationStatement"/> is not a CTAP2 canonical CBOR map conforming to the
    /// packed <c>attStmt</c> syntax.
    /// </exception>
    public static PackedAttestationStatement Parse(ReadOnlyMemory<byte> attestationStatement, MemoryPool<byte> pool)
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

                switch(key)
                {
                    case(AlgKey):
                    {
                        alg = checked((int)reader.ReadInt64());
                        break;
                    }
                    case(SigKey):
                    {
                        sig = reader.ReadByteString();
                        break;
                    }
                    case(X5cKey):
                    {
                        x5c = ReadCertificateChain(reader, pool);
                        break;
                    }
                    default:
                    {
                        throw new Fido2FormatException($"The packed attestation statement carries the unrecognised member '{key}'; only 'alg', 'sig', and 'x5c' are permitted.");
                    }
                }
            }

            reader.ReadEndMap();

            if(reader.BytesRemaining != 0)
            {
                throw new Fido2FormatException($"The packed attestation statement buffer carries {reader.BytesRemaining} trailing byte(s) beyond its single CBOR map.");
            }

            if(alg is null || sig is null)
            {
                throw new Fido2FormatException("The packed attestation statement is missing one or both of the required 'alg' and 'sig' members.");
            }

            return new PackedAttestationStatement(alg.Value, sig.Value, x5c);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException or FormatException)
        {
            DisposeAll(x5c);
            throw new Fido2FormatException("The packed attestation statement bytes are not valid CTAP2 canonical CBOR conforming to the packed attStmt syntax.", exception);
        }
        catch
        {
            DisposeAll(x5c);
            throw;
        }

        //Reads the CBOR array of DER-encoded certificate byte strings at the reader's current position
        //into pooled PkiCertificateMemory carriers, leaf first, per the packed x5c CDDL.
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
