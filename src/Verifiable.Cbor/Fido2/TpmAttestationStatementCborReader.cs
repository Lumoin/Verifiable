using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// The shipped default for <see cref="ParseTpmAttestationStatementDelegate"/>: decodes a
/// <c>tpm</c> attestation statement's CBOR bytes using System.Formats.Cbor.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level
/// 3, section 8.3: TPM Attestation Statement Format</see> defines the <c>attStmt</c> syntax as a
/// CBOR map whose <c>ver</c> member MUST equal the literal string <c>"2.0"</c>, and whose
/// <c>alg</c> and <c>x5c</c> members are grouped as always occurring together — the format has no
/// self-attestation branch, so both are REQUIRED, never omitted as a pair the way <c>packed</c>'s
/// self-attestation branch omits them. <c>sig</c>, <c>certInfo</c>, and <c>pubArea</c> are likewise
/// REQUIRED. Per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All
/// Conformance Classes</see>'s CTAP2 canonical CBOR encoding requirement, this reader reads with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, which already rejects a duplicate or
/// out-of-order map key at the framework level; this reader additionally rejects a non-<c>"2.0"</c>
/// <c>ver</c> value, an unrecognised member, a missing required member, or trailing bytes beyond
/// the single root-level map — violations the conformance mode itself does not know to check —
/// naming the specific violation in every case. Each <c>x5c</c> entry is copied into a pooled
/// <see cref="PkiCertificateMemory"/> tagged <see cref="PkiCertificateTags.X509Certificate"/>; on
/// any failure after one or more entries have been acquired, every acquired entry is disposed
/// before the exception propagates, so a rejected statement never leaks pooled memory.
/// </para>
/// </remarks>
public static class TpmAttestationStatementCborReader
{
    /// <summary>The CBOR map key for the TPM specification version, which MUST equal <see cref="RequiredVersion"/>.</summary>
    private const string VerKey = "ver";

    /// <summary>The CBOR map key for the COSE algorithm identifier.</summary>
    private const string AlgKey = "alg";

    /// <summary>The CBOR map key for the attestation signature (a marshaled TPMT_SIGNATURE).</summary>
    private const string SigKey = "sig";

    /// <summary>The CBOR map key for the AIK certificate chain.</summary>
    private const string X5cKey = "x5c";

    /// <summary>The CBOR map key for the marshaled TPMS_ATTEST bytes.</summary>
    private const string CertInfoKey = "certInfo";

    /// <summary>The CBOR map key for the marshaled TPMT_PUBLIC bytes.</summary>
    private const string PubAreaKey = "pubArea";

    /// <summary>The only value the <c>ver</c> member is permitted to carry.</summary>
    private const string RequiredVersion = "2.0";


    /// <summary>
    /// Decodes <paramref name="attestationStatement"/> into a <see cref="TpmAttestationStatement"/>.
    /// Method-group-compatible with <see cref="ParseTpmAttestationStatementDelegate"/>.
    /// </summary>
    /// <param name="attestationStatement">The raw <c>attStmt</c> CBOR bytes.</param>
    /// <param name="pool">The memory pool the decoded <c>x5c</c> entries' certificate carriers rent from.</param>
    /// <returns>The decoded statement.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="attestationStatement"/> is not a CTAP2 canonical CBOR map conforming to the
    /// tpm <c>attStmt</c> syntax.
    /// </exception>
    public static TpmAttestationStatement Parse(ReadOnlyMemory<byte> attestationStatement, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        List<PkiCertificateMemory>? x5c = null;
        try
        {
            var reader = new CborReader(attestationStatement, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            string? ver = null;
            int? alg = null;
            ReadOnlyMemory<byte>? sig = null;
            ReadOnlyMemory<byte>? certInfo = null;
            ReadOnlyMemory<byte>? pubArea = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string key = reader.ReadTextString();
                entriesRead++;

                switch(key)
                {
                    case(VerKey):
                    {
                        ver = reader.ReadTextString();
                        break;
                    }
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
                    case(CertInfoKey):
                    {
                        certInfo = reader.ReadByteString();
                        break;
                    }
                    case(PubAreaKey):
                    {
                        pubArea = reader.ReadByteString();
                        break;
                    }
                    case(X5cKey):
                    {
                        x5c = ReadCertificateChain(reader, pool);
                        break;
                    }
                    default:
                    {
                        throw new Fido2FormatException($"The tpm attestation statement carries the unrecognised member '{key}'; only 'ver', 'alg', 'x5c', 'sig', 'certInfo', and 'pubArea' are permitted.");
                    }
                }
            }

            reader.ReadEndMap();

            if(reader.BytesRemaining != 0)
            {
                throw new Fido2FormatException($"The tpm attestation statement buffer carries {reader.BytesRemaining} trailing byte(s) beyond its single CBOR map.");
            }

            if(ver is null || alg is null || sig is null || certInfo is null || pubArea is null || x5c is null)
            {
                throw new Fido2FormatException("The tpm attestation statement is missing one or more of the required 'ver', 'alg', 'x5c', 'sig', 'certInfo', and 'pubArea' members.");
            }

            if(!string.Equals(ver, RequiredVersion, StringComparison.Ordinal))
            {
                throw new Fido2FormatException($"The tpm attestation statement's 'ver' member is '{ver}'; it MUST equal '{RequiredVersion}'.");
            }

            return new TpmAttestationStatement(alg.Value, sig.Value, certInfo.Value, pubArea.Value, x5c);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException or FormatException)
        {
            DisposeAll(x5c);
            throw new Fido2FormatException("The tpm attestation statement bytes are not valid CTAP2 canonical CBOR conforming to the tpm attStmt syntax.", exception);
        }
        catch
        {
            DisposeAll(x5c);
            throw;
        }

        //Reads the CBOR array of DER-encoded certificate byte strings at the reader's current position
        //into pooled PkiCertificateMemory carriers, AIK certificate first, per the tpm x5c CDDL.
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
