using System.Collections.Generic;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Extracts the <c>x5chain</c> COSE header parameter from a COSE_Sign1's wire bytes, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360, Section 2</see>, as a
/// chain-ordered (leaf first) list of <see cref="PkiCertificateMemory"/>.
/// </summary>
/// <remarks>
/// A Core seam rather than a direct call into <c>Verifiable.Cbor</c>: <c>Verifiable.OAuth</c> does not
/// reference <c>Verifiable.Cbor</c>, so an SD-CWT verifier that needs the embedded credential's
/// <c>x5chain</c> for OID4VP 1.0 §6.1.1.1 <c>aki</c> evidence takes this delegate instead, wired to
/// <c>Verifiable.Cbor.CoseSign1X5ChainExtractor.Extract</c> — the same COSE-generic reader the mdoc
/// IssuerAuth path uses.
/// </remarks>
/// <param name="coseSign1">The COSE_Sign1 wire bytes (RFC 9052 tag 18 array).</param>
/// <param name="pool">Memory pool for the certificate DER allocations.</param>
/// <returns>
/// Chain-ordered certificates (leaf first) when the <c>x5chain</c> header is present; an empty list
/// when it is absent. The caller owns and must dispose every returned instance.
/// </returns>
public delegate IReadOnlyList<PkiCertificateMemory> ExtractCoseSign1X5ChainDelegate(
    ReadOnlyMemory<byte> coseSign1,
    BaseMemoryPool pool);
