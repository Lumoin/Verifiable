using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Binds each holder-selected disclosure to the credential path it occupies in a redacted
/// SD-JWT payload, by recomputing each disclosure's digest and matching it against the
/// payload's <c>_sd</c> digests, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9901.html">RFC 9901 (SD-JWT)</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is the JSON seam the structural verifier composes but does not perform itself: it reads
/// the redacted payload from the signed compact JWS (<see cref="SdToken{TEnvelope}.IssuerSigned"/>)
/// and matches its <c>_sd</c> digests against the holder-selected
/// <see cref="SdToken{TEnvelope}.Disclosures"/>, so a narrowed presentation binds against exactly
/// what was presented. Wired by the application to <c>Verifiable.Json.SdJwtPathExtraction.ExtractPaths</c>.
/// It is the SD-JWT analog of <see cref="ExtractSdCwtPathsDelegate"/>; the shapes differ because
/// the JWS payload is base64url-encoded inside the compact form (so the token and a decoder are
/// supplied) whereas the COSE payload is already a separate byte segment after parsing.
/// </para>
/// </remarks>
/// <param name="token">The SD-JWT token whose compact JWS carries the redacted payload and whose disclosures are bound.</param>
/// <param name="decoder">Delegate for Base64Url decoding the JWS payload segment.</param>
/// <param name="encoder">Delegate for Base64Url encoding used in digest computation.</param>
/// <param name="pool">Memory pool for allocations.</param>
/// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
/// <returns>A dictionary mapping each bound disclosure to its credential path.</returns>
public delegate IReadOnlyDictionary<SdDisclosure, CredentialPath> ExtractSdJwtPathsDelegate(
    SdToken<string> token,
    DecodeDelegate decoder,
    EncodeDelegate encoder,
    MemoryPool<byte> pool,
    string hashAlgorithm);
