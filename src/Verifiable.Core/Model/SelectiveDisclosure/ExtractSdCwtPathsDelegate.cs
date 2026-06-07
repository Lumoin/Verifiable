using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Binds each holder-selected disclosure to the credential path it occupies in a redacted
/// SD-CWT payload, by recomputing each disclosure's digest and matching it against the
/// payload's redacted-claim digests, per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is the CBOR seam the structural verifier composes but does not perform itself: it
/// parses only the payload from the signed envelope and supplies the holder-selected
/// disclosures, so a narrowed presentation binds against exactly what was presented — never
/// the original full set the wire form's unprotected header still carries. Wired by the
/// application to <c>Verifiable.Cbor.SdCwtPathExtraction.ExtractPaths</c>.
/// </para>
/// </remarks>
/// <param name="payload">The redacted CWT payload bytes (CBOR).</param>
/// <param name="disclosures">The disclosures to bind against the payload's digests.</param>
/// <param name="encoder">Delegate for Base64Url encoding used in digest computation.</param>
/// <param name="pool">Memory pool for allocations.</param>
/// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
/// <returns>A dictionary mapping each bound disclosure to its credential path.</returns>
public delegate IReadOnlyDictionary<SdDisclosure, CredentialPath> ExtractSdCwtPathsDelegate(
    ReadOnlyMemory<byte> payload,
    IReadOnlyList<SdDisclosure> disclosures,
    EncodeDelegate encoder,
    MemoryPool<byte> pool,
    string hashAlgorithm);
