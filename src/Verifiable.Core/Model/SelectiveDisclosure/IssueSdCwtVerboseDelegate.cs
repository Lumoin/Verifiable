using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Issues an SD-CWT by redacting selectively disclosable claims from a CBOR payload and
/// signing the redacted result as a COSE_Sign1 message, additionally returning the redacted
/// payload that was signed, per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is the CBOR issue-pipeline seam the typed-claims convenience members
/// (<c>SdCwtIssuanceExtensions</c>) compose but do not perform themselves: the convenience
/// members serialize the claims to CBOR via a serializer delegate, then hand the bytes to this
/// pipeline. It is the issuance analog of <see cref="ExtractSdCwtPathsDelegate"/> on the
/// verification side. Wired by the application to
/// <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.
/// </para>
/// </remarks>
/// <param name="payload">The CBOR-encoded CWT claims set bytes.</param>
/// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
/// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
/// <param name="privateKey">The issuer's signing key.</param>
/// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
/// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
/// <param name="signingDelegate">The signing function to use.</param>
/// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c> when <see langword="null"/>.</param>
/// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <c>"application/sd-cwt"</c>.</param>
/// <param name="decoyOptions">
/// Optional decoy-digest configuration (count policy plus per-call state) per RFC 9901 §4.2.5 (the
/// SD-CWT draft inherits the concept), threaded explicitly. When <see cref="DecoyDigestOptions.None"/> (the default),
/// the implementation adds no decoys (the minimal, deterministic form). See <c>DecoyDigestOptions</c>.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The issuance result and the redacted CBOR payload that was signed.</returns>
public delegate ValueTask<(SdTokenResult Result, ReadOnlyMemory<byte> RedactedPayload)> IssueSdCwtVerboseDelegate(
    ReadOnlyMemory<byte> payload,
    IReadOnlySet<CredentialPath> disclosablePaths,
    GenerateDisclosureSaltDelegate generateSalt,
    PrivateKeyMemory privateKey,
    string keyId,
    MemoryPool<byte> memoryPool,
    SigningDelegate signingDelegate,
    string? hashAlgorithm,
    string? mediaType,
    DecoyDigestOptions decoyOptions,
    CancellationToken cancellationToken);
