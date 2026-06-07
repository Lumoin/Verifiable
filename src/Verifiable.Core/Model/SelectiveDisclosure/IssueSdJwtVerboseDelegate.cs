using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Issues an SD-JWT by redacting selectively disclosable claims from a UTF-8 JSON payload and
/// signing the redacted result as a compact JWS, additionally returning the redacted payload that
/// was signed, per <see href="https://www.rfc-editor.org/rfc/rfc9901.html">RFC 9901 (SD-JWT)</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is the JSON issue-pipeline seam the typed-claims convenience members
/// (<c>SdJwtIssuanceExtensions</c>) compose but do not perform themselves: the convenience members
/// serialize the claims to JSON via a serializer delegate, then hand the bytes to this pipeline.
/// It is the issuance analog of <see cref="ExtractSdJwtPathsDelegate"/> on the verification side,
/// and the SD-JWT sibling of <see cref="IssueSdCwtVerboseDelegate"/>. Wired by the application to
/// <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.
/// </para>
/// </remarks>
/// <param name="payload">The UTF-8 JSON-encoded claims set bytes.</param>
/// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
/// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
/// <param name="privateKey">The issuer's signing key.</param>
/// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
/// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
/// <param name="signingDelegate">The signing function to use.</param>
/// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c> when <see langword="null"/>.</param>
/// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
/// <param name="decoyOptions">
/// Optional decoy-digest configuration (count policy plus per-call state) per RFC 9901 §4.2.5,
/// threaded explicitly. When <see cref="DecoyDigestOptions.None"/> (the default), the implementation adds no decoys (the minimal,
/// deterministic form). See <c>DecoyDigestOptions</c> / <c>DecoyDigestPolicy</c>.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The issuance result and the redacted JSON payload that was signed.</returns>
public delegate ValueTask<(SdTokenResult Result, ReadOnlyMemory<byte> RedactedPayload)> IssueSdJwtVerboseDelegate(
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
