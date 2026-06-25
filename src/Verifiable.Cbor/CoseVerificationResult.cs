using System;

namespace Verifiable.Cbor;

/// <summary>
/// The outcome of verifying a COSE_Sign1 structure — the verified payload and the decoded header
/// parameters when <see cref="IsValid"/> is <see langword="true"/>. The COSE counterpart of the JOSE
/// layer's <c>JwsVerificationResult</c>, produced by <see cref="CoseVerification.VerifyAndDecodeAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Mint-only: the constructor and the factories are <see langword="internal"/>, so a result with
/// <see cref="IsValid"/> <see langword="true"/> can only originate from this library's COSE verify path —
/// application code cannot fabricate a "valid" result. This mirrors <c>JwsVerificationResult</c>,
/// <c>DidCommSignedVerificationResult</c>, and the <c>Verified{T}</c> trust-carrier pattern.
/// </para>
/// <para>
/// This is a low-level result carrying raw bytes. For credential-specific verification that decodes the
/// payload, use <c>CoseCredentialVerificationResult</c> in <c>Verifiable.Core.Model.Credentials</c>.
/// </para>
/// </remarks>
public readonly record struct CoseVerificationResult
{
    internal CoseVerificationResult(
        bool isValid,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> protectedHeader,
        int? algorithm,
        string? keyId)
    {
        IsValid = isValid;
        Payload = payload;
        ProtectedHeader = protectedHeader;
        Algorithm = algorithm;
        KeyId = keyId;
    }


    /// <summary>Whether the signature is valid.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// The verified payload bytes when verification succeeded, otherwise empty. GC-owned (copied out of
    /// the parsed message before its pooled buffers were released), so it is safe to hold past the call.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>The serialized COSE protected-header bytes; GC-owned, like <see cref="Payload"/>.</summary>
    public ReadOnlyMemory<byte> ProtectedHeader { get; }

    /// <summary>The COSE algorithm (protected-header label 1), or <see langword="null"/> when absent.</summary>
    public int? Algorithm { get; }

    /// <summary>
    /// The key identifier (header label 4) as a UTF-8 string when it is valid UTF-8, otherwise
    /// <see langword="null"/>; read from the protected header first, then the unprotected header.
    /// </summary>
    public string? KeyId { get; }


    //Mints a successful result. Internal so only the library's COSE verify path can produce one.
    internal static CoseVerificationResult Success(
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> protectedHeader,
        int? algorithm = null,
        string? keyId = null) => new(true, payload, protectedHeader, algorithm, keyId);


    //Mints a failed result carrying no payload.
    internal static CoseVerificationResult Failed(
        ReadOnlyMemory<byte> protectedHeader = default,
        int? algorithm = null,
        string? keyId = null) => new(false, default, protectedHeader, algorithm, keyId);
}
