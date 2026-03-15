using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Represents the Internal Certificate issued by the Wallet Provider during
/// wallet activation (Protocol 4 of the SECDSA specification).
/// </summary>
/// <remarks>
/// <para>
/// The Internal Certificate binds together:
/// </para>
/// <list type="bullet">
///   <item><description>The wallet account identifier <see cref="AccountId"/>.</description></item>
///   <item><description>The Native Cryptographic Hardware (NCH) public key U = u·G. The NCH is the hardware-bound key store on the user device (TPM, Secure Enclave, StrongBox, or equivalent). U is used for early instruction authenticity checks at the wallet provider perimeter before the instruction reaches the Wallet Secure Cryptographic Application (WSCA).</description></item>
///   <item><description>The blinding public key G' = aU·G, where aU is HSM-bound at the wallet provider.</description></item>
///   <item><description>The blind SECDSA public key Y' = aU·Y = aU·P·U.</description></item>
/// </list>
/// <para>
/// The raw SECDSA public key Y is never stored in this certificate. Only the blinded
/// form Y' is present, preventing offline PIN brute-force attacks even if an attacker
/// obtains the certificate.
/// </para>
/// <para>
/// Specification reference: SECDSA specification, Protocol 4.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class InternalCertificate: IDisposable
{
    /// <summary>Tracks whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <summary>Owns the memory backing <see cref="IssuerSignature"/>.</summary>
    private IMemoryOwner<byte> IssuerSignatureOwner { get; }

    /// <summary>
    /// Gets the wallet account identifier binding this certificate to a specific user registration.
    /// </summary>
    public string AccountId { get; }

    /// <summary>
    /// Gets the NCH-bound public key U = u·G in uncompressed form.
    /// </summary>
    /// <remarks>
    /// Enables perimeter-level instruction authenticity verification using the NCH signing
    /// key before the instruction reaches the WSCA (Algorithm 37, Steps 1–5).
    /// </remarks>
    public EcPointBytes NchPublicKey { get; }

    /// <summary>
    /// Gets the blinding public key G' = aU·G in uncompressed form.
    /// </summary>
    /// <remarks>
    /// Used in Algorithm 36 to compute the scaled verification values G'' = s^(-1)·G'
    /// and the Schnorr challenge.
    /// </remarks>
    public EcPointBytes BlindingPublicKey { get; }

    /// <summary>
    /// Gets the blind SECDSA public key Y' = aU·Y in uncompressed form.
    /// </summary>
    /// <remarks>
    /// Y' = aU·P·U where P is the user's PIN key and U is the NCH-bound public key.
    /// The WSCA verifies instructions against this value without ever seeing the raw
    /// SECDSA public key Y = P·U.
    /// </remarks>
    public EcPointBytes BlindSecdsaPublicKey { get; }

    /// <summary>
    /// Gets the issuer signature over the certificate fields.
    /// </summary>
    /// <remarks>
    /// Produced by the WSCA over a trusted chain (Protocol 4, Step 18). The bytes
    /// are the raw DER signature; interpretation is left to the serialization layer.
    /// </remarks>
    public ReadOnlyMemory<byte> IssuerSignature { get; }

    /// <summary>
    /// Creates an <see cref="InternalCertificate"/> from its constituent parts.
    /// </summary>
    /// <param name="accountId">The wallet account identifier.</param>
    /// <param name="nchPublicKey">The NCH-bound public key U. Ownership transfers to this instance.</param>
    /// <param name="blindingPublicKey">The blinding public key G'. Ownership transfers to this instance.</param>
    /// <param name="blindSecdsaPublicKey">The blind SECDSA public key Y'. Ownership transfers to this instance.</param>
    /// <param name="issuerSignatureBytes">The raw issuer signature bytes.</param>
    /// <param name="pool">The memory pool for allocating the signature buffer.</param>
    /// <returns>A new <see cref="InternalCertificate"/>.</returns>
    public static InternalCertificate Create(
        string accountId,
        EcPointBytes nchPublicKey,
        EcPointBytes blindingPublicKey,
        EcPointBytes blindSecdsaPublicKey,
        ReadOnlySpan<byte> issuerSignatureBytes,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(accountId);
        ArgumentNullException.ThrowIfNull(nchPublicKey);
        ArgumentNullException.ThrowIfNull(blindingPublicKey);
        ArgumentNullException.ThrowIfNull(blindSecdsaPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> sigOwner = pool.Rent(issuerSignatureBytes.Length);
        issuerSignatureBytes.CopyTo(sigOwner.Memory.Span);
        return new InternalCertificate(
            accountId,
            nchPublicKey,
            blindingPublicKey,
            blindSecdsaPublicKey,
            sigOwner,
            sigOwner.Memory.Slice(0, issuerSignatureBytes.Length));
    }

    private InternalCertificate(
        string accountId,
        EcPointBytes nchPublicKey,
        EcPointBytes blindingPublicKey,
        EcPointBytes blindSecdsaPublicKey,
        IMemoryOwner<byte> issuerSignatureOwner,
        ReadOnlyMemory<byte> issuerSignature)
    {
        AccountId = accountId;
        NchPublicKey = nchPublicKey;
        BlindingPublicKey = blindingPublicKey;
        BlindSecdsaPublicKey = blindSecdsaPublicKey;
        IssuerSignatureOwner = issuerSignatureOwner;
        IssuerSignature = issuerSignature;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            NchPublicKey.Dispose();
            BlindingPublicKey.Dispose();
            BlindSecdsaPublicKey.Dispose();
            IssuerSignatureOwner.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"InternalCertificate(AccountId={AccountId}, U={NchPublicKey.Value.Length} bytes, G'={BlindingPublicKey.Value.Length} bytes, Y'={BlindSecdsaPublicKey.Value.Length} bytes)";
}
