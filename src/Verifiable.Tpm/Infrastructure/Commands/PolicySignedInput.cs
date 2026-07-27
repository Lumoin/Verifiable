using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicySigned command (CC = 0x00000160).
/// </summary>
/// <remarks>
/// <para>
/// Binds a policy session to a signature over <c>aHash = H_authAlg(nonceTPM || expiration || cpHashA ||
/// policyRef)</c>, where <c>H_authAlg</c> is the hash carried inside <see cref="SchemeHashAlg"/> (the signature's
/// own scheme hash) — independent of the policy session's hash algorithm. Neither handle requires authorization
/// (Auth Index: None for both <see cref="AuthObject"/> and <see cref="PolicySession"/>), so the command carries
/// no authorization area at all (<c>TPM_ST_NO_SESSIONS</c>), exactly as TPM2_VerifySignature() does.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.3, Table 124):
/// </para>
/// <list type="bullet">
///   <item><description>authObject (TPMI_DH_OBJECT): The key that validates the signature. Requires no authorization.</description></item>
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle being extended. Requires no authorization.</description></item>
///   <item><description>nonceTPM (TPM2B_NONCE): The policy session's retained nonceTPM, or Empty Buffer for a session-unbound authorization.</description></item>
///   <item><description>cpHashA (TPM2B_DIGEST): Empty Buffer if unbound; else the digest of the command parameters being authorized.</description></item>
///   <item><description>policyRef (TPM2B_NONCE): An opaque qualifier; Empty Buffer if none.</description></item>
///   <item><description>expiration (INT32): Seconds from nonceTPM's generation until expiry; 0 = no expiry; negative = ticket requested.</description></item>
///   <item><description>auth (TPMT_SIGNATURE): The signature over aHash.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicySignedInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    private IMemoryOwner<byte> NonceTpmOwner { get; }

    private IMemoryOwner<byte> CpHashAOwner { get; }

    private IMemoryOwner<byte> PolicyRefOwner { get; }

    private IMemoryOwner<byte> SignatureOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicySigned;

    /// <summary>
    /// Gets the handle of the key whose public part validates the signature.
    /// </summary>
    public uint AuthObject { get; }

    /// <summary>
    /// Gets the handle of the policy session being extended.
    /// </summary>
    public uint PolicySession { get; }

    /// <summary>
    /// Gets the policy session's retained nonceTPM, or empty for a session-unbound authorization.
    /// </summary>
    public ReadOnlyMemory<byte> NonceTpm { get; }

    /// <summary>
    /// Gets the digest of the command parameters being authorized, or empty if unbound.
    /// </summary>
    public ReadOnlyMemory<byte> CpHashA { get; }

    /// <summary>
    /// Gets the opaque policy qualifier, or empty for none.
    /// </summary>
    public ReadOnlyMemory<byte> PolicyRef { get; }

    /// <summary>
    /// Gets the signed expiration (seconds from nonceTPM's generation until expiry).
    /// </summary>
    public int Expiration { get; }

    /// <summary>
    /// Gets the signing algorithm (TPMI_ALG_SIG_SCHEME): TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS.
    /// </summary>
    public TpmAlgIdConstants SignatureScheme { get; }

    /// <summary>
    /// Gets the hash algorithm carried inside the signature (H_authAlg, which builds aHash).
    /// </summary>
    public TpmAlgIdConstants SchemeHashAlg { get; }

    /// <summary>
    /// Gets the signature octets: IEEE P1363 r ‖ s for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.
    /// </summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>
    /// Creates a TPM2_PolicySigned input for an ECDSA signature.
    /// </summary>
    /// <param name="authObject">The handle of the ECDSA key whose public point validates the signature.</param>
    /// <param name="policySession">The policy session handle being extended.</param>
    /// <param name="nonceTpm">The policy session's retained nonceTPM, or empty for a session-unbound authorization.</param>
    /// <param name="cpHashA">The digest of the command parameters being authorized, or empty if unbound.</param>
    /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
    /// <param name="expiration">The signed expiration; 0 = no expiry, negative = ticket requested.</param>
    /// <param name="signature">The signature as IEEE P1363 r ‖ s.</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the parameter buffers.</param>
    /// <returns>A new <see cref="PolicySignedInput"/>.</returns>
    public static PolicySignedInput ForEcdsa(
        uint authObject,
        uint policySession,
        ReadOnlySpan<byte> nonceTpm,
        ReadOnlySpan<byte> cpHashA,
        ReadOnlySpan<byte> policyRef,
        int expiration,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool) =>
        Create(authObject, policySession, nonceTpm, cpHashA, policyRef, expiration, signature, TpmAlgIdConstants.TPM_ALG_ECDSA, schemeHashAlg, pool);

    /// <summary>
    /// Creates a TPM2_PolicySigned input for an RSASSA (RSA PKCS#1 v1.5) signature.
    /// </summary>
    /// <param name="authObject">The handle of the RSA key whose public modulus validates the signature.</param>
    /// <param name="policySession">The policy session handle being extended.</param>
    /// <param name="nonceTpm">The policy session's retained nonceTPM, or empty for a session-unbound authorization.</param>
    /// <param name="cpHashA">The digest of the command parameters being authorized, or empty if unbound.</param>
    /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
    /// <param name="expiration">The signed expiration; 0 = no expiry, negative = ticket requested.</param>
    /// <param name="signature">The raw RSA signature octets.</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the parameter buffers.</param>
    /// <returns>A new <see cref="PolicySignedInput"/>.</returns>
    public static PolicySignedInput ForRsaSsa(
        uint authObject,
        uint policySession,
        ReadOnlySpan<byte> nonceTpm,
        ReadOnlySpan<byte> cpHashA,
        ReadOnlySpan<byte> policyRef,
        int expiration,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool) =>
        Create(authObject, policySession, nonceTpm, cpHashA, policyRef, expiration, signature, TpmAlgIdConstants.TPM_ALG_RSASSA, schemeHashAlg, pool);

    /// <summary>
    /// Creates a TPM2_PolicySigned input for an RSAPSS signature.
    /// </summary>
    /// <param name="authObject">The handle of the RSA key whose public modulus validates the signature.</param>
    /// <param name="policySession">The policy session handle being extended.</param>
    /// <param name="nonceTpm">The policy session's retained nonceTPM, or empty for a session-unbound authorization.</param>
    /// <param name="cpHashA">The digest of the command parameters being authorized, or empty if unbound.</param>
    /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
    /// <param name="expiration">The signed expiration; 0 = no expiry, negative = ticket requested.</param>
    /// <param name="signature">The raw RSA signature octets.</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the parameter buffers.</param>
    /// <returns>A new <see cref="PolicySignedInput"/>.</returns>
    public static PolicySignedInput ForRsaPss(
        uint authObject,
        uint policySession,
        ReadOnlySpan<byte> nonceTpm,
        ReadOnlySpan<byte> cpHashA,
        ReadOnlySpan<byte> policyRef,
        int expiration,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool) =>
        Create(authObject, policySession, nonceTpm, cpHashA, policyRef, expiration, signature, TpmAlgIdConstants.TPM_ALG_RSAPSS, schemeHashAlg, pool);

    /// <summary>
    /// Creates a TPM2_PolicySigned input for the given signing scheme.
    /// </summary>
    /// <param name="authObject">The handle of the key whose public part validates the signature.</param>
    /// <param name="policySession">The policy session handle being extended.</param>
    /// <param name="nonceTpm">The policy session's retained nonceTPM, or empty for a session-unbound authorization.</param>
    /// <param name="cpHashA">The digest of the command parameters being authorized, or empty if unbound.</param>
    /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
    /// <param name="expiration">The signed expiration; 0 = no expiry, negative = ticket requested.</param>
    /// <param name="signature">The signature octets: IEEE P1363 r ‖ s for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the parameter buffers.</param>
    /// <returns>A new <see cref="PolicySignedInput"/>.</returns>
    public static PolicySignedInput Create(
        uint authObject,
        uint policySession,
        ReadOnlySpan<byte> nonceTpm,
        ReadOnlySpan<byte> cpHashA,
        ReadOnlySpan<byte> policyRef,
        int expiration,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> nonceTpmOwner = pool.Rent(Math.Max(nonceTpm.Length, 1));
        nonceTpm.CopyTo(nonceTpmOwner.Memory.Span);

        IMemoryOwner<byte> cpHashAOwner = pool.Rent(Math.Max(cpHashA.Length, 1));
        cpHashA.CopyTo(cpHashAOwner.Memory.Span);

        IMemoryOwner<byte> policyRefOwner = pool.Rent(Math.Max(policyRef.Length, 1));
        policyRef.CopyTo(policyRefOwner.Memory.Span);

        IMemoryOwner<byte> signatureOwner = pool.Rent(Math.Max(signature.Length, 1));
        signature.CopyTo(signatureOwner.Memory.Span);

        return new PolicySignedInput(
            authObject,
            policySession,
            nonceTpmOwner,
            nonceTpmOwner.Memory[..nonceTpm.Length],
            cpHashAOwner,
            cpHashAOwner.Memory[..cpHashA.Length],
            policyRefOwner,
            policyRefOwner.Memory[..policyRef.Length],
            expiration,
            signatureOwner,
            signatureOwner.Memory[..signature.Length],
            signatureScheme,
            schemeHashAlg);
    }

    private PolicySignedInput(
        uint authObject,
        uint policySession,
        IMemoryOwner<byte> nonceTpmOwner,
        ReadOnlyMemory<byte> nonceTpm,
        IMemoryOwner<byte> cpHashAOwner,
        ReadOnlyMemory<byte> cpHashA,
        IMemoryOwner<byte> policyRefOwner,
        ReadOnlyMemory<byte> policyRef,
        int expiration,
        IMemoryOwner<byte> signatureOwner,
        ReadOnlyMemory<byte> signature,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg)
    {
        AuthObject = authObject;
        PolicySession = policySession;
        NonceTpmOwner = nonceTpmOwner;
        NonceTpm = nonceTpm;
        CpHashAOwner = cpHashAOwner;
        CpHashA = cpHashA;
        PolicyRefOwner = policyRefOwner;
        PolicyRef = policyRef;
        Expiration = expiration;
        SignatureOwner = signatureOwner;
        Signature = signature;
        SignatureScheme = signatureScheme;
        SchemeHashAlg = schemeHashAlg;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //TPMT_SIGNATURE: sigAlg (UINT16) + hash (UINT16) + either the ECDSA r/s TPM2B pair (two size prefixes)
        //or the single RSA TPM2B signature (one size prefix); the signature octets are Signature.Length either way.
        int signatureFramingSize = SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA
            ? (4 * sizeof(ushort))
            : (3 * sizeof(ushort));

        return sizeof(uint) + sizeof(uint) +                             //authObject + policySession (handle area).
               sizeof(ushort) + NonceTpm.Length +                        //nonceTPM (TPM2B_NONCE).
               sizeof(ushort) + CpHashA.Length +                         //cpHashA (TPM2B_DIGEST).
               sizeof(ushort) + PolicyRef.Length +                       //policyRef (TPM2B_NONCE).
               sizeof(int) +                                             //expiration (INT32).
               signatureFramingSize + Signature.Length;                  //auth (TPMT_SIGNATURE).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(AuthObject);
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteTpm2b(NonceTpm.Span);
        writer.WriteTpm2b(CpHashA.Span);
        writer.WriteTpm2b(PolicyRef.Span);
        writer.WriteInt32(Expiration);

        writer.WriteUInt16((ushort)SignatureScheme);  //sigAlg: the TPMU_SIGNATURE selector.
        writer.WriteUInt16((ushort)SchemeHashAlg);    //hash inside the signature member (H_authAlg).

        ReadOnlySpan<byte> signatureBytes = Signature.Span;
        if(SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA)
        {
            //TPMS_SIGNATURE_ECDSA: r and s are the equal-width halves of the IEEE P1363 signature — the same
            //framing the simulator's response serializer uses for TPM2_Sign()/TPM2_Certify() and friends.
            if((signatureBytes.Length & 1) != 0)
            {
                throw new InvalidOperationException(
                    $"An ECDSA signature must be IEEE P1363 r ‖ s of even length so r and s are equal width; got {signatureBytes.Length} octets.");
            }

            int fieldWidth = signatureBytes.Length / 2;
            writer.WriteTpm2b(signatureBytes[..fieldWidth]);   //signatureR (TPM2B_ECC_PARAMETER).
            writer.WriteTpm2b(signatureBytes[fieldWidth..]);   //signatureS (TPM2B_ECC_PARAMETER).
        }
        else
        {
            //TPMS_SIGNATURE_RSA: the whole signature as one TPM2B_PUBLIC_KEY_RSA.
            writer.WriteTpm2b(signatureBytes);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            NonceTpmOwner.Dispose();
            CpHashAOwner.Dispose();
            PolicyRefOwner.Dispose();
            SignatureOwner.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"PolicySignedInput(AuthObject={AuthObject:X8}, PolicySession={PolicySession:X8}, Expiration={Expiration}, Scheme={SignatureScheme}, Hash={SchemeHashAlg})";
}
