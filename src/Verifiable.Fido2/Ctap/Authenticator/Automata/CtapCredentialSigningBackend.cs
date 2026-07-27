using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2.Ctap.Authenticator.Custody;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// Generates a fresh WebAuthn credential key pair for a chosen COSE algorithm, modelling
/// <c>authenticatorMakeCredential</c>'s "generate a new credential key pair for the algorithm chosen"
/// step (CTAP 2.3, section 6.1.2, step 15).
/// </summary>
/// <remarks>
/// The simulator models key generation, not a real entropy source, so the actual minting is supplied
/// through this seam rather than baked in — exactly as <c>Verifiable.Tpm.Automata.TpmEccKeyGenerationDelegate</c>
/// keeps <see cref="Verifiable.Tpm"/> backend-agnostic. A caller composes a backend over the production
/// key-creation registry (<see cref="CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm, Purpose, MemoryPool{byte}, string?)"/>),
/// never a bespoke keygen routine.
/// </remarks>
/// <param name="coseAlgorithm">The chosen COSE algorithm identifier the new credential key must use.</param>
/// <param name="pool">The memory pool backing the returned key material.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The generated credential key pair. The caller owns and disposes it.</returns>
public delegate ValueTask<CtapCredentialKeyPair> CtapCredentialKeyGenerationDelegate(
    int coseAlgorithm,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);

/// <summary>
/// The key material a <see cref="CtapCredentialKeyGenerationDelegate"/> produces: the COSE_Key view the
/// simulator embeds in <c>attestedCredentialData</c>, paired with the bound <see cref="PrivateKey"/> the
/// credential store retains for later assertion signing.
/// </summary>
/// <param name="PublicKey">The generated credential's public key, as a COSE_Key view.</param>
/// <param name="PrivateKey">
/// The generated credential's private key, with its signing function already bound (for example via
/// <see cref="CryptographicKeyFactory.CreatePrivateKey(PrivateKeyMemory, string, Tag, string?, System.Collections.Frozen.FrozenDictionary{string, object}?)"/>).
/// </param>
/// <param name="CredentialKeyCustodyExport">
/// An independent copy of <paramref name="PrivateKey"/>'s raw key-material bytes, captured while this
/// delegate still holds the un-wrapped <c>PrivateKeyMemory</c> alongside it, or <see langword="null"/>
/// when this backend does not support state custody for its minted credentials. See
/// <see cref="CtapCredentialRecord.CredentialKeyCustodyExport"/>'s own remarks for why this copy exists
/// and why it cannot be produced later from <paramref name="PrivateKey"/> alone.
/// </param>
public sealed record CtapCredentialKeyPair(CoseKey PublicKey, PrivateKey PrivateKey, PooledMemory? CredentialKeyCustodyExport = null): IDisposable
{
    /// <summary>
    /// Releases the private key material and, when present, the custody-exportable key-material copy.
    /// <see cref="PublicKey"/> carries no pooled memory of its own and needs no disposal.
    /// </summary>
    public void Dispose()
    {
        PrivateKey.Dispose();
        CredentialKeyCustodyExport?.Dispose();
    }
}

/// <summary>
/// The credential-minting backend a <see cref="CtapAuthenticatorSimulator"/> drives for
/// <c>authenticatorMakeCredential</c>: a key generator paired with the set of COSE algorithms it can mint.
/// </summary>
/// <remarks>
/// A seam-bundle the constructor of <see cref="CtapAuthenticatorSimulator"/> takes as one optional
/// dependency — mirroring <c>Verifiable.Tpm.Automata.TpmEccSigningBackend</c>'s role in
/// <c>Verifiable.Tpm.Automata.TpmSimulator</c>. When absent, <see cref="SupportedAlgorithms"/> is
/// effectively empty, so <c>authenticatorMakeCredential</c>'s pubKeyCredParams algorithm-selection loop
/// never chooses an algorithm and the command answers <c>CTAP2_ERR_UNSUPPORTED_ALGORITHM</c>, exactly as
/// TPM defaults its object/signing commands to <c>TPM_RC_COMMAND_CODE</c> when no signing backend is
/// injected.
/// </remarks>
/// <param name="SupportedAlgorithms">
/// The COSE algorithm identifiers this backend can mint a credential key for. For
/// <c>authenticatorMakeCredential</c>'s own pubKeyCredParams algorithm-selection loop, this list only
/// decides MEMBERSHIP — the request's own <c>pubKeyCredParams</c> ordering decides "first-supported-
/// wins", this list's order is irrelevant there. For <c>authenticatorGetInfo</c>'s <c>algorithms</c>
/// (<c>0x0A</c>) member (R6), this list's own order ALSO becomes the advertised most-preferred-to-
/// least-preferred order (CTAP 2.3, snapshot lines 4424-4427) — a caller composing a backend with more
/// than one supported algorithm is choosing the getInfo advertisement order by the order it lists them
/// here.
/// </param>
/// <param name="GenerateCredentialKeyPair">Generates a fresh credential key pair for a chosen algorithm.</param>
public sealed record CtapCredentialSigningBackend(
    IReadOnlyList<int> SupportedAlgorithms,
    CtapCredentialKeyGenerationDelegate GenerateCredentialKeyPair)
{
    /// <summary>The key identifier every ES256-default-minted credential key is registered under.</summary>
    private const string DefaultCredentialKeyIdentifier = "ctap-authenticator-simulator-credential-key";

    /// <summary>The key identifier every EdDSA-default-minted credential key is registered under.</summary>
    private const string EdDsaCredentialKeyIdentifier = "ctap-authenticator-simulator-eddsa-credential-key";

    /// <summary>
    /// Builds the shipped ES256-only default backend: mints NIST P-256 credential keys through the
    /// registered production key-creation seam.
    /// </summary>
    /// <returns>A backend whose <see cref="SupportedAlgorithms"/> is exactly <c>[ES256]</c>.</returns>
    /// <remarks>
    /// Composition of ES256/384/512, RS256, or EdDSA credential support beyond this default is a matter
    /// of supplying a different <see cref="CtapCredentialSigningBackend"/> — this default exists only as
    /// the minimal, spec-clean starting point the wave-2 contract calls for; it is not the only legal
    /// shape a caller may compose.
    /// </remarks>
    public static CtapCredentialSigningBackend CreateEs256Default() =>
        new([WellKnownCoseAlgorithms.Es256], GenerateEs256KeyPairAsync);

    /// <summary>
    /// Builds an EdDSA-only backend: mints Ed25519 credential keys through the same registered
    /// production key-creation seam <see cref="CreateEs256Default"/> uses, just for
    /// <see cref="CryptoAlgorithm.Ed25519"/>/<see cref="Purpose.Signing"/> instead of P-256.
    /// </summary>
    /// <returns>A backend whose <see cref="SupportedAlgorithms"/> is exactly <c>[EdDSA]</c>.</returns>
    /// <remarks>
    /// Composing this backend is the whole of "EdDSA support" for a <see cref="CtapAuthenticatorSimulator"/>
    /// — no new capability beyond what <see cref="CreateEs256Default"/> already demonstrates, per this
    /// record's own remarks.
    /// </remarks>
    public static CtapCredentialSigningBackend CreateEdDsaDefault() =>
        new([WellKnownCoseAlgorithms.EdDsa], GenerateEdDsaKeyPairAsync);

    /// <summary>
    /// Mints a fresh NIST P-256 (ES256) credential key pair through
    /// <see cref="CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm, Purpose, MemoryPool{byte}, string?)"/>,
    /// mirroring the EC2 COSE_Key construction the observed FIDO2 CBOM workload already performs.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The PrivateKey's and the custody-export PooledMemory's ownership both transfer to the returned CtapCredentialKeyPair, which CtapAuthenticatorSimulator's GenerateCredentialAsync either disposes (on failure) or hands to the persisted CtapCredentialRecord (on success); CoseKey carries no pooled memory of its own.")]
    private static async ValueTask<CtapCredentialKeyPair> GenerateEs256KeyPairAsync(int coseAlgorithm, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Signing, pool);

        using PublicKeyMemory publicKeyMemory = keys.PublicKey;

        //R2 (wavect): captured HERE, while this method still holds keys.PrivateKey as an un-wrapped
        //PrivateKeyMemory, since CtapCredentialRecord.CredentialKey's own PrivateKey type exposes no
        //public API to read its raw bytes back out once wrapped — see
        //CtapCredentialRecord.CredentialKeyCustodyExport's own remarks.
        PooledMemory credentialKeyCustodyExport = await keys.PrivateKey.WithKeyBytesAsync(
            static (keyBytes, capturePool) => ValueTask.FromResult(
                PooledMemory.FromBytes(keyBytes.Span, capturePool, CtapAuthenticatorCustodyBufferTags.CredentialKeyCustodyExportPayload)),
            pool).ConfigureAwait(false);

        PrivateKey privateKey;
        try
        {
            privateKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, DefaultCredentialKeyIdentifier, keys.PrivateKey.Tag);
        }
        catch
        {
            credentialKeyCustodyExport.Dispose();
            throw;
        }

        ReadOnlySpan<byte> compressed = publicKeyMemory.AsReadOnlySpan();
        EllipticCurveTypes curveType = EllipticCurveUtilities.CurveTypeFor(publicKeyMemory.Tag.Get<CryptoAlgorithm>());
        byte[] y = EllipticCurveUtilities.Decompress(compressed, curveType);
        CoseKey publicKey = new(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: compressed[1..].ToArray(), y: y);

        return new CtapCredentialKeyPair(publicKey, privateKey, credentialKeyCustodyExport);
    }


    /// <summary>
    /// Mints a fresh Ed25519 (EdDSA) credential key pair through
    /// <see cref="CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm, Purpose, MemoryPool{byte}, string?)"/>.
    /// Unlike <see cref="GenerateEs256KeyPairAsync"/>'s EC2 point, an OKP public key needs no
    /// decompression — the minted public-key bytes are the COSE_Key's <c>x</c> parameter directly, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</see>'s Ed25519 encoding and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9053#section-7.2">RFC 9053 §7.2</see>'s OKP COSE_Key
    /// parameters.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The PrivateKey's ownership transfers to the returned CtapCredentialKeyPair, which CtapAuthenticatorSimulator's GenerateCredentialAsync either disposes (on failure) or hands to the persisted CtapCredentialRecord (on success); CoseKey carries no pooled memory of its own.")]
    private static ValueTask<CtapCredentialKeyPair> GenerateEdDsaKeyPairAsync(int coseAlgorithm, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.Ed25519, Purpose.Signing, pool);

        using PublicKeyMemory publicKeyMemory = keys.PublicKey;
        PrivateKey privateKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, EdDsaCredentialKeyIdentifier, keys.PrivateKey.Tag);

        CoseKey publicKey = new(kty: CoseKeyTypes.Okp, alg: WellKnownCoseAlgorithms.EdDsa, curve: CoseKeyCurves.Ed25519, x: publicKeyMemory.AsReadOnlySpan().ToArray());

        return ValueTask.FromResult(new CtapCredentialKeyPair(publicKey, privateKey));
    }
}
