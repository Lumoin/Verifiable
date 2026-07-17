using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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
public sealed record CtapCredentialKeyPair(CoseKey PublicKey, PrivateKey PrivateKey): IDisposable
{
    /// <summary>
    /// Releases the private key material. <see cref="PublicKey"/> carries no pooled memory of its own and
    /// needs no disposal.
    /// </summary>
    public void Dispose()
    {
        PrivateKey.Dispose();
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
/// The COSE algorithm identifiers this backend can mint a credential key for, in no particular
/// preference order (the request's own <c>pubKeyCredParams</c> ordering decides "first-supported-wins" —
/// this list only decides membership).
/// </param>
/// <param name="GenerateCredentialKeyPair">Generates a fresh credential key pair for a chosen algorithm.</param>
public sealed record CtapCredentialSigningBackend(
    IReadOnlyList<int> SupportedAlgorithms,
    CtapCredentialKeyGenerationDelegate GenerateCredentialKeyPair)
{
    /// <summary>The key identifier every ES256-default-minted credential key is registered under.</summary>
    private const string DefaultCredentialKeyIdentifier = "ctap-authenticator-simulator-credential-key";

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
    /// Mints a fresh NIST P-256 (ES256) credential key pair through
    /// <see cref="CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm, Purpose, MemoryPool{byte}, string?)"/>,
    /// mirroring the EC2 COSE_Key construction the observed FIDO2 CBOM workload already performs.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The PrivateKey's ownership transfers to the returned CtapCredentialKeyPair, which CtapAuthenticatorSimulator's GenerateCredentialAsync either disposes (on failure) or hands to the persisted CtapCredentialRecord (on success); CoseKey carries no pooled memory of its own.")]
    private static ValueTask<CtapCredentialKeyPair> GenerateEs256KeyPairAsync(int coseAlgorithm, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Signing, pool);

        using PublicKeyMemory publicKeyMemory = keys.PublicKey;
        PrivateKey privateKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, DefaultCredentialKeyIdentifier, keys.PrivateKey.Tag);

        ReadOnlySpan<byte> compressed = publicKeyMemory.AsReadOnlySpan();
        EllipticCurveTypes curveType = EllipticCurveUtilities.CurveTypeFor(publicKeyMemory.Tag.Get<CryptoAlgorithm>());
        byte[] y = EllipticCurveUtilities.Decompress(compressed, curveType);
        CoseKey publicKey = new(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: compressed[1..].ToArray(), y: y);

        return ValueTask.FromResult(new CtapCredentialKeyPair(publicKey, privateKey));
    }
}
