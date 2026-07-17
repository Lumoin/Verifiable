using System;
using Verifiable.Cryptography;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// One PIN/UV auth protocol's key-agreement key pair, owned by <see cref="CtapAuthenticatorState"/> for
/// the simulator's whole lifetime.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinProto1">
/// CTAP 2.3, section 6.5.6: PIN/UV Auth Protocol One</see>: "a P-256 private key, x, and the
/// associated public point xB" — <c>initialize()</c>/<c>regenerate()</c>'s state. Each of the two
/// supported protocols maintains its own key-agreement key material, minted via
/// <see cref="CryptographicKeyEvents.CreateKeyPair(Context.CryptoAlgorithm, Purpose, System.Buffers.MemoryPool{byte}, string?)"/>
/// at construction and refreshed by <see cref="CtapAuthenticatorState.PowerCycle"/>'s <c>regenerate()</c>
/// half — the old pair is disposed there, never independently. Owns its pooled key material, mirroring
/// <see cref="CtapCredentialRecord"/>'s dispose-walk convention: this record's <see cref="Dispose"/> is
/// called from <see cref="CtapAuthenticatorSimulator.Dispose"/> or <see cref="CtapAuthenticatorState.PowerCycle"/>.
/// </remarks>
/// <param name="PublicKey">The P-256 key-agreement public point. Owned by this record.</param>
/// <param name="PrivateKey">The P-256 key-agreement private scalar. Owned by this record.</param>
public sealed record CtapPinUvAuthKeyAgreementKeyPair(PublicKeyMemory PublicKey, PrivateKeyMemory PrivateKey): IDisposable
{
    /// <summary>
    /// Releases the key-agreement public and private key material this record owns.
    /// </summary>
    public void Dispose()
    {
        PublicKey.Dispose();
        PrivateKey.Dispose();
    }
}
