// Browser-wasm smoke for VERIFIABLE's OWN libsodium seam: unlike Lumoin.Base.Libsodium's smoke,
// which calls LibsodiumCrypto's raw native operations directly, this exercises the same path a
// Verifiable consumer does — CryptoFunctionRegistry/KeyCreationFunctionRegistry dispatch onto
// LibsodiumCryptographicFunctions and LibsodiumKeyMaterialCreator — running inside dotnet.wasm with
// the family-built libsodium.a statically linked in by Lumoin.Base.Libsodium's own buildTransitive
// targets. Returns the failure count as the exit code so the CI job fails mechanically.
using System.Buffers;
using Lumoin.Base;
using Lumoin.Base.Libsodium;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Libsodium;

int pass = 0, fail = 0;

void Check(string name, bool hasPassed)
{
    if(hasPassed)
    {
        pass++;
        Console.WriteLine($"PASS {name}");
    }
    else
    {
        fail++;
        Console.WriteLine($"FAIL {name}");
    }
}

try
{
    //Registers the libsodium Ed25519 signing/verification and key-creation functions the same way
    //CryptoProviderStartup wires a backend for the CLI: a PatternMatcher closing over this
    //composition root's clock, initialized once against the registries every downstream call
    //resolves through.
    TimeProvider timeProvider = TimeProvider.System;

    CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
        (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
            (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Signing) =>
                    (privateKeyBytes, dataToSign, signaturePool, context, cancellationToken) =>
                        LibsodiumCryptographicFunctions.SignEd25519Async(privateKeyBytes, dataToSign, signaturePool, timeProvider, context, cancellationToken),
                _ => throw new ArgumentException($"No signing function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
            },
        (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
            (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) =>
                    (dataToVerify, signature, publicKeyMaterial, context, cancellationToken) =>
                        LibsodiumCryptographicFunctions.VerifyEd25519Async(dataToVerify, signature, publicKeyMaterial, timeProvider, context, cancellationToken),
                _ => throw new ArgumentException($"No verification function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
            });

    KeyCreationFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
        (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
            (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Signing) =>
                    pool => (LibsodiumKeyMaterialCreator.CreateEd25519Keys(pool), null),
                _ => throw new ArgumentException($"No key creation function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
            });
    Check("Registries initialize", true);

    //The posture guard: on browser-wasm the pool serving Ed25519 secret-key scratch memory must be
    //the pinned, zero-on-return managed branch, never sodium-guarded native memory — WebAssembly's
    //linear memory has no guard-page or memory-locking primitive for anything to sit behind. A run
    //where this flips true is the signal that a future toolchain made real guarded memory available
    //on browser-wasm and the posture in SodiumScratchPool needs revisiting.
    Check("OperatingSystem.IsBrowser is true under this runtime", OperatingSystem.IsBrowser());
    Check("Ed25519 scratch memory is the pinned managed posture, not sodium-guarded native",
        !LibsodiumCryptographicFunctions.UsesSodiumGuardedScratchMemory);

    //RFC 8032 section 7.1 test vector 1 (the empty message), through the registry dispatch exactly as
    //a Verifiable caller (e.g. Jws.SignAsync) reaches it, never LibsodiumCrypto directly.
    byte[] seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    byte[] expectedPublicKey = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    byte[] expectedSignature = Convert.FromHexString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    ReadOnlyMemory<byte> emptyMessage = ReadOnlyMemory<byte>.Empty;

    using BaseMemoryPool signaturePool = new();
    using BaseMemoryPool keyPool = new();
    using BaseMemoryPool convertedKeyPool = new();
    using BaseMemoryPool conversionScratchPool = new();

    SigningDelegate signEd25519 = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.Ed25519, Purpose.Signing);
    VerificationDelegate verifyEd25519 = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(CryptoAlgorithm.Ed25519, Purpose.Verification);

    (Signature vectorSignature, CryptoEvent? _) = await signEd25519(seed, emptyMessage, signaturePool).ConfigureAwait(false);
    using(vectorSignature)
    {
        Check("RFC 8032 vector 1 signature matches the known answer", vectorSignature.AsReadOnlySpan().SequenceEqual(expectedSignature));

        (bool isVectorVerified, CryptoEvent? _) = await verifyEd25519(emptyMessage, expectedSignature, expectedPublicKey).ConfigureAwait(false);
        Check("RFC 8032 vector 1 signature verifies against the known-answer public key", isVectorVerified);

        byte[] tamperedSignature = vectorSignature.AsReadOnlySpan().ToArray();
        tamperedSignature[0] ^= 0x01;
        (bool isTamperedVerified, CryptoEvent? _) = await verifyEd25519(emptyMessage, tamperedSignature, expectedPublicKey).ConfigureAwait(false);
        Check("A tampered RFC 8032 vector 1 signature is rejected", !isTamperedVerified);
    }

    //A freshly minted keypair, through the key-creation registry exactly as a Verifiable caller
    //(e.g. CryptographicKeyFactory) reaches it, sign/verify round trip and Ed25519-to-X25519
    //conversion. Verifiable.Libsodium exposes no Ed25519-to-X25519 conversion of its own, so the
    //conversion below runs through Lumoin.Base.Libsodium's LibsodiumKeyConversion directly, with an
    //explicitly passed scratch pool.
    KeyCreationDelegate createEd25519Keys = KeyCreationFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveCreation(CryptoAlgorithm.Ed25519, Purpose.Signing);
    (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> freshKeys, CryptoEvent? _) = createEd25519Keys(keyPool);
    using PublicKeyMemory freshPublicKey = freshKeys.PublicKey;
    using PrivateKeyMemory freshPrivateKey = freshKeys.PrivateKey;

    Check("A freshly minted Ed25519 keypair has non-empty material",
        freshPublicKey.AsReadOnlySpan().Length > 0 && freshPrivateKey.AsReadOnlySpan().Length > 0);

    ReadOnlyMemory<byte> freshMessage = "Verifiable.Libsodium wasm smoke"u8.ToArray();
    (Signature freshSignature, CryptoEvent? _) = await signEd25519(freshPrivateKey.AsReadOnlyMemory(), freshMessage, signaturePool).ConfigureAwait(false);
    using(freshSignature)
    {
        (bool isFreshVerified, CryptoEvent? _) = await verifyEd25519(freshMessage, freshSignature.AsReadOnlyMemory(), freshPublicKey.AsReadOnlyMemory()).ConfigureAwait(false);
        Check("A signature over a freshly minted keypair verifies", isFreshVerified);
    }

    using IMemoryOwner<byte> convertedPublicKey = LibsodiumKeyConversion.ConvertEd25519PublicKeyToCurve25519PublicKey(
        freshPublicKey.AsReadOnlySpan(), convertedKeyPool);
    using IMemoryOwner<byte> convertedPrivateKey = LibsodiumKeyConversion.ConvertEd25519PrivateKeyToCurve25519PrivateKey(
        freshPrivateKey.AsReadOnlySpan(), convertedKeyPool, conversionScratchPool);

    Span<byte> derivedPublicKey = stackalloc byte[LibsodiumCrypto.X25519PointLength];
    int scalarMultResult = LibsodiumCrypto.ScalarMultBase(derivedPublicKey, convertedPrivateKey.Memory.Span[..LibsodiumCrypto.X25519ScalarLength]);
    Check("ScalarMultBase over the converted X25519 private scalar returns 0", scalarMultResult == 0);
    Check("The converted X25519 public key agrees with ScalarMultBase over the converted private scalar",
        derivedPublicKey.SequenceEqual(convertedPublicKey.Memory.Span[..LibsodiumCrypto.X25519PointLength]));
}
catch(Exception ex)
{
    fail++;
    Console.WriteLine($"FAIL unhandled exception: {ex}");
}

Console.WriteLine(fail == 0 ? $"WASM-SMOKE-SUCCESS: {pass} passed" : $"WASM-SMOKE-FAILURE: {pass} passed, {fail} failed");
return fail;
