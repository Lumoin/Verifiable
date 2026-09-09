using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the plain (<c>TPM_ST_NO_SESSIONS</c>) form of <c>TPM2_RSA_Encrypt()</c> against the in-house
/// behavioural <see cref="TpmSimulator"/> through the production command path (<see cref="TpmCommandExecutor"/>
/// with <see cref="RsaEncryptInput"/> and <see cref="TpmResponseCodec.RsaEncrypt"/>): "This command performs RSA
/// encryption using the indicated padding scheme according to RFC 8017".
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorRsaEncryptTests
{
    /// <summary>The Name algorithm used throughout.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA modulus width in bits every key in this class uses.</summary>
    private const ushort RsaKeyBits = 2048;

    /// <summary>The modulus width in octets (<c>k</c>) for <see cref="RsaKeyBits"/>.</summary>
    private const int ModulusOctets = RsaKeyBits / 8;

    /// <summary>SHA-256's digest width in octets.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>SHA-512's digest width in octets.</summary>
    private const int Sha512DigestSize = 64;

    /// <summary>A selector this simulator's implemented profile does not recognize at all (TPM 2.0 Library Part 2, clause 6.3, Table 8).</summary>
    private const ushort UnknownSchemeSelector = 0x7FFF;

    /// <summary>The persistent handle a persisted decrypt key takes.</summary>
    private const uint PersistentHandle = 0x8100_0175;

    /// <summary>The attribute word of an external unrestricted signing key: unbound, caller-supplied, USER-role by password, dictionary-attack exempt, no decrypt attribute at all.</summary>
    private const TpmaObject ExternalSigningAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;

    /// <summary>The attribute word of an external unrestricted decrypt key: unbound, caller-supplied, USER-role by password, dictionary-attack exempt, decrypt-capable, restricted CLEAR.</summary>
    private const TpmaObject ExternalDecryptAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.DECRYPT | TpmaObject.NO_DA;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "Data is OAEP padded as described in 7.1 of RFC 8017": a <c>TPM2_LoadExternal()</c>-loaded full RSA key
    /// encrypts under OAEP(SHA-256), and BouncyCastle — the independent off-TPM oracle, driven against the
    /// framework key the TPM never received the private half of — decrypts the ciphertext back to the original
    /// plaintext, with and without a label.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// </summary>
    /// <param name="isLabelPresent">Whether a non-empty label is used.</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task RsaEncryptOaepRoundTripDecryptsOffTpmWithTheSameLabel(bool isLabelPresent)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptOaepRoundTripDecryptsOffTpmWithTheSameLabel)}-{isLabelPresent}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        byte[] label = isLabelPresent ? "TEST\0"u8.ToArray() : [];
        byte[] plaintext = "The quick brown fox jumps."u8.ToArray();

        using LoadExternalResponse loaded = await LoadRsaAsync(tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSigningAttributes, TpmtRsaScheme.Null, key.Modulus, key.P).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, loaded.ObjectHandle.Value, plaintext, TpmtRsaDecrypt.Oaep(NameAlg), label);
        Assert.IsTrue(encrypted.IsSuccess, $"TPM2_RSA_Encrypt() under OAEP must succeed: '{encrypted.ResponseCode}'.");
        using RsaEncryptResponse encryptedResponse = encrypted.Value;

        byte[] recovered = DecryptOaepOffTpm(key.Key, encryptedResponse.OutData.Buffer, label, NameAlg);
        Assert.IsTrue(recovered.AsSpan().SequenceEqual(plaintext), "The off-TPM OAEP oracle must recover exactly what the TPM encrypted.");
    }

    /// <summary>
    /// "Data is padded as described in 7.2 of RFC 8017": a <c>TPM2_LoadExternal()</c>-loaded full RSA key
    /// encrypts under RSAES, and the framework's PKCS#1 v1.5 decryption — the independent off-TPM oracle —
    /// recovers the original plaintext.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptRsaEsRoundTripDecryptsOffTpm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptRsaEsRoundTripDecryptsOffTpm), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        byte[] plaintext = "RSAES round trip."u8.ToArray();

        using LoadExternalResponse loaded = await LoadRsaAsync(tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSigningAttributes, TpmtRsaScheme.Null, key.Modulus, key.P).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, loaded.ObjectHandle.Value, plaintext, TpmtRsaDecrypt.RsaEs, ReadOnlyMemory<byte>.Empty);
        Assert.IsTrue(encrypted.IsSuccess, $"TPM2_RSA_Encrypt() under RSAES must succeed: '{encrypted.ResponseCode}'.");
        using RsaEncryptResponse encryptedResponse = encrypted.Value;

        byte[] recovered = key.Key.Decrypt(encryptedResponse.OutData.Buffer.ToArray(), RSAEncryptionPadding.Pkcs1);
        Assert.IsTrue(recovered.AsSpan().SequenceEqual(plaintext), "The framework's PKCS#1 v1.5 decryption must recover exactly what the TPM encrypted.");
    }

    /// <summary>
    /// "Data is OAEP padded as described in 7.1 of RFC 8017 (PKCS#1)": a key whose own scheme is OAEP(SHA-384)
    /// selects that single hash for BOTH the label digest and the mask-generation function — RFC 8017's
    /// EME-OAEP encoding takes one <c>Hash</c> parameter, so Table 42's key-scheme cell offers only the one hash
    /// the key's own <c>TPMT_RSA_SCHEME</c> names. The independent BouncyCastle oracle recovers the plaintext
    /// exactly when driven with SHA-384 for both lhash and MGF1, and fails whichever of the two is instead
    /// driven with SHA-256.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1, Table 42</see>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 43.4</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptKeyOaepHashSelectsBothLhashAndMgf1()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptKeyOaepHashSelectsBothLhashAndMgf1), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        byte[] plaintext = "The OAEP hash cell in the encrypt direction."u8.ToArray();
        byte[] label = "TEST\0"u8.ToArray();

        using LoadExternalResponse loaded = await LoadRsaAsync(
            tpm, registry, pool, TpmiRhHierarchy.Null, ExternalDecryptAttributes, TpmtRsaScheme.Oaep(TpmAlgIdConstants.TPM_ALG_SHA384), key.Modulus, key.P).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, loaded.ObjectHandle.Value, plaintext, TpmtRsaDecrypt.Null, label);
        Assert.IsTrue(encrypted.IsSuccess, $"TPM2_RSA_Encrypt() under the key's own OAEP(SHA-384) must succeed: '{encrypted.ResponseCode}'.");
        using RsaEncryptResponse encryptedResponse = encrypted.Value;
        byte[] ciphertext = encryptedResponse.OutData.Buffer.ToArray();

        byte[] recovered = DecryptOaepOffTpmWithHashes(key.Key, ciphertext, label, TpmAlgIdConstants.TPM_ALG_SHA384, TpmAlgIdConstants.TPM_ALG_SHA384);
        Assert.IsTrue(recovered.AsSpan().SequenceEqual(plaintext), "SHA-384 for both lhash and MGF1 must recover exactly what the TPM encrypted.");

        Assert.ThrowsExactly<InvalidCipherTextException>(() => _ = DecryptOaepOffTpmWithHashes(key.Key, ciphertext, label, TpmAlgIdConstants.TPM_ALG_SHA384, TpmAlgIdConstants.TPM_ALG_SHA256));
        Assert.ThrowsExactly<InvalidCipherTextException>(() => _ = DecryptOaepOffTpmWithHashes(key.Key, ciphertext, label, TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_SHA256));
    }

    /// <summary>
    /// Table 42's mirror cell: a NULL-scheme key defers the hash choice to <c>inScheme</c> entirely, so
    /// <c>inScheme</c> OAEP(SHA-384) drives both lhash and MGF1 with SHA-384 exactly as a key-scheme OAEP(SHA-384)
    /// cell would — the independent oracle recovers the plaintext with SHA-384 for both and fails when MGF1 is
    /// instead driven with SHA-256.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1, Table 42</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptNullSchemeKeyHonorsInSchemeOaepHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptNullSchemeKeyHonorsInSchemeOaepHash), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        byte[] plaintext = "The mirror cell defers the hash choice to inScheme."u8.ToArray();
        byte[] label = "TEST\0"u8.ToArray();

        using LoadExternalResponse loaded = await LoadRsaAsync(
            tpm, registry, pool, TpmiRhHierarchy.Null, ExternalDecryptAttributes, TpmtRsaScheme.Null, key.Modulus, key.P).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, loaded.ObjectHandle.Value, plaintext, TpmtRsaDecrypt.Oaep(TpmAlgIdConstants.TPM_ALG_SHA384), label);
        Assert.IsTrue(encrypted.IsSuccess, $"TPM2_RSA_Encrypt() under inScheme OAEP(SHA-384) on a NULL-scheme key must succeed: '{encrypted.ResponseCode}'.");
        using RsaEncryptResponse encryptedResponse = encrypted.Value;
        byte[] ciphertext = encryptedResponse.OutData.Buffer.ToArray();

        byte[] recovered = DecryptOaepOffTpmWithHashes(key.Key, ciphertext, label, TpmAlgIdConstants.TPM_ALG_SHA384, TpmAlgIdConstants.TPM_ALG_SHA384);
        Assert.IsTrue(recovered.AsSpan().SequenceEqual(plaintext), "SHA-384 for both lhash and MGF1 must recover exactly what the TPM encrypted.");

        Assert.ThrowsExactly<InvalidCipherTextException>(() => _ = DecryptOaepOffTpmWithHashes(key.Key, ciphertext, label, TpmAlgIdConstants.TPM_ALG_SHA384, TpmAlgIdConstants.TPM_ALG_SHA256));
    }

    /// <summary>
    /// "TPM_ALG_NULL ... the TPM will treat message as an unsigned integer and perform a modular exponentiation
    /// of message using the public exponent": the raw scheme's ciphertext equals <c>m^e mod n</c>, computed
    /// off-TPM byte-exact and <c>k</c>-wide, for a message carrying leading zero octets and a message narrower
    /// than <c>k</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// </summary>
    /// <param name="isMessageNarrowerThanK">Whether the message is trimmed narrower than the modulus width rather than merely carrying leading zeros.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RsaEncryptNullSchemeCiphertextMatchesModPowByteExact(bool isMessageNarrowerThanK)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptNullSchemeCiphertextMatchesModPowByteExact)}-{isMessageNarrowerThanK}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null).ConfigureAwait(false);
        byte[] modulus = decryptKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();

        byte[] message = isMessageNarrowerThanK
            ? [0x2A, 0x2B, 0x2C]
            : BuildLeadingZeroPaddedValue(modulus.Length, leadingZeros: 5);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, message, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.IsTrue(encrypted.IsSuccess, $"TPM2_RSA_Encrypt() under the raw scheme must succeed: '{encrypted.ResponseCode}'.");
        using RsaEncryptResponse encryptedResponse = encrypted.Value;

        byte[] expected = ModPowRaw(message, TpmsRsaParms.DefaultExponent, modulus, modulus.Length);
        Assert.IsTrue(encryptedResponse.OutData.Buffer.SequenceEqual(expected), "The raw scheme's ciphertext must equal m^e mod n, k octets wide.");
    }

    /// <summary>
    /// Table 42's nine padding-scheme-selection cells over a <c>TPM2_CreatePrimary()</c>'d unrestricted decrypt
    /// key: a SUCCESS cell's ciphertext is <c>k</c> octets that the TPM itself decrypts back through
    /// <c>TPM2_RSA_Decrypt()</c> under the matching scheme; a conflicting cell (RSAES key with OAEP inScheme, or
    /// the reverse) answers <c>TPM_RC_SCHEME</c>. The raw (NULL, NULL) cell's own decryption recovers the
    /// message left-padded to the modulus width rather than the original octets, per "The returned value may
    /// include leading octets zeros so that it is the same size as the public modulus"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.3.1</see>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1, Table 42</see>.
    /// </summary>
    /// <param name="keySchemeSelector">The key's own scheme selector.</param>
    /// <param name="inSchemeSelector">The command's <c>inScheme</c> selector.</param>
    /// <param name="isSchemeConflict">Whether Table 42 names this cell an error.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, false)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_RSAES, false)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_OAEP, false)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSAES, TpmAlgIdConstants.TPM_ALG_NULL, false)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSAES, TpmAlgIdConstants.TPM_ALG_RSAES, false)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSAES, TpmAlgIdConstants.TPM_ALG_OAEP, true)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_NULL, false)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_RSAES, true)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_OAEP, false)]
    public async Task RsaEncryptTable42PaddingSchemeSelectionCellsAreHonored(TpmAlgIdConstants keySchemeSelector, TpmAlgIdConstants inSchemeSelector, bool isSchemeConflict)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptTable42PaddingSchemeSelectionCellsAreHonored)}-{keySchemeSelector}-{inSchemeSelector}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtRsaScheme keyScheme = ToKeyScheme(keySchemeSelector);
        TpmtRsaDecrypt inScheme = ToInScheme(inSchemeSelector);
        byte[] message = "Table 42 message"u8.ToArray();

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, keyScheme).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, message, inScheme, ReadOnlyMemory<byte>.Empty);

        if(isSchemeConflict)
        {
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 1), encrypted.ResponseCode, $"Key scheme {keySchemeSelector} with inScheme {inSchemeSelector} is Table 42's error cell.");

            return;
        }

        Assert.IsTrue(encrypted.IsSuccess, $"Key scheme {keySchemeSelector} with inScheme {inSchemeSelector} must succeed: '{encrypted.ResponseCode}'.");
        using RsaEncryptResponse encryptedResponse = encrypted.Value;
        Assert.HasCount(ModulusOctets, encryptedResponse.OutData.Buffer.ToArray(), "Every scheme returns exactly k octets.");

        TpmResult<RsaDecryptResponse> decrypted = await DecryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, encryptedResponse.OutData.Buffer.ToArray(), inScheme, ReadOnlyMemory<byte>.Empty);
        Assert.IsTrue(decrypted.IsSuccess, $"TPM2_RSA_Decrypt() under the same selection must recover the plaintext: '{decrypted.ResponseCode}'.");
        using RsaDecryptResponse decryptedResponse = decrypted.Value;

        bool isRawScheme = keySchemeSelector == TpmAlgIdConstants.TPM_ALG_NULL && inSchemeSelector == TpmAlgIdConstants.TPM_ALG_NULL;
        byte[] expectedMessage = isRawScheme ? PadLeft(message, ModulusOctets) : message;
        Assert.IsTrue(decryptedResponse.Message.Buffer.SequenceEqual(expectedMessage), "The TPM's own decryption must recover exactly what it encrypted.");
    }

    /// <summary>
    /// A signing-scheme key's selector has no <see cref="TpmiAlgRsaDecrypt"/> counterpart: "the padding scheme is
    /// supported" is Table 42's own second gate, refused with <c>TPM_RC_SCHEME</c> whether <c>inScheme</c> defers
    /// (NULL) or names a conflicting scheme (OAEP).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// </summary>
    /// <param name="inSchemeSelector">The command's <c>inScheme</c> selector.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_OAEP)]
    public async Task RsaEncryptSigningSchemeKeyIsRefusedWithSchemeRegardlessOfInScheme(TpmAlgIdConstants inSchemeSelector)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptSigningSchemeKeyIsRefusedWithSchemeRegardlessOfInScheme)}-{inSchemeSelector}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        TpmtRsaDecrypt inScheme = ToInScheme(inSchemeSelector);

        using CreatePrimaryResponse signingKey = await CreateRsaSigningKeyAsync(tpm, registry, pool, TpmtRsaScheme.Rsassa(NameAlg)).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, signingKey.ObjectHandle.Value, "x"u8.ToArray(), inScheme, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 1), encrypted.ResponseCode, "An RSASSA key admits no decryption scheme (Table 42's own property check).");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// Table 192's own <c>#TPM_RC_VALUE</c>: an <c>inScheme</c> selector outside {RSAES, OAEP, NULL} — a signing
    /// selector or an unassigned one — is refused at parse, before any handle is even resolved.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.4, Table 192</see>.
    /// </summary>
    /// <param name="badSelector">The unadmitted selector.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSASSA)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSAPSS)]
    [DataRow((TpmAlgIdConstants)UnknownSchemeSelector)]
    public async Task RsaEncryptInSchemeSelectorOutsideTheAdmittedSetIsRefusedWithValueAtParse(TpmAlgIdConstants badSelector)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptInSchemeSelectorOutsideTheAdmittedSetIsRefusedWithValueAtParse)}-{badSelector}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        TpmtRsaDecrypt inScheme = new() { Scheme = TpmiAlgRsaDecrypt.FromValue(badSelector) };

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST, "x"u8.ToArray(), inScheme, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 1), encrypted.ResponseCode,
            "Table 44: inScheme is TPM2_RSA_Encrypt()'s second parameter (index 1); an unadmitted selector is refused with parameter-encoded TPM_RC_VALUE at parse, before the (unloaded) handle is ever resolved.");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// Table 173/77: an OAEP <c>inScheme</c> naming a hash algorithm of <c>TPM_ALG_NULL</c> (no <c>+</c> on
    /// <c>TPMS_SCHEME_HASH.hashAlg</c>) or one outside the implemented profile is refused with
    /// <c>TPM_RC_HASH</c> at parse.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.17, Table 173</see>.
    /// </summary>
    /// <param name="hashAlg">The OAEP hash algorithm under test.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SM3_256)]
    public async Task RsaEncryptInSchemeOaepHashOutsideTheProfileIsRefusedWithHashAtParse(TpmAlgIdConstants hashAlg)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptInSchemeOaepHashOutsideTheProfileIsRefusedWithHashAtParse)}-{hashAlg}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST, "x"u8.ToArray(), TpmtRsaDecrypt.Oaep(hashAlg), ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), encrypted.ResponseCode,
            "Table 44: inScheme is TPM2_RSA_Encrypt()'s second parameter (index 1); a NULL or unimplemented OAEP hash is parameter-encoded TPM_RC_HASH at parse.");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// "the TPM shall return TPM_RC_VALUE if the last octet in label is not zero": the rule holds for every
    /// selected scheme, since it is judged before Table 42's own selection runs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// </summary>
    /// <param name="inSchemeSelector">The scheme selected for the malformed label.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSAES)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_OAEP)]
    public async Task RsaEncryptLabelWithoutATerminatingZeroIsRefusedWithValue(TpmAlgIdConstants inSchemeSelector)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptLabelWithoutATerminatingZeroIsRefusedWithValue)}-{inSchemeSelector}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        TpmtRsaDecrypt inScheme = ToInScheme(inSchemeSelector);

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, "x"u8.ToArray(), inScheme, new byte[] { 0x01, 0x02 });
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 2), encrypted.ResponseCode, "A non-empty label whose last octet is not zero is TPM_RC_VALUE regardless of the selected scheme.");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// OAEP's message-size limit (Table 43): <c>mLen &gt; k − 2·hLen − 2</c> is <c>TPM_RC_VALUE</c>, and
    /// <c>mLen == k − 2·hLen − 2</c> succeeds, for SHA-256 and SHA-512.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1, Table 43</see>.
    /// </summary>
    /// <param name="hashAlg">The OAEP hash algorithm.</param>
    /// <param name="digestSize">The hash's digest width.</param>
    /// <param name="isAtTheLimit">Whether the message is exactly at the limit (success) or one octet over (refused).</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA256, Sha256DigestSize, false)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA256, Sha256DigestSize, true)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA512, Sha512DigestSize, false)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA512, Sha512DigestSize, true)]
    public async Task RsaEncryptOaepMessageAtOrOverTheSizeLimitIsJudged(TpmAlgIdConstants hashAlg, int digestSize, bool isAtTheLimit)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptOaepMessageAtOrOverTheSizeLimitIsJudged)}-{hashAlg}-{isAtTheLimit}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Oaep(hashAlg)).ConfigureAwait(false);
        int limit = ModulusOctets - (2 * digestSize) - 2;
        byte[] message = new byte[isAtTheLimit ? limit : limit + 1];

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, message, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);

        if(isAtTheLimit)
        {
            Assert.IsTrue(encrypted.IsSuccess, $"A message of exactly k - 2hLen - 2 octets must succeed under OAEP({hashAlg}): '{encrypted.ResponseCode}'.");
            encrypted.Value.Dispose();
        }
        else
        {
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), encrypted.ResponseCode, $"message is TPM2_RSA_Encrypt()'s first parameter (Table 44, index 0); one octet over k - 2hLen - 2 under OAEP({hashAlg}) must be parameter-encoded TPM_RC_VALUE.");
        }
    }

    /// <summary>
    /// RSAES's message-size limit (Table 43): <c>mLen &gt; k − 11</c> is <c>TPM_RC_VALUE</c>, and
    /// <c>mLen == k − 11</c> succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1, Table 43</see>.
    /// </summary>
    /// <param name="isAtTheLimit">Whether the message is exactly at the limit (success) or one octet over (refused).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RsaEncryptRsaEsMessageAtOrOverTheSizeLimitIsJudged(bool isAtTheLimit)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptRsaEsMessageAtOrOverTheSizeLimitIsJudged)}-{isAtTheLimit}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs).ConfigureAwait(false);
        int limit = ModulusOctets - 11;
        byte[] message = new byte[isAtTheLimit ? limit : limit + 1];

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, message, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);

        if(isAtTheLimit)
        {
            Assert.IsTrue(encrypted.IsSuccess, $"A message of exactly k - 11 octets must succeed under RSAES: '{encrypted.ResponseCode}'.");
            encrypted.Value.Dispose();
        }
        else
        {
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), encrypted.ResponseCode, "message is TPM2_RSA_Encrypt()'s first parameter (Table 44, index 0); one octet over k - 11 under RSAES must be parameter-encoded TPM_RC_VALUE.");
        }
    }

    /// <summary>
    /// The raw scheme's width and value rules: a <c>k+1</c>-octet message with a non-zero leading octet is
    /// <c>TPM_RC_VALUE</c> (the trimmed width still exceeds <c>k</c>); a <c>k+1</c>-octet message with a zero
    /// lead succeeds (the leading zero is stripped); the value <c>n</c> itself is <c>TPM_RC_VALUE</c> ("The
    /// numeric value of the message must be less than the numeric value of the public modulus"); <c>n − 1</c>
    /// succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1, Table 43</see>.
    /// </summary>
    /// <param name="testCase">The width/value case under test.</param>
    [TestMethod]
    [DataRow(NullSchemeCase.OverWidthNonZeroLead)]
    [DataRow(NullSchemeCase.OverWidthZeroLead)]
    [DataRow(NullSchemeCase.EqualToModulus)]
    [DataRow(NullSchemeCase.OneBelowModulus)]
    public async Task RsaEncryptNullSchemeWidthAndValueRulesAreJudged(NullSchemeCase testCase)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptNullSchemeWidthAndValueRulesAreJudged)}-{testCase}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null).ConfigureAwait(false);
        byte[] modulus = decryptKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();

        byte[] message = testCase switch
        {
            NullSchemeCase.OverWidthNonZeroLead => BuildOverWidthValue(modulus.Length, leadingOctet: 0x01),
            NullSchemeCase.OverWidthZeroLead => BuildOverWidthValue(modulus.Length, leadingOctet: 0x00),
            NullSchemeCase.EqualToModulus => modulus,
            NullSchemeCase.OneBelowModulus => DecrementBigEndian(modulus),
            _ => throw new ArgumentOutOfRangeException(nameof(testCase))
        };

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, message, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);

        bool isSuccessExpected = testCase is NullSchemeCase.OverWidthZeroLead or NullSchemeCase.OneBelowModulus;
        if(isSuccessExpected)
        {
            Assert.IsTrue(encrypted.IsSuccess, $"{testCase} must succeed: '{encrypted.ResponseCode}'.");
            encrypted.Value.Dispose();
        }
        else
        {
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), encrypted.ResponseCode, $"message is TPM2_RSA_Encrypt()'s first parameter (Table 44, index 0); {testCase} must be parameter-encoded TPM_RC_VALUE.");
        }
    }

    /// <summary>The width/value cases <see cref="RsaEncryptNullSchemeWidthAndValueRulesAreJudged"/> drives.</summary>
    internal enum NullSchemeCase
    {
        /// <summary>A <c>k+1</c>-octet message whose leading octet is non-zero: the trimmed width still exceeds <c>k</c>.</summary>
        OverWidthNonZeroLead,

        /// <summary>A <c>k+1</c>-octet message whose leading octet is zero: stripping it leaves exactly <c>k</c> octets.</summary>
        OverWidthZeroLead,

        /// <summary>The message equals the public modulus <c>n</c> exactly.</summary>
        EqualToModulus,

        /// <summary>The message equals <c>n − 1</c>, the largest value strictly below the modulus.</summary>
        OneBelowModulus
    }

    /// <summary>
    /// An empty message is admitted by every scheme: OAEP and RSAES pad it, and the TPM itself decrypts the
    /// result back to an empty octet string; the raw scheme answers <c>k</c> zero octets (<c>0^e mod n = 0</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// </summary>
    /// <param name="schemeSelector">The scheme under test.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_OAEP)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSAES)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL)]
    public async Task RsaEncryptEmptyMessageIsAdmittedByEveryScheme(TpmAlgIdConstants schemeSelector)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptEmptyMessageIsAdmittedByEveryScheme)}-{schemeSelector}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtRsaScheme keyScheme = ToKeyScheme(schemeSelector);
        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, keyScheme).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.IsTrue(encrypted.IsSuccess, $"An empty message must be admitted by {schemeSelector}: '{encrypted.ResponseCode}'.");
        using RsaEncryptResponse encryptedResponse = encrypted.Value;

        if(schemeSelector == TpmAlgIdConstants.TPM_ALG_NULL)
        {
            Assert.IsTrue(encryptedResponse.OutData.Buffer.SequenceEqual(new byte[ModulusOctets]), "The raw scheme's empty-message ciphertext is k zero octets (0 raised to any power is 0).");

            return;
        }

        TpmResult<RsaDecryptResponse> decrypted = await DecryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, encryptedResponse.OutData.Buffer.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.IsTrue(decrypted.IsSuccess, $"TPM2_RSA_Decrypt() must recover the empty message: '{decrypted.ResponseCode}'.");
        using RsaDecryptResponse decryptedResponse = decrypted.Value;
        Assert.AreEqual(0, decryptedResponse.Message.Size, "The recovered plaintext must be empty.");
    }

    /// <summary>
    /// "The key referenced by keyHandle is required to be an RSA key": a loaded ECC key, a loaded HMAC
    /// (KEYEDHASH) key, and an open hash sequence context are each refused with <c>TPM_RC_KEY</c> naming
    /// keyHandle, handle 1 of Table 44 — none of them runs an authorization ladder first, since this command
    /// carries none (Auth Index: None).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// </summary>
    /// <param name="kind">The non-RSA loaded kind under test.</param>
    [TestMethod]
    [DataRow(NonRsaKind.Ecc)]
    [DataRow(NonRsaKind.Hmac)]
    [DataRow(NonRsaKind.HashSequence)]
    public async Task RsaEncryptNonRsaLoadedKindsAreRefusedWithKey(NonRsaKind kind)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptNonRsaLoadedKindsAreRefusedWithKey)}-{kind}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint handle = kind switch
        {
            NonRsaKind.Ecc => (await CreateEccSigningKeyAsync(tpm, registry, pool).ConfigureAwait(false)).ObjectHandle.Value,
            NonRsaKind.Hmac => (await LoadHmacKeyAsync(tpm, registry, pool).ConfigureAwait(false)).ObjectHandle.Value,
            NonRsaKind.HashSequence => (await StartHashSequenceAsync(tpm, registry, pool).ConfigureAwait(false)).Value,
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, handle, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), encrypted.ResponseCode, $"{kind} is never an RSA key.");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>The non-RSA loaded kinds <see cref="RsaEncryptNonRsaLoadedKindsAreRefusedWithKey"/> drives.</summary>
    internal enum NonRsaKind
    {
        /// <summary>A loaded ECC signing key.</summary>
        Ecc,

        /// <summary>A loaded HMAC (KEYEDHASH) key.</summary>
        Hmac,

        /// <summary>An open hash sequence context.</summary>
        HashSequence
    }

    /// <summary>
    /// An unloaded transient-range handle answers <c>TPM_RC_REFERENCE_H0</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.4, step 2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptUnloadedHandleIsRefusedWithReferenceH0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptUnloadedHandleIsRefusedWithReferenceH0), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, encrypted.ResponseCode, "An untouched transient handle names no loaded object.");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// The persistent-range complement of <see cref="RsaEncryptUnloadedHandleIsRefusedWithReferenceH0"/>: an
    /// unallocated persistent handle answers <c>TPM_RC_HANDLE</c> naming keyHandle, handle 1 of Table 44 (clause
    /// 5.4, step 2.2).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.4, step 2.2</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptUnallocatedPersistentHandleIsRefusedWithHandle()
    {
        const uint UnallocatedPersistentHandle = 0x8100_9999u;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptUnallocatedPersistentHandleIsRefusedWithHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, UnallocatedPersistentHandle, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), encrypted.ResponseCode, "An unallocated persistent handle names no evicted object.");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// Table 49's admitted set is the transient and persistent ranges only: <c>TPM_RH_NULL</c> is neither, so it
    /// is refused with <c>TPM_RC_VALUE</c> naming keyHandle, handle 1 of Table 44, judged before any resolution
    /// is attempted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.3, Table 49</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptTpmRhNullHandleIsRefusedWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptTpmRhNullHandleIsRefusedWithValue), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, (uint)TpmRh.TPM_RH_NULL, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), encrypted.ResponseCode,
            "Table 44: keyHandle is TPM2_RSA_Encrypt()'s sole handle (index 0); TPM_RH_NULL is outside the transient/persistent ranges (Table 49 carries no '+').");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// "The TPM shall successfully unmarshal the number of handles required by the command and validate that the
    /// value of the handle is consistent with the command syntax. If not, the TPM shall return TPM_RC_VALUE." —
    /// an NV-index, PCR or session-range handle is refused the same <c>TPM_RC_VALUE</c>, naming keyHandle, handle
    /// 1 of Table 44, as <see cref="RsaEncryptTpmRhNullHandleIsRefusedWithValue"/>'s permanent-range handle, at
    /// parse before any resolution is attempted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.4, step 1; Part 2, clause 9.3, Table 49</see>.
    /// </summary>
    [TestMethod]
    [DataRow(0x0100_0001u, DisplayName = "NV Index")]
    [DataRow(0x0000_0001u, DisplayName = "PCR")]
    [DataRow(0x0200_0001u, DisplayName = "HMAC session")]
    public async Task RsaEncryptWithAMistypedHandleIsRefusedWithValue(uint mistypedHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptWithAMistypedHandleIsRefusedWithValue), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, mistypedHandle, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), encrypted.ResponseCode,
            $"Table 44: keyHandle is TPM2_RSA_Encrypt()'s sole handle (index 0); a handle of type 0x{(mistypedHandle >> 24):X2} is outside the transient/persistent ranges (Table 49 carries no '+').");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// A persistent decrypt key encrypts successfully; once its hierarchy is disabled, <c>TPM2_EvictControl()</c>
    /// left the object in place but the persistent-handle resolution refuses it — <c>TPM_RC_HANDLE</c>, not an
    /// eviction (TPM 2.0 Library Part 3, clause 5.4, Handle Area Validation).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 24.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptPersistentKeySucceedsThenDisabledHierarchyIsRefusedWithHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptPersistentKeySucceedsThenDisabledHierarchyIsRefusedWithHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null).ConfigureAwait(false);
        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl() must persist the decrypt key: '{persistResult.ResponseCode}'.");

        TpmResult<RsaEncryptResponse> encryptedWhileEnabled = await EncryptAsync(
            tpm, registry, pool, PersistentHandle, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.IsTrue(encryptedWhileEnabled.IsSuccess, $"The persistent key must encrypt: '{encryptedWhileEnabled.ResponseCode}'.");
        encryptedWhileEnabled.Value.Dispose();

        await SetOwnerHierarchyEnabledAsync(tpm, registry, pool, TpmiYesNo.No).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encryptedWhileDisabled = await EncryptAsync(
            tpm, registry, pool, PersistentHandle, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), encryptedWhileDisabled.ResponseCode, "The disabled hierarchy's persistent object resolves to nothing (Part 3, clause 24.2.1).");
        DisposeIfSuccess(encryptedWhileDisabled);
    }

    /// <summary>
    /// "Because only the public portion of the key needs to be loaded for this command, the caller can
    /// manipulate the attributes of the key in any way desired. As a result, the TPM shall not check the
    /// consistency of the attributes. The only property checking is that the key is an RSA key and that the
    /// padding scheme is supported.": a public-only external UNRESTRICTED SIGNING key — no decrypt attribute at
    /// all — still encrypts under <c>inScheme</c> OAEP, and the framework twin — retained off-TPM — decrypts the
    /// result.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptSigningKeyWithoutTheDecryptAttributeEncryptsUnderOaep()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptSigningKeyWithoutTheDecryptAttributeEncryptsUnderOaep), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        byte[] plaintext = "Attributes are not checked here."u8.ToArray();

        using LoadExternalResponse loaded = await LoadRsaAsync(
            tpm, registry, pool, TpmiRhHierarchy.Owner, ExternalSigningAttributes, TpmtRsaScheme.Null, key.Modulus).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, loaded.ObjectHandle.Value, plaintext, TpmtRsaDecrypt.Oaep(NameAlg), ReadOnlyMemory<byte>.Empty);
        Assert.IsTrue(encrypted.IsSuccess, $"A public-only signing key without the decrypt attribute must still encrypt: '{encrypted.ResponseCode}'.");
        using RsaEncryptResponse encryptedResponse = encrypted.Value;

        byte[] recovered = DecryptOaepOffTpm(key.Key, encryptedResponse.OutData.Buffer, ReadOnlySpan<byte>.Empty, NameAlg);
        Assert.IsTrue(recovered.AsSpan().SequenceEqual(plaintext), "The framework twin must recover exactly what the TPM encrypted.");
    }

    /// <summary>
    /// The standard RSA endorsement key (restricted, scheme NULL) encrypts under every scheme <c>inScheme</c>
    /// selects — Part 3's Note again: no attribute is checked, so a restricted decrypt key is admitted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// </summary>
    /// <param name="schemeSelector">The scheme <c>inScheme</c> selects.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_OAEP)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSAES)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL)]
    public async Task RsaEncryptEndorsementKeyEncryptsUnderEveryScheme(TpmAlgIdConstants schemeSelector)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptEndorsementKeyEncryptsUnderEveryScheme)}-{schemeSelector}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        TpmtRsaDecrypt inScheme = ToInScheme(schemeSelector);

        using CreatePrimaryResponse ek = await CreateRsaEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, ek.ObjectHandle.Value, "The EK encrypts."u8.ToArray(), inScheme, ReadOnlyMemory<byte>.Empty);
        Assert.IsTrue(encrypted.IsSuccess, $"The EK must encrypt under {schemeSelector}: '{encrypted.ResponseCode}'.");
        using RsaEncryptResponse encryptedResponse = encrypted.Value;
        Assert.HasCount(ModulusOctets, encryptedResponse.OutData.Buffer.ToArray(), "Every scheme returns exactly k octets.");
    }

    /// <summary>
    /// Wire-shape refusals judged at parse, before any handle is resolved: a <c>message</c> wider than
    /// <c>MAX_RSA_KEY_BYTES</c> is parameter-encoded <c>TPM_RC_SIZE</c>; a <c>label</c> wider than
    /// <c>TPM2B_DATA</c>'s bound (66 octets) is parameter-encoded <c>TPM_RC_SIZE</c>; an octet trailing a
    /// well-formed frame is <c>TPM_RC_SIZE</c>, parameter-encoded to the same index (clause 5.8.2, Unmarshaling Errors, the reference's own
    /// generic trailing-octets rule, not a property of one field).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2, Table 44; Part 2, clause 6.6.2, Table 15</see>.
    /// </summary>
    /// <param name="shape">The malformation applied.</param>
    [TestMethod]
    [DataRow(WireShape.OverWideMessage)]
    [DataRow(WireShape.OverWideLabel)]
    [DataRow(WireShape.TrailingOctet)]
    public async Task RsaEncryptWireShapeViolationsAreRefusedWithSizeAtParse(WireShape shape)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptWireShapeViolationsAreRefusedWithSizeAtParse)}-{shape}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null).ConfigureAwait(false);

        var body = new List<byte>();
        AppendUInt32(body, decryptKey.ObjectHandle.Value);

        switch(shape)
        {
            case WireShape.OverWideMessage:
            {
                AppendTpm2b(body, new byte[Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1]);
                AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_NULL);
                AppendUInt16(body, 0);
                break;
            }
            case WireShape.OverWideLabel:
            {
                AppendTpm2b(body, "x"u8);
                AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_NULL);
                byte[] overWideLabel = new byte[Tpm2bData.MaxSize + 1];
                AppendTpm2b(body, overWideLabel);
                break;
            }
            case WireShape.TrailingOctet:
            {
                AppendTpm2b(body, "x"u8);
                AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_NULL);
                AppendUInt16(body, 0);
                body.Add(0xA5);
                break;
            }
            default:
            {
                throw new ArgumentOutOfRangeException(nameof(shape));
            }
        }

        TpmRcConstants responseCode = await SubmitFramedAsync(simulator, pool, [.. body]).ConfigureAwait(false);

        //message (Table 44's first parameter, index 0) is also reached, over already-decrypted plaintext, by the
        //shared decrypt-session continuation; the continuation's already-designated guard (TpmRcExtensions.
        //IsDesignated) keeps a designated code from ever picking up a second, session designation, so message's
        //own over-bound answer is parameter-encoded exactly as label's is. Only the frame-level trailing-octet
        //check (TrailingOctet) stays bare, since it is a property of the whole area, not of one field.
        TpmRcConstants expected = shape switch
        {
            WireShape.OverWideMessage => HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0),
            WireShape.OverWideLabel => HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 2),
            _ => TpmRcConstants.TPM_RC_SIZE
        };

        Assert.AreEqual(expected, responseCode, $"{shape} must be {expected}.");
    }

    /// <summary>The wire-shape malformations <see cref="RsaEncryptWireShapeViolationsAreRefusedWithSizeAtParse"/> drives.</summary>
    internal enum WireShape
    {
        /// <summary>A <c>message</c> one octet wider than <c>MAX_RSA_KEY_BYTES</c> (512).</summary>
        OverWideMessage,

        /// <summary>A <c>label</c> one octet wider than <c>TPM2B_DATA</c>'s bound (66).</summary>
        OverWideLabel,

        /// <summary>An octet after an otherwise well-formed frame.</summary>
        TrailingOctet
    }

    /// <summary>
    /// "TPM_RC_INITIALIZE": a command submitted before <c>TPM2_Startup()</c> is refused before any of this
    /// command's own rules run.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.2</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptPreStartupIsRefusedWithInitialize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator(
            $"tpm-in-house-rsa-encrypt-{nameof(RsaEncryptPreStartupIsRefusedWithInitialize)}", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, encrypted.ResponseCode, "Before TPM2_Startup() every command is TPM_RC_INITIALIZE (Part 1, clause 12.2).");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// "TPM_RC_FAILURE": once a failed self-test has entered Failure Mode, every command but the few Failure
    /// Mode admits is refused before its own rules run.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptFailureModeIsRefusedWithFailure()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator(
            $"tpm-in-house-rsa-encrypt-{nameof(RsaEncryptFailureModeIsRefusedWithFailure)}",selfTest: TpmSelfTestBehavior.Fails, rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmRcConstants selfTestCode = await SubmitSelfTestAsync(simulator, pool).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, selfTestCode, "A failing self-test enters Failure Mode.");

        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, encrypted.ResponseCode, "In Failure Mode TPM2_RSA_Encrypt() is TPM_RC_FAILURE (Part 1, clause 12.3).");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// A simulator constructed without an RSA signing backend answers <c>TPM_RC_COMMAND_CODE</c> at parse — the
    /// same backend-absence gate <c>TPM2_CreatePrimary()</c>'s RSA arm uses.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptSimulatorWithNoRsaBackendIsRefusedWithCommandCode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator(
            $"tpm-in-house-rsa-encrypt-{nameof(RsaEncryptSimulatorWithNoRsaBackendIsRefusedWithCommandCode)}", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: null, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(TpmRcConstants.TPM_RC_COMMAND_CODE, encrypted.ResponseCode, "With no RSA backend supplied, the command is unimplemented (TPM_RC_COMMAND_CODE).");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>
    /// "a parameter does not have one of its allowed values": every internal encryption failure — a backend
    /// that raises instead of returning ciphertext, or one that answers ciphertext octets not the modulus width
    /// every scheme must return — collapses to the same <c>TPM_RC_VALUE</c>, never an unhandled exception
    /// escaping the command.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2.1</see>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 4.15, Table 2</see>.
    /// </summary>
    /// <param name="failureCase">Which delegate misbehaves and how.</param>
    [TestMethod]
    [DataRow(RsaEncryptBackendFailureCase.OaepEncryptThrows)]
    [DataRow(RsaEncryptBackendFailureCase.RawEncryptWrongWidth)]
    [DataRow(RsaEncryptBackendFailureCase.RsaesEncryptWrongWidth)]
    public async Task RsaEncryptBackendFailuresAreRefusedWithValue(RsaEncryptBackendFailureCase failureCase)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmRsaSigningBackend backend = BuildFailingBackend(failureCase);
        using var simulator = new TpmSimulator(
            $"tpm-in-house-rsa-encrypt-{nameof(RsaEncryptBackendFailuresAreRefusedWithValue)}-{failureCase}", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: backend, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtRsaScheme keyScheme = failureCase switch
        {
            RsaEncryptBackendFailureCase.OaepEncryptThrows => TpmtRsaScheme.Oaep(NameAlg),
            RsaEncryptBackendFailureCase.RawEncryptWrongWidth => TpmtRsaScheme.Null,
            RsaEncryptBackendFailureCase.RsaesEncryptWrongWidth => TpmtRsaScheme.RsaEs,
            _ => throw new ArgumentOutOfRangeException(nameof(failureCase))
        };
        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, keyScheme).ConfigureAwait(false);

        TpmResult<RsaEncryptResponse> encrypted = await EncryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, encrypted.ResponseCode, $"{failureCase} must collapse to TPM_RC_VALUE.");
        DisposeIfSuccess(encrypted);
    }

    /// <summary>The backend misbehaviors <see cref="RsaEncryptBackendFailuresAreRefusedWithValue"/> drives.</summary>
    internal enum RsaEncryptBackendFailureCase
    {
        /// <summary>The OAEP-encrypt delegate raises instead of returning ciphertext.</summary>
        OaepEncryptThrows,

        /// <summary>The raw (RSAEP) encrypt delegate answers one octet narrower than the modulus.</summary>
        RawEncryptWrongWidth,

        /// <summary>The RSAES-encrypt delegate answers one octet wider than the modulus.</summary>
        RsaesEncryptWrongWidth
    }

    /// <summary>Builds a signing backend whose single RSA-encrypt delegate named by <paramref name="failureCase"/> misbehaves, every other delegate left as <see cref="MicrosoftTpmRsaSigningBackend.Create"/> composes it.</summary>
    /// <param name="failureCase">Which delegate misbehaves and how.</param>
    /// <returns>The backend to inject into the simulator under test.</returns>
    private static TpmRsaSigningBackend BuildFailingBackend(RsaEncryptBackendFailureCase failureCase) => failureCase switch
    {
        RsaEncryptBackendFailureCase.OaepEncryptThrows => MicrosoftTpmRsaSigningBackend.Create() with { EncryptOaep = ThrowingEncryptOaepAsync },
        RsaEncryptBackendFailureCase.RawEncryptWrongWidth => MicrosoftTpmRsaSigningBackend.Create() with { EncryptRaw = OneOctetNarrowerRawAsync },
        RsaEncryptBackendFailureCase.RsaesEncryptWrongWidth => MicrosoftTpmRsaSigningBackend.Create() with { EncryptRsaes = OneOctetWiderRsaesAsync },
        _ => throw new ArgumentOutOfRangeException(nameof(failureCase))
    };

    /// <summary>A <see cref="TpmRsaOaepEncryptDelegate"/> modelling a provider fault: it raises instead of returning ciphertext, the "any backend throw" case the effect's own catch collapses to <c>TPM_RC_VALUE</c>.</summary>
    /// <param name="modulus">Unused.</param>
    /// <param name="exponent">Unused.</param>
    /// <param name="plaintext">Unused.</param>
    /// <param name="label">Unused.</param>
    /// <param name="lhashAlg">Unused.</param>
    /// <param name="mgfHashAlg">Unused.</param>
    /// <param name="pool">Unused.</param>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>Never returns.</returns>
    private static ValueTask<IMemoryOwner<byte>> ThrowingEncryptOaepAsync(
        ReadOnlyMemory<byte> modulus, uint exponent, ReadOnlyMemory<byte> plaintext, ReadOnlyMemory<byte> label,
        TpmAlgIdConstants lhashAlg, TpmAlgIdConstants mgfHashAlg, BaseMemoryPool pool, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("Simulated RSA-OAEP encryption provider fault.");

    /// <summary>A <see cref="TpmRsaPublicOperationDelegate"/> answering exactly <c>k − 1</c> octets — narrower than the modulus width every scheme must return.</summary>
    /// <param name="modulus">The RSA public modulus; only its length is used.</param>
    /// <param name="exponent">Unused.</param>
    /// <param name="value">Unused.</param>
    /// <param name="pool">The memory pool backing the returned buffer.</param>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>An owner of exactly <c>modulus.Length - 1</c> octets.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned owner, which the simulator disposes.")]
    private static ValueTask<IMemoryOwner<byte>> OneOctetNarrowerRawAsync(
        ReadOnlyMemory<byte> modulus, uint exponent, ReadOnlyMemory<byte> value, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> owner = pool.Rent(modulus.Length - 1);
        owner.Memory.Span.Clear();

        return ValueTask.FromResult(owner);
    }

    /// <summary>A <see cref="TpmRsaEsEncryptDelegate"/> answering exactly <c>k + 1</c> octets — wider than the modulus width every scheme must return.</summary>
    /// <param name="modulus">The RSA public modulus; only its length is used.</param>
    /// <param name="exponent">Unused.</param>
    /// <param name="message">Unused.</param>
    /// <param name="pool">The memory pool backing the returned buffer.</param>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>An owner of exactly <c>modulus.Length + 1</c> octets.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned owner, which the simulator disposes.")]
    private static ValueTask<IMemoryOwner<byte>> OneOctetWiderRsaesAsync(
        ReadOnlyMemory<byte> modulus, uint exponent, ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> owner = pool.Rent(modulus.Length + 1);
        owner.Memory.Span.Clear();

        return ValueTask.FromResult(owner);
    }

    /// <summary>
    /// Pool hygiene across every refusal category and a success: a parse refusal (an over-wide message), a
    /// transition refusal (an unloaded handle), an effect refusal (the raw scheme's width rule), and a success
    /// each leave the pool with exactly the carriers outstanding before them.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptPoolBalanceAcrossEveryRefusalCategoryAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptPoolBalanceAcrossEveryRefusalCategoryAndASuccess), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null).ConfigureAwait(false);
        long baseline = trackingPool.OutstandingCount;

        var body = new List<byte>();
        AppendUInt32(body, decryptKey.ObjectHandle.Value);
        AppendTpm2b(body, new byte[Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1]);
        AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_NULL);
        AppendUInt16(body, 0);
        TpmRcConstants parseRefusal = await SubmitFramedAsync(simulator, pool, [.. body]).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), parseRefusal, "An over-wide message is refused at parse, parameter-encoded to message (Table 44, index 0).");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A parse refusal returns every carrier it rented.");

        TpmResult<RsaEncryptResponse> transitionRefusal = await EncryptAsync(
            tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST + 1, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        TpmRcConstants transitionRefusalCode = transitionRefusal.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : transitionRefusal.ResponseCode;
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, transitionRefusalCode, "An unloaded transient handle is refused at the transition (clause 5.4, step 2.1).");
        DisposeIfSuccess(transitionRefusal);
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A transition refusal returns every carrier it rented.");

        byte[] modulus = decryptKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] overWidth = BuildOverWidthValue(modulus.Length, leadingOctet: 0x01);
        TpmResult<RsaEncryptResponse> effectRefusal = await EncryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, overWidth, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        TpmRcConstants effectRefusalCode = effectRefusal.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : effectRefusal.ResponseCode;
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), effectRefusalCode, "message is TPM2_RSA_Encrypt()'s first parameter (Table 44, index 0); an over-width raw-scheme message is refused at the effect with parameter-encoded TPM_RC_VALUE.");
        DisposeIfSuccess(effectRefusal);
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "An effect refusal returns every carrier it rented.");

        TpmResult<RsaEncryptResponse> success = await EncryptAsync(
            tpm, registry, pool, decryptKey.ObjectHandle.Value, "x"u8.ToArray(), TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty);
        Assert.IsTrue(success.IsSuccess, $"The final call must succeed: '{success.ResponseCode}'.");
        success.Value.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A success releases every carrier once disposed.");
    }

    /// <summary>Disposes <paramref name="result"/>'s success value, when there is one — the response object a negative test never otherwise reads still owes its pooled carrier back on the rare implementation defect that lets it succeed.</summary>
    /// <typeparam name="T">The response type.</typeparam>
    /// <param name="result">The result to release.</param>
    private static void DisposeIfSuccess<T>(TpmResult<T> result)
        where T: IDisposable
    {
        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }
    }

    /// <summary>Maps a Table 42 scheme selector (NULL/RSAES/OAEP) to the key-side scheme, fixing OAEP's hash to SHA-256.</summary>
    /// <param name="selector">The scheme selector.</param>
    /// <returns>The key scheme.</returns>
    private static TpmtRsaScheme ToKeyScheme(TpmAlgIdConstants selector) => selector switch
    {
        TpmAlgIdConstants.TPM_ALG_NULL => TpmtRsaScheme.Null,
        TpmAlgIdConstants.TPM_ALG_RSAES => TpmtRsaScheme.RsaEs,
        TpmAlgIdConstants.TPM_ALG_OAEP => TpmtRsaScheme.Oaep(NameAlg),
        _ => throw new ArgumentOutOfRangeException(nameof(selector))
    };

    /// <summary>Maps a Table 42 scheme selector (NULL/RSAES/OAEP) to the command's <c>inScheme</c>, fixing OAEP's hash to SHA-256.</summary>
    /// <param name="selector">The scheme selector.</param>
    /// <returns>The <c>inScheme</c> value.</returns>
    private static TpmtRsaDecrypt ToInScheme(TpmAlgIdConstants selector) => selector switch
    {
        TpmAlgIdConstants.TPM_ALG_NULL => TpmtRsaDecrypt.Null,
        TpmAlgIdConstants.TPM_ALG_RSAES => TpmtRsaDecrypt.RsaEs,
        TpmAlgIdConstants.TPM_ALG_OAEP => TpmtRsaDecrypt.Oaep(NameAlg),
        _ => throw new ArgumentOutOfRangeException(nameof(selector))
    };

    /// <summary>Builds a <c>width</c>-octet big-endian value with the given number of leading zero octets, the rest a fixed non-zero pattern.</summary>
    /// <param name="width">The total octet width.</param>
    /// <param name="leadingZeros">How many leading octets are zero.</param>
    /// <returns>The value.</returns>
    private static byte[] BuildLeadingZeroPaddedValue(int width, int leadingZeros)
    {
        byte[] value = new byte[width];
        for(int index = leadingZeros; index < width; index++)
        {
            value[index] = 0x11;
        }

        return value;
    }

    /// <summary>Builds a <c>width + 1</c>-octet value whose leading octet is <paramref name="leadingOctet"/> and whose remaining octets are a fixed pattern well below the modulus.</summary>
    /// <param name="width">The modulus width <c>k</c>.</param>
    /// <param name="leadingOctet">The value's first octet.</param>
    /// <returns>The <c>width + 1</c>-octet value.</returns>
    private static byte[] BuildOverWidthValue(int width, byte leadingOctet)
    {
        byte[] value = new byte[width + 1];
        value[0] = leadingOctet;
        for(int index = 1; index < value.Length; index++)
        {
            value[index] = 0x01;
        }

        return value;
    }

    /// <summary>Decrements a big-endian unsigned value by one, borrowing across octets as needed.</summary>
    /// <param name="value">The value to decrement.</param>
    /// <returns>A new array holding <paramref name="value"/> minus one.</returns>
    private static byte[] DecrementBigEndian(byte[] value)
    {
        byte[] result = (byte[])value.Clone();
        for(int index = result.Length - 1; index >= 0; index--)
        {
            if(result[index] != 0)
            {
                result[index]--;

                break;
            }

            result[index] = 0xFF;
        }

        return result;
    }

    /// <summary>Computes <c>message^exponent mod modulus</c>, left-padded to <paramref name="width"/> octets — the raw RSAEP oracle (RFC 8017 §5.1.1), independent of the project's own backend.</summary>
    /// <param name="message">The message octets, big-endian.</param>
    /// <param name="exponent">The public exponent.</param>
    /// <param name="modulus">The modulus octets, big-endian.</param>
    /// <param name="width">The modulus width in octets, <c>k</c>.</param>
    /// <returns>The <paramref name="width"/>-octet ciphertext.</returns>
    private static byte[] ModPowRaw(ReadOnlySpan<byte> message, uint exponent, ReadOnlySpan<byte> modulus, int width)
    {
        var m = new System.Numerics.BigInteger(message, isUnsigned: true, isBigEndian: true);
        var e = new System.Numerics.BigInteger(exponent);
        var n = new System.Numerics.BigInteger(modulus, isUnsigned: true, isBigEndian: true);
        System.Numerics.BigInteger c = System.Numerics.BigInteger.ModPow(m, e, n);
        byte[] raw = c.ToByteArray(isUnsigned: true, isBigEndian: true);
        if(raw.Length == width)
        {
            return raw;
        }

        byte[] padded = new byte[width];
        raw.CopyTo(padded, width - raw.Length);

        return padded;
    }

    /// <summary>Maps a TPM hash algorithm identifier to a fresh BouncyCastle digest instance (digests are stateful and not reusable across calls).</summary>
    /// <param name="hashAlg">The TPM hash algorithm identifier.</param>
    /// <returns>The digest instance.</returns>
    private static IDigest ResolveDigest(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => new Sha1Digest(),
        TpmAlgIdConstants.TPM_ALG_SHA256 => new Sha256Digest(),
        TpmAlgIdConstants.TPM_ALG_SHA384 => new Sha384Digest(),
        TpmAlgIdConstants.TPM_ALG_SHA512 => new Sha512Digest(),
        _ => throw new NotSupportedException($"No off-TPM OAEP oracle digest is mapped for '{hashAlg}'.")
    };

    /// <summary>
    /// Decrypts an OAEP ciphertext off-TPM against the framework key's own private material — the independent
    /// oracle: BouncyCastle's <see cref="OaepEncoding"/> constructed with an explicit label, since the framework
    /// <see cref="RSA"/> surface exposes no label parameter.
    /// </summary>
    /// <param name="key">The framework RSA key (its private parameters are exported here).</param>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="label">The OAEP label, terminating zero included when present.</param>
    /// <param name="hashAlg">The OAEP hash algorithm used for both <c>lhash</c> and MGF1.</param>
    /// <returns>The recovered plaintext.</returns>
    private static byte[] DecryptOaepOffTpm(RSA key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> label, TpmAlgIdConstants hashAlg)
    {
        RSAParameters parameters = key.ExportParameters(includePrivateParameters: true);
        var privateKey = new RsaPrivateCrtKeyParameters(
            new BigInteger(1, parameters.Modulus), new BigInteger(1, parameters.Exponent),
            new BigInteger(1, parameters.D), new BigInteger(1, parameters.P), new BigInteger(1, parameters.Q),
            new BigInteger(1, parameters.DP), new BigInteger(1, parameters.DQ), new BigInteger(1, parameters.InverseQ));
        var oaep = new OaepEncoding(new RsaEngine(), ResolveDigest(hashAlg), ResolveDigest(hashAlg), label.ToArray());
        oaep.Init(forEncryption: false, privateKey);
        byte[] ciphertextBytes = ciphertext.ToArray();

        return oaep.ProcessBlock(ciphertextBytes, 0, ciphertextBytes.Length);
    }

    /// <summary>
    /// Decrypts an OAEP ciphertext off-TPM with independently chosen <c>lhash</c> and MGF1 hash algorithms — the
    /// twin of <see cref="DecryptOaepOffTpm"/> that keeps BouncyCastle's <see cref="OaepEncoding"/> two hash
    /// parameters distinct, since a Table 42 cell pins both to the SAME selected scheme's hash and a test proving
    /// that pinning must be able to drive the oracle with a mismatched MGF1 hash to observe the failure.
    /// </summary>
    /// <param name="key">The framework RSA key (its private parameters are exported here).</param>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="label">The OAEP label, terminating zero included when present.</param>
    /// <param name="lhashAlg">The hash algorithm computing the label digest <c>lhash</c>.</param>
    /// <param name="mgfHashAlg">The hash algorithm driving MGF1.</param>
    /// <returns>The recovered plaintext.</returns>
    private static byte[] DecryptOaepOffTpmWithHashes(RSA key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> label, TpmAlgIdConstants lhashAlg, TpmAlgIdConstants mgfHashAlg)
    {
        RSAParameters parameters = key.ExportParameters(includePrivateParameters: true);
        var privateKey = new RsaPrivateCrtKeyParameters(
            new BigInteger(1, parameters.Modulus), new BigInteger(1, parameters.Exponent),
            new BigInteger(1, parameters.D), new BigInteger(1, parameters.P), new BigInteger(1, parameters.Q),
            new BigInteger(1, parameters.DP), new BigInteger(1, parameters.DQ), new BigInteger(1, parameters.InverseQ));
        var oaep = new OaepEncoding(new RsaEngine(), ResolveDigest(lhashAlg), ResolveDigest(mgfHashAlg), label.ToArray());
        oaep.Init(forEncryption: false, privateKey);
        byte[] ciphertextBytes = ciphertext.ToArray();

        return oaep.ProcessBlock(ciphertextBytes, 0, ciphertextBytes.Length);
    }

    /// <summary>Issues <c>TPM2_RSA_Encrypt()</c>'s plain form through the production executor, borrowing and disposing its own message/label carriers.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The key handle.</param>
    /// <param name="message">The plaintext to encrypt.</param>
    /// <param name="inScheme">The command's <c>inScheme</c>.</param>
    /// <param name="label">The optional label.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<RsaEncryptResponse>> EncryptAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle,
        ReadOnlyMemory<byte> message, TpmtRsaDecrypt inScheme, ReadOnlyMemory<byte> label)
    {
        using Tpm2bPublicKeyRsa messageCarrier = Tpm2bPublicKeyRsa.Create(message.Span, pool);
        using Tpm2bData labelCarrier = Tpm2bData.Create(label.Span, pool);
        var input = new RsaEncryptInput(TpmiDhObject.FromValue(keyHandle), messageCarrier, inScheme, labelCarrier);

        return await TpmCommandExecutor.ExecuteAsync<RsaEncryptResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_RSA_Decrypt()</c>'s password form against an empty-authValue key, through the production executor.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The key handle.</param>
    /// <param name="cipherText">The ciphertext to decrypt.</param>
    /// <param name="inScheme">The command's <c>inScheme</c>.</param>
    /// <param name="label">The optional label.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<RsaDecryptResponse>> DecryptAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle,
        ReadOnlyMemory<byte> cipherText, TpmtRsaDecrypt inScheme, ReadOnlyMemory<byte> label)
    {
        using Tpm2bPublicKeyRsa cipherCarrier = Tpm2bPublicKeyRsa.Create(cipherText.Span, pool);
        using Tpm2bData labelCarrier = Tpm2bData.Create(label.Span, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        var input = new RsaDecryptInput(TpmiDhObject.FromValue(keyHandle), cipherCarrier, inScheme, labelCarrier);

        return await TpmCommandExecutor.ExecuteAsync<RsaDecryptResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates an unrestricted RSA decrypt key through <c>TPM2_CreatePrimary()</c> under the owner hierarchy, empty password, dictionary-attack exempt.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="scheme">The key's own decryption scheme.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtRsaScheme scheme)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaDecryptKey(TpmRh.TPM_RH_OWNER, password: null, RsaKeyBits, scheme, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an unrestricted RSA signing key through <c>TPM2_CreatePrimary()</c> under the owner hierarchy.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="scheme">The key's own signing scheme.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtRsaScheme scheme)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(TpmRh.TPM_RH_OWNER, password: null, RsaKeyBits, scheme, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates the standard RSA 2048 endorsement key (restricted, scheme NULL) under the endorsement hierarchy.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaEndorsementKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_ENDORSEMENT, pool);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA EK) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an ECC P-256 ECDSA signing primary under the owner hierarchy.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(NameAlg), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>A framework-minted RSA-2048 key pair, retained off-TPM as the independent decryption oracle.</summary>
    private sealed class RsaKeyMaterial: IDisposable
    {
        /// <summary>Gets the framework key, the off-TPM decryption oracle.</summary>
        public RSA Key { get; }

        /// <summary>Gets the public modulus, 256 octets.</summary>
        public byte[] Modulus { get; }

        /// <summary>Gets the first prime factor, 128 octets.</summary>
        public byte[] P { get; }

        /// <summary>Initializes the material from the framework key.</summary>
        /// <param name="key">The framework key; owned.</param>
        private RsaKeyMaterial(RSA key)
        {
            Key = key;
            RSAParameters parameters = key.ExportParameters(includePrivateParameters: true);
            Modulus = PadLeft(parameters.Modulus!, ModulusOctets);
            P = PadLeft(parameters.P!, ModulusOctets / 2);
        }

        /// <summary>Mints a fresh RSA-2048 key pair.</summary>
        /// <returns>The material; the caller disposes it.</returns>
        public static RsaKeyMaterial Generate() => new(RSA.Create((int)RsaKeyBits));

        /// <summary>Releases the framework key and clears the prime.</summary>
        public void Dispose()
        {
            Array.Clear(P);
            Key.Dispose();
        }
    }

    /// <summary>Left-pads an unsigned big-endian integer to a fixed width.</summary>
    /// <param name="value">The integer's octets.</param>
    /// <param name="width">The target width.</param>
    /// <returns>The padded octets.</returns>
    private static byte[] PadLeft(byte[] value, int width)
    {
        if(value.Length == width)
        {
            return value;
        }

        byte[] padded = new byte[width];
        value.CopyTo(padded, width - value.Length);

        return padded;
    }

    /// <summary>Builds an RSA-2048 signing-shaped public area carrying the given modulus (TPM 2.0 Library Part 2, clause 12.2.4, Table 235).</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <param name="scheme">The scheme.</param>
    /// <param name="modulus">The public modulus.</param>
    /// <returns>The public area; the caller owns it.</returns>
    private static Tpm2bPublic BuildRsaPublic(BaseMemoryPool pool, TpmaObject attributes, TpmtRsaScheme scheme, ReadOnlySpan<byte> modulus) =>
        Tpm2bPublic.CreateRsaSigningKey(NameAlg, attributes, RsaKeyBits, scheme, modulus, pool);

    /// <summary>Issues <c>TPM2_LoadExternal()</c> for an RSA-2048 key built from the given modulus — public-only when <paramref name="prime"/> is empty, with a sensitive area around the prime otherwise.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy the object joins.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <param name="scheme">The scheme.</param>
    /// <param name="modulus">The public modulus.</param>
    /// <param name="prime">One prime factor, or empty for a public-only load.</param>
    /// <returns>The response; the caller owns it and asserts success itself.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once the command has been issued.")]
    private async Task<LoadExternalResponse> LoadRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiRhHierarchy hierarchy,
        TpmaObject attributes, TpmtRsaScheme scheme, ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> prime = default)
    {
        Tpm2bPublic inPublic = BuildRsaPublic(pool, attributes, scheme, modulus.Span);
        TpmtSensitive? inPrivate = prime.IsEmpty
            ? null
            : new TpmtSensitive(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, TpmuSensitiveComposite.FromRsa(Tpm2bPrivateKeyRsa.Create(prime.Span, pool)));
        using var input = new LoadExternalInput(inPrivate, inPublic, hierarchy);

        TpmResult<LoadExternalResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_LoadExternal() (RSA) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Loads a fixed HMAC (KEYEDHASH) key with its sensitive area under <c>TPM_RH_NULL</c>.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once the command has been issued.")]
    private async Task<LoadExternalResponse> LoadHmacKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        byte[] seed = new byte[Sha256DigestSize];
        Array.Fill(seed, (byte)0xC0);
        byte[] hmacKey = [0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B];
        byte[] message = new byte[seed.Length + hmacKey.Length];
        seed.CopyTo(message, 0);
        hmacKey.CopyTo(message, seed.Length);
        byte[] unique = SHA256.HashData(message);

        Tpm2bPublic inPublic = Tpm2bPublic.CreateKeyedHashTemplate(NameAlg, ExternalSigningAttributes, TpmsKeyedHashParms.Hmac(NameAlg), default, pool, unique);
        TpmtSensitive inPrivate = TpmtSensitive.ForKeyedHash(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Create(seed, pool), Tpm2bSensitiveData.Create(hmacKey, pool));
        using var input = new LoadExternalInput(inPrivate, inPublic, TpmiRhHierarchy.Null);

        TpmResult<LoadExternalResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_LoadExternal() (HMAC) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Opens a SHA-256 hash sequence context with an empty authValue.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The sequence handle.</returns>
    private async Task<TpmiDhObject> StartHashSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using HashSequenceStartInput input = HashSequenceStartInput.Create([], TpmiAlgHash.FromValue(NameAlg), pool);
        TpmResult<HashSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HashSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>Writes the owner hierarchy's enable through <c>TPM2_HierarchyControl()</c> under platform authorization and asserts success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="state">The enable state to write.</param>
    private async Task SetOwnerHierarchyEnabledAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiYesNo state)
    {
        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            tpm, new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, TpmRh.TPM_RH_OWNER, state), [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl(OWNER, {state}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Creates an operational simulator with both asymmetric backends wired.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            $"tpm-in-house-rsa-encrypt-{name}", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an unauthorized command on the wire.</summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)TpmHeader.Parse(ref reader).Code, "TPM2_Startup(CLEAR) must succeed.");
    }

    /// <summary>Issues <c>TPM2_SelfTest(NO)</c> directly against the simulator and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSelfTestAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new SelfTestInput(IsFullTest: false);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer TPM2_SelfTest() rather than fault.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_RSA_Encrypt, TpmResponseCodec.RsaEncrypt);
        _ = registry.Register(TpmCcConstants.TPM_CC_RSA_Decrypt, TpmResponseCodec.RsaDecrypt);
        _ = registry.Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal);
        _ = registry.Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl);

        return registry;
    }

    /// <summary>Appends a big-endian <c>UINT32</c>.</summary>
    /// <param name="body">The frame under construction.</param>
    /// <param name="value">The value.</param>
    private static void AppendUInt32(List<byte> body, uint value)
    {
        Span<byte> scratch = stackalloc byte[sizeof(uint)];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(scratch, value);
        body.AddRange(scratch);
    }

    /// <summary>Appends a big-endian <c>UINT16</c>.</summary>
    /// <param name="body">The frame under construction.</param>
    /// <param name="value">The value.</param>
    private static void AppendUInt16(List<byte> body, ushort value)
    {
        Span<byte> scratch = stackalloc byte[sizeof(ushort)];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(scratch, value);
        body.AddRange(scratch);
    }

    /// <summary>Appends a size-prefixed <c>TPM2B</c>.</summary>
    /// <param name="body">The frame under construction.</param>
    /// <param name="octets">The buffer contents.</param>
    private static void AppendTpm2b(List<byte> body, ReadOnlySpan<byte> octets)
    {
        AppendUInt16(body, (ushort)octets.Length);
        body.AddRange(octets.ToArray());
    }

    /// <summary>Frames a <c>TPM_ST_NO_SESSIONS</c> <c>TPM2_RSA_Encrypt()</c> header around <paramref name="body"/>, submits it straight to the simulator, and returns the response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="body">The handle and parameter area, already laid out.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_RSA_Encrypt);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        if(result.IsSuccess)
        {
            using TpmResponse response = result.Value;
            var reader = new TpmReader(response.AsReadOnlySpan());

            return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
        }

        return result.ResponseCode;
    }
}
