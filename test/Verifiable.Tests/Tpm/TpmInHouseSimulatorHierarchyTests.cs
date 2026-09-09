using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the hierarchy and provisioning command family - <c>TPM2_HierarchyChangeAuth</c>,
/// <c>TPM2_Clear</c>, <c>TPM2_ClearControl</c>, <c>TPM2_HierarchyControl</c> and
/// <c>TPM2_SetPrimaryPolicy</c> - against the in-house behavioural <see cref="TpmSimulator"/>, entirely
/// in-process and with no external assets, through the same production command path production code uses
/// (<see cref="TpmCommandExecutor"/>, the real command inputs and response codecs, and the
/// <c>Extensions/Hierarchy</c> verb group).
/// </summary>
/// <remarks>
/// <para>
/// <b>These commands are simulator-only by construction.</b> <c>TPM2_Clear</c> discards the storage primary
/// seed and every key derived under it, and <c>TPM2_HierarchyControl</c> can disable the platform hierarchy
/// until the next platform reset (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
/// 2.0 Library Specification</see>, Part 3, clauses 24.6.1 and 24.2.1). Nothing in this file, and nothing any
/// hardware-gated test reaches, may ever put one of them on a real device.
/// </para>
/// <para>
/// <b>Where each ladder lives.</b> The five commands' own authorization, size and availability ladders are
/// here. The cross-feeds into already-shipped surfaces are asserted where those surfaces are already covered,
/// so each observation sits beside the machinery it observes: ticket invalidation across the storage-proof
/// rotation in <c>TpmInHouseSimulatorPolicyTicketTests</c>, persistent-object eviction and NV Index deletion
/// in <c>TpmInHouseSimulatorPersistenceTests</c>, the phantom counter high-water mark's survival of an owner
/// change in <c>TpmInHouseSimulatorNvCounterTests</c>, and the dictionary-attack reset in
/// <c>TpmInHouseSimulatorDictionaryAttackTests</c>.
/// </para>
/// <para>
/// <b>Two response codes are inferences, and are marked as such at their own tests.</b> Part 3, clause 24.8
/// names no code for a <c>TPM2_HierarchyChangeAuth</c> against a disabled hierarchy, and clause 24.2.1 names
/// none for a wrong-authority <c>TPM2_HierarchyControl</c>; the codes asserted here are read off the shared
/// availability rule of Part 1, clause 10.2 and the sibling command's stated code in clause 24.3.1.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorHierarchyTests
{
    /// <summary>The session and policy hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width in octets.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>
    /// The octet bound on a hierarchy authorization value. A hierarchy has no Name algorithm, so the bound is
    /// "the digest produced by the hash algorithm used for context integrity" (TPM 2.0 Library Part 1, clause
    /// 16.6.4.2; Part 3, clause 24.8.1 restates it as the command's own rule, with a worked SHA-384 example
    /// giving 48 octets). This simulator's context-integrity hash is SHA-256, so the bound is its digest width.
    /// </summary>
    private const int ContextIntegrityDigestSize = 32;

    /// <summary>Every RSA storage-parent-shaped template this simulator builds fixes nameAlg to SHA-256.</summary>
    private const TpmAlgIdConstants TpmKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA public exponent the framework RSA key generator uses (TPM 2.0 Library Part 2, Table 228).</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>The RSA modulus size this file's RSA CreatePrimary templates use.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>
    /// A handle inside the Authenticated Countdown Timer range <c>TPMI_RH_HIERARCHY_POLICY</c> also admits
    /// (TPM 2.0 Library Part 2, clause 9.29's <c>TPM_RH_ACT_0</c> at 0x40000110); this library models no ACT.
    /// </summary>
    private const uint ActHandle = 0x4000_0110;

    /// <summary>The authorization value the rotation ladders install first.</summary>
    private static byte[] FirstAuth { get; } = [0x51, 0x62, 0x73, 0x84, 0x95, 0xA6, 0xB7, 0xC8];

    /// <summary>A second authorization value, distinct from <see cref="FirstAuth"/>.</summary>
    private static byte[] SecondAuth { get; } = [0x19, 0x28, 0x37, 0x46, 0x55, 0x64, 0x73, 0x82, 0x91];

    /// <summary>A value that authorizes nothing here, distinct from every other value in this file.</summary>
    private static byte[] WrongAuth { get; } = [0xDE, 0xAD, 0xBE, 0xEF];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The rotation, end to end, for each hierarchy that carries its own authorization value:
    /// <c>TPM2_HierarchyChangeAuth</c> "allows the authorization secret for a hierarchy or lockout to be changed
    /// using the current authorization value as the command authorization"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 24.8.1), so after a rotation the replaced value must stop
    /// authorizing and the installed one must start. The Empty Buffer is a knowable, usable authorization value
    /// rather than a disabled one (Part 1, clause 10.2, Table 8), so rotating back to it must also work - the
    /// last leg pins exactly that, since a design that treated "empty" as "unset" would refuse it.
    /// </summary>
    /// <param name="hierarchy">The hierarchy handle whose authorization value is rotated.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, DisplayName = "TPM_RH_OWNER")]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, DisplayName = "TPM_RH_ENDORSEMENT")]
    [DataRow((uint)TpmRh.TPM_RH_PLATFORM, DisplayName = "TPM_RH_PLATFORM")]
    public async Task HierarchyChangeAuthReplacesTheAuthorizationValueSoTheOldOneStopsAuthorizing(uint hierarchy)
    {
        var hierarchyHandle = (TpmRh)hierarchy;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyChangeAuthResponse> firstRotation = await device.ChangeHierarchyAuthAsync(
            hierarchyHandle, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(firstRotation.IsSuccess, $"The factory-state rotation must succeed: '{firstRotation.ResponseCode}'.");

        TpmResult<HierarchyChangeAuthResponse> staleRotation = await device.ChangeHierarchyAuthWithPasswordAsync(
            hierarchyHandle, ReadOnlyMemory<byte>.Empty, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(staleRotation.IsSuccess, "The replaced authorization value must no longer authorize the command.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), staleRotation.ResponseCode,
            "Owner, endorsement and platform authorization values are dictionary-attack exempt permanent-entity values (Part 1, clause 16.8.1), so a mismatch is the plain TPM_RC_BAD_AUTH.");

        TpmResult<HierarchyChangeAuthResponse> secondRotation = await device.ChangeHierarchyAuthWithPasswordAsync(
            hierarchyHandle, FirstAuth, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(secondRotation.IsSuccess, $"The installed authorization value must authorize the next rotation: '{secondRotation.ResponseCode}'.");

        TpmResult<HierarchyChangeAuthResponse> backToEmpty = await device.ChangeHierarchyAuthWithPasswordAsync(
            hierarchyHandle, SecondAuth, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(backToEmpty.IsSuccess, $"Returning a hierarchy to the Empty Buffer must be accepted: '{backToEmpty.ResponseCode}'.");

        TpmResult<HierarchyChangeAuthResponse> emptyAuthorizes = await device.ChangeHierarchyAuthWithPasswordAsync(
            hierarchyHandle, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            emptyAuthorizes.IsSuccess,
            $"The Empty Buffer must authorize as an ordinary value once installed - it is knowable, not disabled: '{emptyAuthorizes.ResponseCode}'.");
    }

    /// <summary>
    /// <c>lockoutAuth</c> is the one permanent entity inside dictionary-attack protection (TPM 2.0 Library Part
    /// 1, clause 16.8.1), so a wrong current value on its rotation is not merely refused: it engages the
    /// special lockoutAuth-failure state that bars further use of the value "regardless of the setting of
    /// failedTries and maxTries" (clause 16.8.5,
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>), so the very next attempt - the CORRECT one - answers <c>TPM_RC_LOCKOUT</c> before
    /// any value is compared. Platform Authorization is categorically exempt from all of it (Part 3, clause
    /// 25.1), which is what keeps a platform-authorized command the recovery path out of a self-inflicted
    /// lockout; the last leg proves that exemption is real rather than assumed.
    /// </summary>
    [TestMethod]
    public async Task HierarchyChangeAuthOnLockoutSpendsTheOneStrikeAndPlatformAuthorizationStaysUsable()
    {
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyChangeAuthResponse> wrongValue = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_LOCKOUT, WrongAuth, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(wrongValue.IsSuccess, "A wrong lockoutAuth must not rotate the lockout entity's authorization value.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongValue.ResponseCode,
            "A lockoutAuth mismatch is TPM_RC_AUTH_FAIL, the code clause 16.8.5's one-strike state hangs off, not the dictionary-attack-exempt TPM_RC_BAD_AUTH.");

        TpmResult<HierarchyChangeAuthResponse> correctValue = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(correctValue.IsSuccess, "One strike must bar further use of lockoutAuth, correct value included.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, correctValue.ResponseCode,
            "The one-strike state is checked before the value is compared, so the answer is TPM_RC_LOCKOUT rather than a second TPM_RC_AUTH_FAIL.");

        TpmResult<ClearControlResponse> platformArm = await device.ClearControlWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, isDisablingClear: true, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            platformArm.IsSuccess,
            $"Platform Authorization is never dictionary-attack gated, so it must still work while lockoutAuth is barred: '{platformArm.ResponseCode}'.");
    }

    /// <summary>
    /// The size gate strips before it measures, and the order is normative rather than an optimization:
    /// "Trailing octets of zero are to be removed from any string before it is used as an authValue"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 16.6.4.3) and only the remainder is measured against the bound
    /// Part 3, clause 24.8.1 states for this command, "the digest produced by the hash algorithm used for context
    /// integrity". A genuine 33-octet value is therefore <c>TPM_RC_SIZE</c> while a 32-octet value padded out
    /// with trailing zeros is accepted - and the value actually installed is the STRIPPED one, proven by
    /// authorizing with the 32-octet form afterwards. A gate that measured first would reject the padded value;
    /// one that never measured would accept the 33-octet one; one that stored the padded form would fail the
    /// last leg.
    /// </summary>
    [TestMethod]
    public async Task HierarchyChangeAuthStripsTrailingZerosBeforeMeasuringNewAuthAgainstTheContextIntegrityDigestSize()
    {
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        //One octet past the bound with no trailing zero to strip: nothing can bring it inside the limit.
        byte[] overlongNewAuth = new byte[ContextIntegrityDigestSize + 1];
        for(int i = 0; i < overlongNewAuth.Length; i++)
        {
            overlongNewAuth[i] = (byte)(i + 1);
        }

        TpmResult<HierarchyChangeAuthResponse> overlongResult = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, overlongNewAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(overlongResult.IsSuccess, "A newAuth longer than the context-integrity digest size must not be accepted.");
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), overlongResult.ResponseCode, "Table 205: newAuth is TPM2_HierarchyChangeAuth()'s sole parameter (parameter 1); a value wider than the context-integrity digest size is parameter-encoded TPM_RC_SIZE at index 0.");

        TpmResult<HierarchyChangeAuthResponse> stillEmpty = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(stillEmpty.IsSuccess, $"A refused over-long rotation must leave the authorization value untouched: '{stillEmpty.ResponseCode}'.");

        //The same meaningful octets padded past the limit with zeros: stripping brings the value back to exactly
        //the digest width, so the gate must accept it and install the stripped form.
        byte[] strippedNewAuth = overlongNewAuth.AsSpan(0, ContextIntegrityDigestSize).ToArray();
        byte[] paddedNewAuth = new byte[ContextIntegrityDigestSize + 8];
        strippedNewAuth.CopyTo(paddedNewAuth.AsSpan());

        TpmResult<HierarchyChangeAuthResponse> paddedResult = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, FirstAuth, paddedNewAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            paddedResult.IsSuccess,
            $"A value that is over-long only because of trailing zero octets must be accepted after stripping: '{paddedResult.ResponseCode}'.");

        TpmResult<HierarchyChangeAuthResponse> strippedAuthorizes = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, strippedNewAuth, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            strippedAuthorizes.IsSuccess,
            $"The value installed must be the STRIPPED form, so the 32-octet value authorizes: '{strippedAuthorizes.ResponseCode}'.");
    }

    /// <summary>
    /// The replacement value rides <c>newAuth</c>, the command's sole and therefore first sized parameter, under
    /// a SEPARATE decrypt session, so it never appears as wire content; the value being replaced never appears
    /// either, because it only ever enters as a term of the session keys
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clauses 18.1 and 16.6.10). Every command octet the verb sends is captured
    /// and searched. The hierarchy already carries a real authorization value here, so a failure of this test
    /// would be a genuine secret on the bus rather than an artefact of a factory-state Empty Buffer.
    /// </summary>
    [TestMethod]
    public async Task ChangeHierarchyAuthAsyncNeverSendsEitherAuthorizationValueAsPlaintextOnTheWire()
    {
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyChangeAuthResponse> provisioning = await plainDevice.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(provisioning.IsSuccess, $"Provisioning the first authorization value failed: '{provisioning.ResponseCode}'.");

        var capturedCommands = new List<byte[]>();
        using TpmDevice capturingDevice = CreateCapturingDevice(simulator, capturedCommands);

        TpmResult<HierarchyChangeAuthResponse> rotation = await capturingDevice.ChangeHierarchyAuthAsync(
            TpmRh.TPM_RH_OWNER, FirstAuth, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotation.IsSuccess, $"ChangeHierarchyAuthAsync failed: '{rotation.ResponseCode}'.");

        Assert.IsNotEmpty(capturedCommands, "The capturing wrapper must have observed the rotation's commands.");
        foreach(byte[] command in capturedCommands)
        {
            Assert.IsFalse(
                ContainsSubsequence(command, SecondAuth),
                "The replacement authorization value must never appear as a contiguous byte sequence on the wire.");
            Assert.IsFalse(
                ContainsSubsequence(command, FirstAuth),
                "The authorization value being replaced must never appear as a contiguous byte sequence on the wire.");
        }
    }

    /// <summary>
    /// The confidentiality boundary of the replacement value, stated honestly and proven by ONE independent
    /// keystream derivation applied to three rotations. The decrypt companion is bound to the target hierarchy,
    /// so its session key is <c>KDFa(authValue, "ATH", nonceTPM, nonceCaller)</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 16.6.10, equation 20) and the XOR keystream over <c>newAuth</c>
    /// (clause 18.2) derives from it alone. While the hierarchy's authorization value is still the Empty
    /// Buffer, that key is a function of the two public <c>TPM2_StartAuthSession</c> nonces and nothing else, so
    /// the first provisioning rotation's encryption is structural rather than confidential - and this test
    /// recovers the value to say so. Once a real authorization value is installed the SAME derivation stops
    /// recovering it, and the salted overload folds a secret only the TPM can recover (clause 16.6.12, equation
    /// 25) so it closes the factory-state case too.
    /// </summary>
    [TestMethod]
    public async Task TheFactoryStateRotationYieldsToThePublicNonceKeystreamWhileARealValueAndTheSaltedOverloadDoNot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        var factoryStatePairs = new List<(TpmCcConstants Code, byte[] Command, byte[] Response)>();
        using(TpmDevice recordingDevice = CreateRecordingDevice(simulator, factoryStatePairs))
        {
            TpmResult<HierarchyChangeAuthResponse> result = await recordingDevice.ChangeHierarchyAuthAsync(
                TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"The factory-state rotation failed: '{result.ResponseCode}'.");
        }

        byte[] factoryStateRecovered = await RecoverNewAuthWithABoundSessionKeyAsync(
            factoryStatePairs, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
        Assert.IsTrue(
            factoryStateRecovered.AsSpan().SequenceEqual(FirstAuth),
            "With the hierarchy's authorization value still the Empty Buffer the bound session key is a function of the public nonces alone, so the derivation recovers the replacement value - structural encryption, not confidentiality.");

        var provisionedPairs = new List<(TpmCcConstants Code, byte[] Command, byte[] Response)>();
        using(TpmDevice recordingDevice = CreateRecordingDevice(simulator, provisionedPairs))
        {
            TpmResult<HierarchyChangeAuthResponse> result = await recordingDevice.ChangeHierarchyAuthAsync(
                TpmRh.TPM_RH_OWNER, FirstAuth, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"The rotation under a real authorization value failed: '{result.ResponseCode}'.");
        }

        byte[] publicOnlyAttempt = await RecoverNewAuthWithABoundSessionKeyAsync(
            provisionedPairs, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
        Assert.IsFalse(
            publicOnlyAttempt.AsSpan().SequenceEqual(SecondAuth),
            "Once the hierarchy carries a real authorization value the bound session key folds a secret, so the public-nonce derivation no longer recovers the replacement value.");

        byte[] withTheSecretAttempt = await RecoverNewAuthWithABoundSessionKeyAsync(
            provisionedPairs, FirstAuth, pool).ConfigureAwait(false);
        Assert.IsTrue(
            withTheSecretAttempt.AsSpan().SequenceEqual(SecondAuth),
            "The same derivation keyed on the hierarchy's real authorization value must recover it, or the previous leg would prove nothing about which term made the difference.");

        using TpmSimulator saltedSimulator = await CreateOperationalAsync().ConfigureAwait(false);
        var saltedPairs = new List<(TpmCcConstants Code, byte[] Command, byte[] Response)>();
        using(TpmDevice recordingDevice = CreateRecordingDevice(saltedSimulator, saltedPairs))
        {
            using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(recordingDevice, CreateKeyRegistry(), pool).ConfigureAwait(false);
            uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

            try
            {
                ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
                TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

                TpmResult<HierarchyChangeAuthResponse> saltedResult = await recordingDevice.ChangeHierarchyAuthAsync(
                    TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstAuth,
                    tpmKeyHandle, modulus, DefaultRsaExponent, TpmKeyNameAlg, rsaBackend.EncryptOaep, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(saltedResult.IsSuccess, $"The salted rotation failed: '{saltedResult.ResponseCode}'.");
            }
            finally
            {
                _ = await recordingDevice.FlushContextAsync(tpmKeyHandle, CancellationToken.None).ConfigureAwait(false);
            }
        }

        byte[] saltedRecovered = await RecoverNewAuthWithABoundSessionKeyAsync(
            saltedPairs, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
        Assert.IsFalse(
            saltedRecovered.AsSpan().SequenceEqual(FirstAuth),
            "The salted overload folds a salt only the TPM can recover, so the public derivation that unlocked the factory-state rotation cannot recover the replacement value even against an Empty Buffer authorization value.");
    }

    /// <summary>
    /// The response-key rule, pinned on the wire. Part 3, clause 24.8.1: "The HMAC in the response shall use
    /// the new authorization value when computing the response HMAC"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>) - which bites only for a session whose HMAC key carries the authorization value at
    /// all, so this test composes the UNBOUND HMAC session where it does (Part 1, clause 16.6.10's equation 22
    /// drops that term for a session bound to the entity it authorizes, which is why the shipped verb binds).
    /// Both candidate response HMACs are recomputed off-wire from the captured exchange: the NEW-keyed one must
    /// equal what the TPM framed and the OLD-keyed one must not. The host session's own key was fixed at
    /// composition and does not move, so it rejects that correct response with <c>TPM_RC_AUTH_FAIL</c> - the
    /// rotation nevertheless committed, which the closing probe proves, so the refusal is the caller's stale key
    /// rather than a refused command.
    /// </summary>
    [TestMethod]
    public async Task HierarchyChangeAuthFramesItsResponseHmacUnderTheNewAuthorizationValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRotationRegistry();

        TpmResult<HierarchyChangeAuthResponse> provisioning = await plainDevice.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(provisioning.IsSuccess, $"Provisioning the first authorization value failed: '{provisioning.ResponseCode}'.");

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            plainDevice, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound HMAC) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        byte[]? capturedCommand = null;
        byte[]? capturedResponse = null;
        async ValueTask<TpmResult<TpmResponse>> CaptureRotationAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] commandBytes = command.ToArray();
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
            if(ReadCommandCode(commandBytes) == TpmCcConstants.TPM_CC_HierarchyChangeAuth && result.IsSuccess)
            {
                capturedCommand = commandBytes;
                capturedResponse = result.Value.AsReadOnlySpan().ToArray();
            }

            return result;
        }

        using TpmDevice capturingDevice = TpmDevice.Create(CaptureRotationAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
            session.SetAuthValue(FirstAuth, pool);

            using Tpm2bAuth newAuth = Tpm2bAuth.Create(SecondAuth, pool);
            using HierarchyChangeAuthInput input = new(TpmRh.TPM_RH_OWNER, newAuth);

            TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
                capturingDevice, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(
                result.IsSuccess,
                "An unbound host session keys its response check on the value it was composed with, which the command just replaced, so it cannot verify a spec-correct response.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode,
                "A response authorization that does not verify is an integrity failure, not a parse failure.");
        }
        finally
        {
            _ = await plainDevice.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }

        Assert.IsNotNull(capturedCommand, "The capturing transport must have observed the rotation command.");
        Assert.IsNotNull(capturedResponse, "The capturing transport must have observed the rotation response.");

        byte[] commandNonceCaller = ReadCommandSessionNonces(capturedCommand!, handleCount: 1)[0];
        (int hmacStart, int hmacLength, byte[] responseNonceTpm, byte sessionAttributes) = ReadFirstResponseSessionEntry(capturedResponse!);

        byte[] hmacData = await BuildResponseHmacDataAsync(
            capturedResponse!, TpmCcConstants.TPM_CC_HierarchyChangeAuth, responseNonceTpm, commandNonceCaller, sessionAttributes, pool).ConfigureAwait(false);

        //An unbound, unsalted session's sessionKey is the Empty Buffer (Part 1, clause 16.6.9), so the whole
        //HMAC key is the authorization value term alone, trailing zeros already removed (clause 16.6.4.3).
        byte[] newKeyedHmac = await ComputeSessionHmacAsync(StripTrailingZeros(SecondAuth), hmacData, pool).ConfigureAwait(false);
        byte[] oldKeyedHmac = await ComputeSessionHmacAsync(StripTrailingZeros(FirstAuth), hmacData, pool).ConfigureAwait(false);

        Assert.HasCount(hmacLength, newKeyedHmac, "The framed response HMAC must be the session hash's full width.");
        Assert.IsFalse(
            newKeyedHmac.AsSpan().SequenceEqual(oldKeyedHmac),
            "The two candidate keys must produce different HMACs, or this test would prove nothing.");
        Assert.IsTrue(
            capturedResponse!.AsSpan(hmacStart, hmacLength).SequenceEqual(newKeyedHmac),
            "The TPM must key the response HMAC on the NEW authorization value: the rotation commits before the response is framed.");

        //The command itself was genuine, so the rotation happened; only the caller could not verify the framing.
        TpmResult<HierarchyChangeAuthResponse> probe = await plainDevice.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, SecondAuth, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(probe.IsSuccess, $"The genuine command did rotate the hierarchy: '{probe.ResponseCode}'.");
    }

    /// <summary>
    /// The bound default's response leg is genuinely verified rather than merely unproblematic: an active
    /// transport that alters one octet of the rotation's response authorization HMAC is refused with
    /// <c>TPM_RC_AUTH_FAIL</c>, while the identical exchange left alone succeeds. This is what makes the
    /// group's "no key swap is needed here" reasoning non-vacuous - the response HMAC key is the session key,
    /// fixed at <c>TPM2_StartAuthSession</c> and unaffected by the value the command replaces (TPM 2.0 Library
    /// Part 1, clause 16.6.10, equations 21/22,
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>), and the host still checks it.
    /// </summary>
    [TestMethod]
    public async Task TheBoundRotationVerifiesItsResponseAuthorizationAndRefusesATamperedOne()
    {
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        bool tampered = false;
        async ValueTask<TpmResult<TpmResponse>> TamperRotationResponseAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] commandBytes = command.ToArray();
            TpmResult<TpmResponse> genuine = await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
            if(ReadCommandCode(commandBytes) != TpmCcConstants.TPM_CC_HierarchyChangeAuth || !genuine.IsSuccess)
            {
                return genuine;
            }

            byte[] responseBytes;
            using(TpmResponse genuineResponse = genuine.Value)
            {
                responseBytes = genuineResponse.AsReadOnlySpan().ToArray();
            }

            (int hmacStart, int hmacLength, _, _) = ReadFirstResponseSessionEntry(responseBytes);
            responseBytes[hmacStart + hmacLength - 1] ^= 0xFF;
            tampered = true;

            return CopyToResponse(responseBytes, commandPool);
        }

        using(TpmDevice tamperingDevice = TpmDevice.Create(TamperRotationResponseAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream()))
        {
            TpmResult<HierarchyChangeAuthResponse> result = await tamperingDevice.ChangeHierarchyAuthAsync(
                TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(tampered, "The tampering transport must have observed and altered the rotation response.");
            Assert.IsFalse(result.IsSuccess, "A response authorization HMAC that does not verify must never be accepted.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode);
        }

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResult<HierarchyChangeAuthResponse> untampered = await plainDevice.ChangeHierarchyAuthAsync(
            TpmRh.TPM_RH_OWNER, FirstAuth, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            untampered.IsSuccess,
            $"The same composition left alone must succeed, or the refusal above would prove nothing: '{untampered.ResponseCode}'.");
    }

    /// <summary>
    /// A decrypt or encrypt attribute on the AUTHORIZING session is refused with a session-encoded
    /// <c>TPM_RC_ATTRIBUTES</c> rather than honoured. Part 1, clause 18.1's note is the reason: a session used
    /// both to authorize an entity and to encrypt folds that entity's authorization value into its
    /// <c>sessionValue</c> (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>), which would key the encryption of the NEW authorization value on the
    /// OLD one - protecting it against nobody who could not already guess the value being rotated away from. The
    /// attribute is set on the built command by an intervening transport, because the verb itself composes a
    /// SEPARATE decrypt session and never asks for this shape.
    /// </summary>
    [TestMethod]
    public async Task HierarchyChangeAuthWithADecryptAttributedAuthorizingSessionIsRefusedWithAttributes()
    {
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        async ValueTask<TpmResult<TpmResponse>> ClaimDecryptOnRotationAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_HierarchyChangeAuth)
            {
                SetFirstSessionAttributeBit(bytes, handleCount: 1, (byte)TpmaSession.DECRYPT);

                return await simulator.SubmitAsync(bytes, commandPool, ct).ConfigureAwait(false);
            }

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice tamperingDevice = TpmDevice.Create(ClaimDecryptOnRotationAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyChangeAuthResponse> result = await tamperingDevice.ChangeHierarchyAuthAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A decrypt-attributed authorizing session must not be accepted.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError,
            "The refusal is about the session's attributes, not about a key or a value.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
            "The refusal names the offending session, so the raw wire code carries the session-index modifier.");

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResult<HierarchyChangeAuthResponse> untouched = await plainDevice.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            untouched.IsSuccess,
            $"The refused rotation must have left the authorization value untouched: '{untouched.ResponseCode}'.");
    }

    /// <summary>
    /// A hierarchy whose enable is CLEAR can authorize nothing at all - "When an enable is FALSE, the
    /// corresponding authValue and authPolicy cannot be used to authorize any TPM action"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 10.2, Table 8), which clause 10.2 restates for this command
    /// specifically: "TPM2_HierarchyChangeAuth() can change the authValue associated with a hierarchy but only
    /// if the hierarchy is enabled". clause 24.8 names no response code for the refusal; the code asserted here
    /// is read off the sibling command's stated one for the identical condition ("If the enable associated with
    /// authHandle is not SET ... the TPM returns TPM_RC_HIERARCHY", clause 24.3.1), so it is an inference by
    /// analogy rather than a quotation. The same refusal is asserted for <c>TPM2_SetPrimaryPolicy</c>, where it
    /// IS quoted, so the two cannot silently drift apart.
    /// </summary>
    [TestMethod]
    public async Task ADisabledHierarchyCanAuthorizeNeitherItsOwnAuthorizationChangeNorItsPolicyInstallation()
    {
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyControlResponse> disableResult = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_ENDORSEMENT, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"Disabling the endorsement hierarchy failed: '{disableResult.ResponseCode}'.");

        TpmResult<HierarchyChangeAuthResponse> rotation = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(rotation.IsSuccess, "A disabled hierarchy must not be able to change its own authorization value.");
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), rotation.ResponseCode, "Table 205: authHandle is TPM2_HierarchyChangeAuth()'s sole handle (handle 1); a disabled hierarchy is handle-encoded TPM_RC_HIERARCHY at index 0.");

        byte[] policyDigest = ComputePolicyAuthValueDigest();
        TpmResult<SetPrimaryPolicyResponse> policyResult = await device.SetPrimaryPolicyWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, policyDigest, SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(policyResult.IsSuccess, "A disabled hierarchy must not be able to install its own policy.");
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), policyResult.ResponseCode, "Table 195: authHandle is TPM2_SetPrimaryPolicy()'s sole handle (handle 1); a disabled hierarchy is handle-encoded TPM_RC_HIERARCHY at index 0.");

        TpmResult<HierarchyControlResponse> enableResult = await device.EnableHierarchyWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_ENDORSEMENT, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(enableResult.IsSuccess, $"Platform Authorization must be able to re-enable the hierarchy: '{enableResult.ResponseCode}'.");

        TpmResult<HierarchyChangeAuthResponse> afterEnable = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            afterEnable.IsSuccess,
            $"Re-enabling restores the hierarchy's own authorization path, so the refusals above were about the enable: '{afterEnable.ResponseCode}'.");
    }

    /// <summary>
    /// <c>TPM2_ClearControl</c>'s authorization asymmetry, end to end. "Lockout Authorization may be used to SET
    /// disableClear but not to CLEAR it. Platform Authorization may be used to SET or CLEAR disableClear"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 24.7.1), and with the control SET, "If TPM2_ClearControl() has
    /// disabled this command, the TPM shall return TPM_RC_DISABLED" (clause 24.6.1). The refused CLEAR is
    /// <c>TPM_RC_AUTH_FAIL</c> even though nothing about the supplied value was wrong, and it must NOT behave
    /// like the authorization-compare failure that shares that code: no dictionary-attack counter moves and
    /// lockoutAuth stays usable, which the closing legs prove.
    /// </summary>
    [TestMethod]
    public async Task ClearControlLetsLockoutTightenTheControlButOnlyPlatformCanLoosenItAgain()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<ClearControlResponse> lockoutSet = await device.ClearControlAsync(
            TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty, isDisablingClear: true, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lockoutSet.IsSuccess, $"Lockout Authorization must be able to SET disableClear: '{lockoutSet.ResponseCode}'.");

        TpmResult<ClearResponse> disabledClear = await device.ClearAsync(
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(disabledClear.IsSuccess, "With disableClear SET, TPM2_Clear must not execute.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_DISABLED, disabledClear.ResponseCode);

        TpmResult<ClearControlResponse> lockoutClear = await device.ClearControlAsync(
            TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty, isDisablingClear: false, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(lockoutClear.IsSuccess, "Lockout Authorization must never CLEAR disableClear - the ratchet only tightens.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), lockoutClear.ResponseCode,
            "The refusal reuses the generic authorization-failure code, session-encoded to authHandle's own authorizing session, rather than the TPM_RC_AUTH_TYPE its sibling TPM2_HierarchyControl answers for a wrong-authority combination.");

        //Not a value failure: the same authorization still works in the direction it is allowed, so the refusal
        //above spent no dictionary-attack strike (Part 1, clause 16.8.5's one-strike state would have barred this).
        TpmResult<ClearControlResponse> lockoutStillUsable = await device.ClearControlAsync(
            TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty, isDisablingClear: true, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            lockoutStillUsable.IsSuccess,
            $"A refused direction must not disable lockoutAuth the way a wrong value does: '{lockoutStillUsable.ResponseCode}'.");

        Assert.AreEqual(
            0u, await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_LOCKOUT_COUNTER).ConfigureAwait(false),
            "The refused direction must not have advanced the dictionary-attack failure counter.");

        TpmResult<ClearControlResponse> platformClear = await device.ClearControlAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, isDisablingClear: false, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(platformClear.IsSuccess, $"Platform Authorization must be able to CLEAR disableClear: '{platformClear.ResponseCode}'.");

        TpmResult<ClearResponse> permittedClear = await device.ClearAsync(
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(permittedClear.IsSuccess, $"With disableClear CLEAR again, TPM2_Clear must execute: '{permittedClear.ResponseCode}'.");
    }

    /// <summary>
    /// <c>TPM2_Clear</c> "removes all TPM context associated with a specific Owner"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 24.6.1): among its listed effects, ownerAuth, endorsementAuth and
    /// lockoutAuth are set to the Empty Buffer along with their three policies, while platformAuth appears
    /// nowhere on that list and must survive. This drives all four to distinct real values first, so a Clear
    /// that reset the wrong ones - or all of them - is observable in both directions.
    /// </summary>
    [TestMethod]
    public async Task ClearEmptiesTheOwnerEndorsementAndLockoutAuthorizationValuesWhilePlatformAuthSurvives()
    {
        byte[] ownerAuth = [0x11, 0x22, 0x33];
        byte[] endorsementAuth = [0x44, 0x55, 0x66];
        byte[] lockoutAuth = [0x77, 0x88, 0x99];
        byte[] platformAuth = [0xAA, 0xBB, 0xCC];

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        await RotateAsync(device, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, ownerAuth).ConfigureAwait(false);
        await RotateAsync(device, TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, endorsementAuth).ConfigureAwait(false);
        await RotateAsync(device, TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty, lockoutAuth).ConfigureAwait(false);
        await RotateAsync(device, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, platformAuth).ConfigureAwait(false);

        TpmResult<SetPrimaryPolicyResponse> ownerPolicy = await device.SetPrimaryPolicyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ownerAuth, ComputePolicyAuthValueDigest(), SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(ownerPolicy.IsSuccess, $"Installing the owner policy failed: '{ownerPolicy.ResponseCode}'.");

        TpmResult<ClearResponse> clearResult = await device.ClearAsync(lockoutAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearResult.IsSuccess, $"TPM2_Clear under the rotated lockoutAuth failed: '{clearResult.ResponseCode}'.");

        TpmResult<HierarchyChangeAuthResponse> ownerAfter = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(ownerAfter.IsSuccess, $"ownerAuth must be the Empty Buffer after a clear: '{ownerAfter.ResponseCode}'.");

        TpmResult<HierarchyChangeAuthResponse> endorsementAfter = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(endorsementAfter.IsSuccess, $"endorsementAuth must be the Empty Buffer after a clear: '{endorsementAfter.ResponseCode}'.");

        TpmResult<ClearControlResponse> lockoutAfter = await device.ClearControlWithPasswordAsync(
            TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty, isDisablingClear: true, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            lockoutAfter.IsSuccess,
            $"lockoutAuth must be the Empty Buffer AND usable after a clear - a cleared TPM must not arrive unable to administer its own dictionary-attack state: '{lockoutAfter.ResponseCode}'.");

        TpmResult<ClearControlResponse> platformSurvives = await device.ClearControlWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, platformAuth, isDisablingClear: false, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            platformSurvives.IsSuccess,
            $"platformAuth appears on no clause of clause 24.6.1's effect list, so the value installed before the clear must still authorize: '{platformSurvives.ResponseCode}'.");

        TpmResult<ClearControlResponse> platformNotEmptied = await device.ClearControlWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, isDisablingClear: true, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(platformNotEmptied.IsSuccess, "A clear that emptied platformAuth too would let the Empty Buffer authorize here.");
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), platformNotEmptied.ResponseCode, "authHandle's authorizing session is session 1 of Table 201 (TPM 2.0 Library Part 2, clause 6.6.2); a platformAuth that would also have emptied itself is session-encoded TPM_RC_BAD_AUTH there.");
    }

    /// <summary>
    /// Three more items of clause 24.6.1's effect list, read back through the surfaces that report them: "SET
    /// shEnable and ehEnable", "set Clock to zero ... set resetCount to zero ... set restartCount to zero and
    /// ... set Safe to YES", and "increment pcrUpdateCounter"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 24.6.1). The two enables are driven CLEAR first so their restoration
    /// is observable, and <c>resetCount</c> is non-zero before the clear because the <c>TPM2_Startup</c> that
    /// brought the TPM up already incremented it - without that, zeroing it would be indistinguishable from
    /// leaving it alone. The <c>pcrUpdateCounter</c> increment is what lets an application build a policy
    /// session that a clear is guaranteed to invalidate.
    /// </summary>
    [TestMethod]
    public async Task ClearRestoresTheStorageAndEndorsementEnablesResetsTheClockCountersAndBumpsThePcrUpdateCounter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateClockAndPcrRegistry();

        TpmResult<HierarchyControlResponse> disableStorage = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableStorage.IsSuccess, $"Disabling the storage hierarchy failed: '{disableStorage.ResponseCode}'.");

        TpmResult<HierarchyControlResponse> disableEndorsement = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_ENDORSEMENT, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableEndorsement.IsSuccess, $"Disabling the endorsement hierarchy failed: '{disableEndorsement.ResponseCode}'.");

        var enablesBefore = (TpmaStartupClear)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_STARTUP_CLEAR).ConfigureAwait(false);
        Assert.IsFalse(enablesBefore.HasFlag(TpmaStartupClear.SH_ENABLE), "shEnable must be CLEAR before the clear, or its restoration proves nothing.");
        Assert.IsFalse(enablesBefore.HasFlag(TpmaStartupClear.EH_ENABLE), "ehEnable must be CLEAR before the clear, or its restoration proves nothing.");

        TpmsClockInfo clockBefore = await ReadClockInfoAsync(device, registry, pool).ConfigureAwait(false);
        Assert.AreNotEqual(0u, clockBefore.ResetCount, "The TPM2_Startup that brought this TPM up must have advanced resetCount, or zeroing it would be unobservable.");

        uint pcrCounterBefore = await ReadPcrUpdateCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<ClearResponse> clearResult = await device.ClearAsync(ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearResult.IsSuccess, $"TPM2_Clear failed: '{clearResult.ResponseCode}'.");

        var enablesAfter = (TpmaStartupClear)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_STARTUP_CLEAR).ConfigureAwait(false);
        Assert.IsTrue(enablesAfter.HasFlag(TpmaStartupClear.SH_ENABLE), "A clear must SET shEnable.");
        Assert.IsTrue(enablesAfter.HasFlag(TpmaStartupClear.EH_ENABLE), "A clear must SET ehEnable.");
        Assert.IsTrue(enablesAfter.HasFlag(TpmaStartupClear.PH_ENABLE), "A clear must leave the platform hierarchy's enable alone.");

        TpmsClockInfo clockAfter = await ReadClockInfoAsync(device, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(0u, clockAfter.ResetCount, "A clear must set resetCount to zero.");
        Assert.AreEqual(0u, clockAfter.RestartCount, "A clear must set restartCount to zero.");
        Assert.IsTrue(clockAfter.Safe.IsYes, "A clear must set Safe to YES.");

        uint pcrCounterAfter = await ReadPcrUpdateCounterAsync(device, registry, pool).ConfigureAwait(false);
        Assert.IsGreaterThan(pcrCounterBefore, pcrCounterAfter, "A clear must increment pcrUpdateCounter, which is what invalidates a TPM2_PolicyPCR-bound session across it.");
    }

    /// <summary>
    /// The enable gate reaches the commands that use a hierarchy, not just the ones that administer it: with
    /// <c>shEnable</c> CLEAR no primary object may be created under the storage hierarchy, because neither its
    /// authorization value nor its policy can authorize anything
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 10.2, Table 8) and the handle names an unavailable hierarchy
    /// (<c>TPM_RC_HIERARCHY</c>, the code Part 3, clause 24.3.1 states for the same condition). Recovery is
    /// exclusively Platform Authorization's: "When shEnable is CLEAR, it can only be SET
    /// (TPM2_HierarchyControl()) if Platform Authorization is provided" (Part 1, clause 10.4), and the storage
    /// hierarchy's own attempt to re-enable itself cannot even reach that rule - the availability gate answers
    /// first, which is what makes the privilege asymmetry structural rather than a check that could be forgotten.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryUnderADisabledHierarchyIsRefusedUntilPlatformAuthorizationReEnablesIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateKeyRegistry();

        TpmResult<CreatePrimaryResponse> beforeDisable = await CreateOwnerPrimaryAsync(device, registry, pool).ConfigureAwait(false);
        Assert.IsTrue(beforeDisable.IsSuccess, $"CreatePrimary must succeed while the storage hierarchy is enabled: '{beforeDisable.ResponseCode}'.");
        using(beforeDisable.Value)
        {
            _ = await device.FlushContextAsync(beforeDisable.Value.ObjectHandle.Value, CancellationToken.None).ConfigureAwait(false);
        }

        TpmResult<HierarchyControlResponse> disableResult = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"The storage hierarchy's own authorization must be able to disable it: '{disableResult.ResponseCode}'.");

        TpmResult<CreatePrimaryResponse> whileDisabled = await CreateOwnerPrimaryAsync(device, registry, pool).ConfigureAwait(false);
        Assert.IsFalse(whileDisabled.IsSuccess, "No primary object may be created under a disabled hierarchy.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_HIERARCHY, whileDisabled.ResponseCode);

        //The storage hierarchy's own attempt to SET its enable again: refused because a CLEAR enable already bars
        //its authorization value, so the attempt never reaches the "only platform may SET this" rule.
        TpmResult<HierarchyControlResponse> ownAttempt = await HierarchyControlWithPasswordAsync(
            device, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TpmiYesNo.Yes).ConfigureAwait(false);
        Assert.IsFalse(ownAttempt.IsSuccess, "A disabled hierarchy must not be able to re-enable itself.");
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), ownAttempt.ResponseCode,
            "The availability gate of Part 1, clause 10.2 answers before the command's own authority rule, so the refusal names the hierarchy rather than the authorization type.");

        TpmResult<HierarchyControlResponse> platformEnable = await device.EnableHierarchyWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(platformEnable.IsSuccess, $"Platform Authorization must be able to SET shEnable: '{platformEnable.ResponseCode}'.");

        TpmResult<CreatePrimaryResponse> afterEnable = await CreateOwnerPrimaryAsync(device, registry, pool).ConfigureAwait(false);
        Assert.IsTrue(afterEnable.IsSuccess, $"CreatePrimary must work again once the hierarchy is enabled: '{afterEnable.ResponseCode}'.");
        using(afterEnable.Value)
        {
            _ = await device.FlushContextAsync(afterEnable.Value.ObjectHandle.Value, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Every authorization that is not applicable to the enable being written is refused with
    /// <c>TPM_RC_AUTH_TYPE</c> - the authorization was supplied correctly but is the wrong KIND for the action.
    /// Part 3, clause 24.2.1 states the permitted combinations rather than a response code: phEnable and
    /// phEnableNV move only "if platformAuth/platformPolicy is provided", shEnable "if either
    /// platformAuth/platformPolicy or ownerAuth/ownerPolicy is provided", ehEnable "if either
    /// platformAuth/platformPolicy or endorsementAuth/endorsementPolicy is provided"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>); the code asserted here is an inference from that clause's own structure and is
    /// deliberately distinct from the <c>TPM_RC_AUTH_FAIL</c> its sibling <c>TPM2_ClearControl</c> answers for a
    /// comparable disallowed combination, so a caller can tell a wrong-kind authorization from a wrong value.
    /// Every hierarchy is enabled throughout, so nothing here is pre-empted by the availability gate.
    /// </summary>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="enable">The enable being written.</param>
    /// <param name="isSetting">Whether the write SETs the enable.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, (uint)TpmRh.TPM_RH_ENDORSEMENT, false, DisplayName = "owner may not CLEAR ehEnable")]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, (uint)TpmRh.TPM_RH_OWNER, false, DisplayName = "endorsement may not CLEAR shEnable")]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, (uint)TpmRh.TPM_RH_OWNER, true, DisplayName = "endorsement may not SET shEnable")]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, (uint)TpmRh.TPM_RH_PLATFORM, false, DisplayName = "owner may not CLEAR phEnable")]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, (uint)TpmRh.TPM_RH_PLATFORM_NV, false, DisplayName = "endorsement may not CLEAR phEnableNV")]
    public async Task HierarchyControlRefusesAnAuthorizationThatIsNotApplicableToTheEnableBeingWritten(uint authHandle, uint enable, bool isSetting)
    {
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyControlResponse> result = await HierarchyControlWithPasswordAsync(
            device, (TpmRh)authHandle, ReadOnlyMemory<byte>.Empty, (TpmRh)enable, isSetting ? TpmiYesNo.Yes : TpmiYesNo.No).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "An authorization that is not applicable to the target enable must never write it.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode);

        //Non-vacuity: the SAME enable moves when the applicable authorization is supplied. SETting is the
        //platform's alone; CLEARing is open to the named hierarchy itself except for the two platform enables.
        TpmRh applicableAuth = isSetting
            ? TpmRh.TPM_RH_PLATFORM
            : (TpmRh)enable switch
            {
                TpmRh.TPM_RH_PLATFORM or TpmRh.TPM_RH_PLATFORM_NV => TpmRh.TPM_RH_PLATFORM,
                TpmRh named => named
            };

        TpmResult<HierarchyControlResponse> applicable = await HierarchyControlWithPasswordAsync(
            device, applicableAuth, ReadOnlyMemory<byte>.Empty, (TpmRh)enable, isSetting ? TpmiYesNo.Yes : TpmiYesNo.No).ConfigureAwait(false);
        Assert.IsTrue(applicable.IsSuccess, $"The applicable authorization must write the same enable: '{applicable.ResponseCode}'.");
    }

    /// <summary>
    /// CLEARing <c>phEnable</c> is a one-way door for the whole command surface: "phEnable may not be SET using
    /// this command" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 3, clause 24.2.1) and "When phEnable is CLEAR, a _TPM_Init is required
    /// to SET it. On any _TPM_Init, phEnable is SET" (Part 1, clause 10.3). Disabling the platform hierarchy
    /// therefore also removes the only authorization that could re-enable the storage hierarchy, which the
    /// middle leg proves; a full <c>TPM2_Startup</c> reset then restores all four enables at once, "phEnable
    /// shall be SET" from the every-startup list plus "phEnableNV, shEnable and ehEnable shall be SET" from the
    /// TPM Reset list (Part 3, clause 9.3).
    /// </summary>
    [TestMethod]
    public async Task ClearingThePlatformEnableIsOneWayUntilAStartupResetRestoresAllFourEnables()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyControlResponse> disableStorage = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableStorage.IsSuccess, $"Disabling the storage hierarchy failed: '{disableStorage.ResponseCode}'.");

        TpmResult<HierarchyControlResponse> disablePlatform = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_PLATFORM, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disablePlatform.IsSuccess, $"Platform Authorization must be able to CLEAR its own enable: '{disablePlatform.ResponseCode}'.");

        var enablesWhileDisabled = (TpmaStartupClear)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_STARTUP_CLEAR).ConfigureAwait(false);
        Assert.IsFalse(enablesWhileDisabled.HasFlag(TpmaStartupClear.PH_ENABLE), "phEnable must read CLEAR once the platform hierarchy is disabled.");
        Assert.IsFalse(enablesWhileDisabled.HasFlag(TpmaStartupClear.SH_ENABLE), "shEnable must read CLEAR once the storage hierarchy is disabled.");

        TpmResult<HierarchyControlResponse> selfEnable = await HierarchyControlWithPasswordAsync(
            device, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_PLATFORM, TpmiYesNo.Yes).ConfigureAwait(false);
        Assert.IsFalse(selfEnable.IsSuccess, "No command may SET phEnable.");
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), selfEnable.ResponseCode,
            "platformAuth cannot authorize anything while phEnable is CLEAR, so the attempt is refused by the availability gate.");

        TpmResult<HierarchyControlResponse> rescueStorage = await device.EnableHierarchyWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(rescueStorage.IsSuccess, "Disabling the platform hierarchy also removes the only authorization that could re-enable the storage one.");
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), rescueStorage.ResponseCode, "Table 193: authHandle is TPM2_HierarchyControl()'s sole handle (handle 1); the availability gate CLEAR by the platform's own disable is handle-encoded TPM_RC_HIERARCHY at index 0.");

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        var enablesAfterReset = (TpmaStartupClear)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_STARTUP_CLEAR).ConfigureAwait(false);
        Assert.IsTrue(enablesAfterReset.HasFlag(TpmaStartupClear.PH_ENABLE), "A TPM Reset must SET phEnable.");
        Assert.IsTrue(enablesAfterReset.HasFlag(TpmaStartupClear.SH_ENABLE), "A TPM Reset must SET shEnable.");
        Assert.IsTrue(enablesAfterReset.HasFlag(TpmaStartupClear.EH_ENABLE), "A TPM Reset must SET ehEnable.");
        Assert.IsTrue(enablesAfterReset.HasFlag(TpmaStartupClear.PH_ENABLE_NV), "A TPM Reset must SET phEnableNV.");

        TpmResult<HierarchyControlResponse> afterReset = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_PLATFORM_NV, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            afterReset.IsSuccess,
            $"Platform Authorization must work again after the reset, or the restored enable would be a report rather than a state change: '{afterReset.ResponseCode}'.");
    }

    /// <summary>
    /// platformAuth is a per-boot secret rather than a persistent one: "On TPM Reset or TPM Restart, platformAuth
    /// is set to an EmptyAuth, and platformPolicy is set to an Empty Policy"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 10.3), which Part 3, clause 9.3 states as a bullet of its own on the
    /// TPM Reset list, "platformAuth and platformPolicy shall be set to the Empty Buffer". A value platform
    /// firmware installs therefore stops authorizing at the next power cycle and the Empty Buffer authorizes
    /// again - the opposite of <c>ownerAuth</c> and <c>lockoutAuth</c>, which survive every reset and only
    /// <c>TPM2_Clear</c> returns (clause 24.6.1, whose effect list never mentions platformAuth). The middle leg
    /// is what makes the last two non-vacuous: the installed value must genuinely have displaced the Empty Buffer
    /// before the reset, or "the Empty Buffer authorizes afterwards" would also be true of a TPM that never
    /// changed at all.
    /// </summary>
    [TestMethod]
    public async Task ATpmResetReturnsPlatformAuthToTheEmptyBufferSoTheInstalledValueStopsAuthorizing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyChangeAuthResponse> install = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            install.IsSuccess,
            $"Installing a platform authorization value must succeed: '{(install.IsTpmError ? install.ResponseCode : default)}'.");

        TpmResult<HierarchyChangeAuthResponse> emptyBeforeReset = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(emptyBeforeReset.IsSuccess, "The Empty Buffer must stop authorizing once a platform authorization value is installed.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0),
            emptyBeforeReset.IsTpmError ? emptyBeforeReset.ResponseCode : default,
            "platformAuth is a dictionary-attack exempt permanent-entity value (Part 1, clause 16.8.1), so a mismatch is the plain TPM_RC_BAD_AUTH.");

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        TpmResult<HierarchyChangeAuthResponse> installedAfterReset = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, FirstAuth, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(installedAfterReset.IsSuccess, "A TPM Reset must discard the installed platform authorization value.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0),
            installedAfterReset.IsTpmError ? installedAfterReset.ResponseCode : default,
            "Nothing of the installed value survives the reset, so offering it is an ordinary mismatch rather than a refusal of the hierarchy itself.");

        TpmResult<HierarchyChangeAuthResponse> emptyAfterReset = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            emptyAfterReset.IsSuccess,
            $"The Empty Buffer must authorize the platform hierarchy again after a TPM Reset: '{(emptyAfterReset.IsTpmError ? emptyAfterReset.ResponseCode : default)}'.");
    }

    /// <summary>
    /// A TPM Restart - <c>TPM2_Shutdown(STATE)</c>, then <c>_TPM_Init</c>, then <c>TPM2_Startup(CLEAR)</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 9.3) - restores exactly what a TPM Reset restores for this command
    /// family, and clause 9.3 spells it out on the Restart list itself rather than by reference to the Reset
    /// one: "phEnableNV, shEnable and ehEnable shall be SET" and "platformAuth and platformPolicy shall be set to
    /// the Empty Buffer", joined by the every-startup rule "On any TPM2_Startup(), phEnable shall be SET". Only a
    /// TPM Resume carries any of it forward. The counter readback pins that this sequence really took the Restart
    /// path: a Restart increments <c>restartCount</c> and leaves <c>resetCount</c> alone, where a Reset would do
    /// the reverse (Part 1, clauses 33.4-33.5), so a TPM that answered a Reset here would fail that assertion
    /// rather than pass the enable checks for the wrong reason.
    /// </summary>
    [TestMethod]
    public async Task ATpmRestartRestoresAllFourEnablesAndEmptiesPlatformAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateClockAndPcrRegistry();

        TpmResult<HierarchyChangeAuthResponse> install = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            install.IsSuccess,
            $"Installing a platform authorization value must succeed: '{(install.IsTpmError ? install.ResponseCode : default)}'.");

        //Each disable is authorized by the value just installed, so the platform authorization is proven live
        //before the restart discards it. The platform's own enable goes last: CLEARing it removes the very
        //authorization the other three disables depend on.
        TpmRh[] enablesToDisable = [TpmRh.TPM_RH_OWNER, TpmRh.TPM_RH_ENDORSEMENT, TpmRh.TPM_RH_PLATFORM_NV, TpmRh.TPM_RH_PLATFORM];
        foreach(TpmRh enable in enablesToDisable)
        {
            TpmResult<HierarchyControlResponse> disabled = await device.DisableHierarchyWithPasswordAsync(
                TpmRh.TPM_RH_PLATFORM, FirstAuth, enable, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                disabled.IsSuccess,
                $"Disabling '{enable}' under the installed platform authorization value must succeed: '{(disabled.IsTpmError ? disabled.ResponseCode : default)}'.");
        }

        var enablesBefore = (TpmaStartupClear)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_STARTUP_CLEAR).ConfigureAwait(false);
        Assert.IsFalse(enablesBefore.HasFlag(TpmaStartupClear.PH_ENABLE), "phEnable must be CLEAR before the restart, or its restoration proves nothing.");
        Assert.IsFalse(enablesBefore.HasFlag(TpmaStartupClear.SH_ENABLE), "shEnable must be CLEAR before the restart, or its restoration proves nothing.");
        Assert.IsFalse(enablesBefore.HasFlag(TpmaStartupClear.EH_ENABLE), "ehEnable must be CLEAR before the restart, or its restoration proves nothing.");
        Assert.IsFalse(enablesBefore.HasFlag(TpmaStartupClear.PH_ENABLE_NV), "phEnableNV must be CLEAR before the restart, or its restoration proves nothing.");

        TpmsClockInfo clockBefore = await ReadClockInfoAsync(device, registry, pool).ConfigureAwait(false);

        await IssueShutdownStateAsync(simulator, pool).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        TpmsClockInfo clockAfter = await ReadClockInfoAsync(device, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(clockBefore.ResetCount, clockAfter.ResetCount, "A TPM Restart leaves resetCount alone, which is what distinguishes it from a TPM Reset.");
        Assert.AreEqual(clockBefore.RestartCount + 1u, clockAfter.RestartCount, "A TPM Restart increments restartCount.");

        var enablesAfter = (TpmaStartupClear)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_STARTUP_CLEAR).ConfigureAwait(false);
        Assert.IsTrue(enablesAfter.HasFlag(TpmaStartupClear.PH_ENABLE), "A TPM Restart must SET phEnable, on the every-startup bullet.");
        Assert.IsTrue(enablesAfter.HasFlag(TpmaStartupClear.SH_ENABLE), "A TPM Restart must SET shEnable, on its own bullet list.");
        Assert.IsTrue(enablesAfter.HasFlag(TpmaStartupClear.EH_ENABLE), "A TPM Restart must SET ehEnable, on its own bullet list.");
        Assert.IsTrue(enablesAfter.HasFlag(TpmaStartupClear.PH_ENABLE_NV), "A TPM Restart must SET phEnableNV, on its own bullet list.");

        TpmResult<HierarchyChangeAuthResponse> installedAfterRestart = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, FirstAuth, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(installedAfterRestart.IsSuccess, "A TPM Restart must empty platformAuth exactly as a TPM Reset does.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0),
            installedAfterRestart.IsTpmError ? installedAfterRestart.ResponseCode : default,
            "The platform hierarchy is enabled again, so the refusal is the value mismatch rather than an unavailable hierarchy.");

        TpmResult<HierarchyChangeAuthResponse> emptyAfterRestart = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, SecondAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            emptyAfterRestart.IsSuccess,
            $"The Empty Buffer must authorize the platform hierarchy again after a TPM Restart: '{(emptyAfterRestart.IsTpmError ? emptyAfterRestart.ResponseCode : default)}'.");
    }

    /// <summary>
    /// <c>TPM2_SetPrimaryPolicy</c>'s two parameters must agree: "an authorization policy digest may be the
    /// Empty Buffer. If hashAlg is TPM_ALG_NULL, then this shall be an Empty Buffer" and "If the authPolicy is
    /// an Empty Buffer, then this field shall be TPM_ALG_NULL"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 24.3.2), with the size rule stated as "When hashAlg is not
    /// TPM_ALG_NULL, if the size of authPolicy is not consistent with the hash algorithm, the TPM returns
    /// TPM_RC_SIZE" (clause 24.3.1). One rule covers both directions because the null algorithm's digest size
    /// is zero, so each ladder rung below is a genuine size disagreement rather than a special case.
    /// </summary>
    [TestMethod]
    public async Task SetPrimaryPolicyRefusesEveryDigestWhoseSizeDisagreesWithItsHashAlgorithm()
    {
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] fullWidthDigest = ComputePolicyAuthValueDigest();
        byte[] shortDigest = fullWidthDigest.AsSpan(0, Sha256DigestSize - 1).ToArray();

        TpmResult<SetPrimaryPolicyResponse> digestWithNullAlg = await device.SetPrimaryPolicyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, fullWidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), digestWithNullAlg.ResponseCode,
            "A non-empty digest offered with TPM_ALG_NULL disagrees with the null algorithm's zero digest size.");

        TpmResult<SetPrimaryPolicyResponse> emptyWithRealAlg = await device.SetPrimaryPolicyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), emptyWithRealAlg.ResponseCode,
            "An Empty Buffer offered with a real algorithm disagrees with that algorithm's digest size.");

        TpmResult<SetPrimaryPolicyResponse> shortWithRealAlg = await device.SetPrimaryPolicyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, shortDigest, SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), shortWithRealAlg.ResponseCode, "A digest one octet short of the algorithm's width must be refused.");

        TpmResult<SetPrimaryPolicyResponse> consistent = await device.SetPrimaryPolicyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, fullWidthDigest, SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(consistent.IsSuccess, $"A digest of exactly the algorithm's width must be accepted: '{consistent.ResponseCode}'.");

        TpmResult<SetPrimaryPolicyResponse> emptyWithNullAlg = await device.SetPrimaryPolicyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_NULL, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            emptyWithNullAlg.IsSuccess,
            $"The Empty Buffer with TPM_ALG_NULL is the documented way back to a policy-less hierarchy: '{emptyWithNullAlg.ResponseCode}'.");
    }

    /// <summary>
    /// <c>TPMI_RH_HIERARCHY_POLICY</c> is the only handle-interface type in this family that also admits
    /// <c>TPMI_RH_ACT</c> ("TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPMI_RH_ACT or
    /// TPM_RH_PLATFORM+{PP}",
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 24.3.2), and "On TPMs implementing Authenticated Countdown Timers
    /// (ACT), this command may also be used to set the authorization policy for an ACT" (clause 24.3.1). This
    /// library implements no ACT, so an ACT handle must be refused as an out-of-range value for the interface
    /// type rather than silently accepted into a policy slot that does not exist.
    /// </summary>
    [TestMethod]
    public async Task SetPrimaryPolicyRefusesAnAuthenticatedCountdownTimerHandleWithValue()
    {
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<SetPrimaryPolicyResponse> result = await device.SetPrimaryPolicyWithPasswordAsync(
            (TpmRh)ActHandle, ReadOnlyMemory<byte>.Empty, ComputePolicyAuthValueDigest(), SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "An unmodelled ACT handle must not be accepted as a policy target.");
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode, "Table 195: authHandle is TPM2_SetPrimaryPolicy()'s sole handle (handle 1); an authenticated but unmodelled ACT handle is handle-encoded TPM_RC_VALUE at index 0.");
    }

    /// <summary>
    /// The closure this command exists to provide, proven in both directions. A hierarchy's policy path starts
    /// disabled: "When the authPolicy is empty, it cannot match any policyDigest value so the use of authPolicy
    /// is disabled" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 1, clause 10.2, Table 8), so a policy session offered as the
    /// authorizer of <c>TPM2_PolicySecret</c> against a policy-less hierarchy is answered with
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> - the entity has no policy path at all, which is a different answer from a
    /// policy that failed to match. <c>TPM2_SetPrimaryPolicy</c> installs one ("The policy that is changed is
    /// the policy associated with authHandle", Part 3, clause 24.3.1) and the same session then authorizes;
    /// a session whose accumulated digest reaches a DIFFERENT value is <c>TPM_RC_POLICY_FAIL</c>; and
    /// reinstalling the Empty Buffer closes the path again.
    /// </summary>
    [TestMethod]
    public async Task SetPrimaryPolicyOpensAndClosesAHierarchysPolicySessionAuthorizationPath()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePolicyRegistry();

        TpmRcConstants beforeInstall = await AuthorizeOwnerPolicySecretOverAPolicySessionAsync(
            device, registry, pool, foldCommandCodeFirst: false).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, beforeInstall,
            "A policy-less hierarchy is outside the policy path entirely, so a policy-session authorizer is refused before its digest is ever compared.");

        TpmResult<SetPrimaryPolicyResponse> install = await device.SetPrimaryPolicyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, ComputePolicyAuthValueDigest(), SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(install.IsSuccess, $"Installing the owner policy failed: '{install.ResponseCode}'.");

        TpmRcConstants satisfied = await AuthorizeOwnerPolicySecretOverAPolicySessionAsync(
            device, registry, pool, foldCommandCodeFirst: false).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, satisfied,
            "A policy session whose accumulated digest reproduces the installed policy must authorize the hierarchy.");

        TpmRcConstants unsatisfied = await AuthorizeOwnerPolicySecretOverAPolicySessionAsync(
            device, registry, pool, foldCommandCodeFirst: true).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), unsatisfied,
            "A session that reaches a different digest fails the comparison, which is a distinct answer from having no policy path at all — CheckAuthSession's outcome wrap, the sole authorizing session, slot 0.");

        TpmResult<SetPrimaryPolicyResponse> uninstall = await device.SetPrimaryPolicyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_NULL, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(uninstall.IsSuccess, $"Reinstalling the Empty Buffer failed: '{uninstall.ResponseCode}'.");

        TpmRcConstants afterUninstall = await AuthorizeOwnerPolicySecretOverAPolicySessionAsync(
            device, registry, pool, foldCommandCodeFirst: false).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, afterUninstall,
            "Emptying the policy must close the path again - the Empty Buffer disables policy authorization rather than matching an empty session digest.");
    }

    /// <summary>
    /// The two <c>TPM_CAP_TPM_PROPERTIES</c> rows that report hierarchy state track it rather than reporting
    /// constants: <c>TPMA_PERMANENT</c>'s <c>ownerAuthSet</c>/<c>endorsementAuthSet</c>/<c>lockoutAuthSet</c>
    /// and <c>disableClear</c>, and <c>TPMA_STARTUP_CLEAR</c>'s four enables
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clauses 8.6 and 8.7). These are the only surface through which a caller can
    /// observe that a hierarchy has been disabled at all, since a disabled hierarchy refuses both its
    /// authorization value and its policy and nothing else in the response surface distinguishes that from a
    /// wrong secret. Every bit is driven in both directions by the five commands themselves.
    /// </summary>
    [TestMethod]
    public async Task PermanentAndStartupClearPropertiesTrackHierarchyStateAcrossRotationControlAndClear()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        var atManufacture = (TpmaPermanent)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_PERMANENT).ConfigureAwait(false);
        Assert.IsFalse(atManufacture.HasFlag(TpmaPermanent.OWNER_AUTH_SET), "A freshly started TPM's ownerAuth is the Empty Buffer.");
        Assert.IsFalse(atManufacture.HasFlag(TpmaPermanent.ENDORSEMENT_AUTH_SET), "A freshly started TPM's endorsementAuth is the Empty Buffer.");
        Assert.IsFalse(atManufacture.HasFlag(TpmaPermanent.LOCKOUT_AUTH_SET), "A freshly started TPM's lockoutAuth is the Empty Buffer.");
        Assert.IsFalse(atManufacture.HasFlag(TpmaPermanent.DISABLE_CLEAR), "disableClear is CLEAR at manufacture, so TPM2_Clear is permitted out of the box.");

        var enablesAtStart = (TpmaStartupClear)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_STARTUP_CLEAR).ConfigureAwait(false);
        Assert.IsTrue(enablesAtStart.HasFlag(TpmaStartupClear.PH_ENABLE), "phEnable is SET on every TPM2_Startup.");
        Assert.IsTrue(enablesAtStart.HasFlag(TpmaStartupClear.SH_ENABLE), "shEnable is SET on a TPM Reset.");
        Assert.IsTrue(enablesAtStart.HasFlag(TpmaStartupClear.EH_ENABLE), "ehEnable is SET on a TPM Reset.");
        Assert.IsTrue(enablesAtStart.HasFlag(TpmaStartupClear.PH_ENABLE_NV), "phEnableNV is SET on a TPM Reset.");

        await RotateAsync(device, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstAuth).ConfigureAwait(false);
        await RotateAsync(device, TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, FirstAuth).ConfigureAwait(false);
        await RotateAsync(device, TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty, FirstAuth).ConfigureAwait(false);

        var afterRotation = (TpmaPermanent)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_PERMANENT).ConfigureAwait(false);
        Assert.IsTrue(afterRotation.HasFlag(TpmaPermanent.OWNER_AUTH_SET), "TPM2_HierarchyChangeAuth on the owner hierarchy must show in TPMA_PERMANENT.");
        Assert.IsTrue(afterRotation.HasFlag(TpmaPermanent.ENDORSEMENT_AUTH_SET), "TPM2_HierarchyChangeAuth on the endorsement hierarchy must show in TPMA_PERMANENT.");
        Assert.IsTrue(afterRotation.HasFlag(TpmaPermanent.LOCKOUT_AUTH_SET), "TPM2_HierarchyChangeAuth on the lockout entity must show in TPMA_PERMANENT.");

        TpmResult<ClearControlResponse> setControl = await device.ClearControlWithPasswordAsync(
            TpmRh.TPM_RH_LOCKOUT, FirstAuth, isDisablingClear: true, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(setControl.IsSuccess, $"Setting disableClear failed: '{setControl.ResponseCode}'.");

        var afterControl = (TpmaPermanent)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_PERMANENT).ConfigureAwait(false);
        Assert.IsTrue(afterControl.HasFlag(TpmaPermanent.DISABLE_CLEAR), "TPM2_ClearControl must show in TPMA_PERMANENT.");

        TpmResult<ClearControlResponse> clearControl = await device.ClearControlWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, isDisablingClear: false, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearControl.IsSuccess, $"Clearing disableClear failed: '{clearControl.ResponseCode}'.");

        TpmResult<HierarchyControlResponse> disableStorage = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, FirstAuth, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableStorage.IsSuccess, $"Disabling the storage hierarchy failed: '{disableStorage.ResponseCode}'.");

        var afterDisable = (TpmaStartupClear)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_STARTUP_CLEAR).ConfigureAwait(false);
        Assert.IsFalse(afterDisable.HasFlag(TpmaStartupClear.SH_ENABLE), "TPM2_HierarchyControl must show in TPMA_STARTUP_CLEAR.");
        Assert.IsTrue(afterDisable.HasFlag(TpmaStartupClear.EH_ENABLE), "Only the named enable may move.");

        TpmResult<ClearResponse> clearResult = await device.ClearAsync(FirstAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearResult.IsSuccess, $"TPM2_Clear failed: '{clearResult.ResponseCode}'.");

        var afterClear = (TpmaPermanent)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_PERMANENT).ConfigureAwait(false);
        Assert.IsFalse(afterClear.HasFlag(TpmaPermanent.OWNER_AUTH_SET), "A clear empties ownerAuth, which the property must report.");
        Assert.IsFalse(afterClear.HasFlag(TpmaPermanent.ENDORSEMENT_AUTH_SET), "A clear empties endorsementAuth, which the property must report.");
        Assert.IsFalse(afterClear.HasFlag(TpmaPermanent.LOCKOUT_AUTH_SET), "A clear empties lockoutAuth, which the property must report.");

        var enablesAfterClear = (TpmaStartupClear)await ReadPropertyAsync(device, pool, TpmPtConstants.TPM_PT_STARTUP_CLEAR).ConfigureAwait(false);
        Assert.IsTrue(enablesAfterClear.HasFlag(TpmaStartupClear.SH_ENABLE), "A clear SETs shEnable, which the property must report.");
    }

    /// <summary>
    /// <c>@primaryHandle</c> is <c>TPM2_CreatePrimary</c>'s own USER-role authorization handle (TPM 2.0 Library
    /// Part 3, clause 24.1, Table 191), so once the owner hierarchy carries a real authorization value a
    /// WRONG password must refuse the command exactly as every other hierarchy command in this family refuses
    /// one: the bare, dictionary-attack-uncharged <c>TPM_RC_BAD_AUTH</c> a permanent entity's authValue
    /// mismatch answers (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 1, clause 16.8.1), never the session-encoded code an object slot
    /// answers for the same kind of mismatch. The CORRECT password must still create. Both directions are
    /// proven across all four modelled CreatePrimary templates - ECC and RSA signing keys, ECC and RSA
    /// restricted storage parents - because each is dispatched to its own handler, and verifying some templates'
    /// arms while leaving a sibling's silently auth-blind would be exactly the inconsistent gap this sweep
    /// closes.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryVerifiesTheHierarchyAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateKeyRegistry();

        await RotateAsync(device, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstAuth).ConfigureAwait(false);

        (string TemplateName, Func<CreatePrimaryInput> BuildInput)[] templates =
        [
            ("the ECC signing key template", () => CreatePrimaryInput.ForEccSigningKey(
                TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool)),
            ("the RSA signing key template", () => CreatePrimaryInput.ForRsaSigningKey(
                TpmRh.TPM_RH_OWNER, password: null, Rsa2048KeyBits, TpmtRsaScheme.Null, pool)),
            ("the ECC storage parent template", () => CreatePrimaryInput.ForEccStorageParent(
                TpmRh.TPM_RH_OWNER, authPassword: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool)),
            ("the RSA storage parent template", () => CreateRsaStorageParentInput(TpmRh.TPM_RH_OWNER, password: null, pool)),
        ];

        foreach((string templateName, Func<CreatePrimaryInput> buildInput) in templates)
        {
            using CreatePrimaryInput input = buildInput();

            TpmResult<TpmDictionaryAttackParameters> before = await device.GetDictionaryAttackParametersAsync(
                pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(before.IsSuccess, $"Reading the dictionary-attack parameters failed: '{before.ResponseCode}'.");

            using TpmPasswordSession wrongAuth = TpmPasswordSession.Create(WrongAuth, pool);
            TpmResult<CreatePrimaryResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                device, input, [wrongAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(wrongResult.IsSuccess, $"A wrong owner hierarchy password must not create a primary under {templateName}.");
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), wrongResult.ResponseCode,
                $"The owner hierarchy is a dictionary-attack exempt permanent entity, so a mismatch under {templateName} fails the primaryHandle authorization, session 1 of TPM2_CreatePrimary()'s own command table.");

            TpmResult<TpmDictionaryAttackParameters> afterWrong = await device.GetDictionaryAttackParametersAsync(
                pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                before.Value.LockoutCounter, afterWrong.Value.LockoutCounter,
                $"A wrong owner hierarchy password must never advance the dictionary-attack lockout counter (under {templateName}).");

            using TpmPasswordSession correctAuth = TpmPasswordSession.Create(FirstAuth, pool);
            TpmResult<CreatePrimaryResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                device, input, [correctAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(correctResult.IsSuccess, $"The correct owner hierarchy password must create a primary under {templateName}: '{correctResult.ResponseCode}'.");

            using(correctResult.Value)
            {
                _ = await device.FlushContextAsync(correctResult.Value.ObjectHandle.Value, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// The null hierarchy has no authValue slot of its own - its authorization value is structurally empty
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 10.2), a different footing from a rotated-then-emptied hierarchy's
    /// live Empty Buffer VALUE. <c>TPM2_CreatePrimary</c>'s null-hierarchy arm compares the supplied password,
    /// trailing zeros stripped (clause 16.6.4.3), against that structural emptiness: any non-empty remainder
    /// answers the bare, dictionary-attack-uncharged <c>TPM_RC_BAD_AUTH</c> a permanent entity's mismatch
    /// answers (clause 16.8.1) - TPM_RH_NULL included, since only lockoutAuth carries the one-strike exception
    /// - while the Empty Buffer still creates.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryUnderTheNullHierarchyRequiresEmptyAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateKeyRegistry();

        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_NULL, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool);

        TpmResult<TpmDictionaryAttackParameters> before = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"Reading the dictionary-attack parameters failed: '{before.ResponseCode}'.");

        using TpmPasswordSession nonEmptyAuth = TpmPasswordSession.Create(WrongAuth, pool);
        TpmResult<CreatePrimaryResponse> nonEmptyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, input, [nonEmptyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(nonEmptyResult.IsSuccess, "A non-empty password offered against the null hierarchy must never authorize CreatePrimary.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), nonEmptyResult.ResponseCode,
            "The null hierarchy's structurally empty authValue mismatches any non-empty supplied password at the primaryHandle authorization, session 1 of TPM2_CreatePrimary()'s own command table.");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, afterWrong.Value.LockoutCounter,
            "TPM_RH_NULL is a permanent entity, so a mismatch here must never advance the dictionary-attack lockout counter.");

        using TpmPasswordSession emptyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> emptyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, input, [emptyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(emptyResult.IsSuccess, $"The Empty Buffer must authorize CreatePrimary under the null hierarchy: '{emptyResult.ResponseCode}'.");

        using(emptyResult.Value)
        {
            _ = await device.FlushContextAsync(emptyResult.Value.ObjectHandle.Value, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// TPM 2.0 Library Part 2, clause 9.13, Table 59 (<c>TPMI_RH_HIERARCHY</c>): only <c>TPM_RH_OWNER</c>,
    /// <c>TPM_RH_ENDORSEMENT</c>, <c>TPM_RH_PLATFORM</c> and <c>TPM_RH_NULL</c> admit a primary object.
    /// <c>TPM_RH_LOCKOUT</c> is a permanent handle outside that four-value set, so <c>TPM2_CreatePrimary()</c>
    /// must refuse it with the bare <c>TPM_RC_VALUE</c> before any state moves — no object created.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryWithAnOutOfSetPermanentHandleReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateKeyRegistry();

        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_LOCKOUT, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool);

        using TpmPasswordSession auth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, input, [auth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "TPM_RH_LOCKOUT is outside Table 59's four admitted hierarchy selectors and must never create a primary.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_VALUE, result.ResponseCode,
            $"An out-of-set permanent primaryHandle must be refused with the bare TPM_RC_VALUE (got '{result.ResponseCode}').");
    }

    /// <summary>
    /// TPM 2.0 Library Part 2, clause 9.13, Table 59 (<c>TPMI_RH_HIERARCHY</c>): the four admitted values are
    /// all PERMANENT handles, so a TRANSIENT-range handle offered as <c>primaryHandle</c> — a wholly different
    /// handle type, not merely an out-of-set permanent one — is refused by the very same <c>#TPM_RC_VALUE</c>
    /// gate before any state moves.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryWithATransientRangeHandleReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateKeyRegistry();

        using CreatePrimaryInput input = CreateTransientRangeHandlePrimaryInput(pool);

        using TpmPasswordSession auth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, input, [auth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A transient-range handle is a different handle type entirely from Table 59's four permanent selectors and must never create a primary.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_VALUE, result.ResponseCode,
            $"A transient-range primaryHandle must be refused with the bare TPM_RC_VALUE (got '{result.ResponseCode}').");
    }

    /// <summary>
    /// Composes a CreatePrimary input whose <c>primaryHandle</c> is a raw transient-range handle rather than any
    /// of Table 59's four permanent hierarchy selectors — an otherwise-ordinary ECC signing template, since only
    /// the handle itself is the probe.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateTransientRangeHandlePrimaryInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);

        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT |
            TpmaObject.NO_DA;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg));

        return new CreatePrimaryInput((TpmRh)TpmHandleRanges.TRANSIENT_FIRST, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>
    /// TPM 2.0 Library Part 2, clause 9.13, Table 59 (<c>TPMI_RH_HIERARCHY</c>): <c>TPM_RH_PLATFORM</c> is one of
    /// the four admitted hierarchy selectors, so <c>TPM2_CreatePrimary()</c> must admit it exactly as it admits
    /// <c>TPM_RH_OWNER</c> — a primary object is created and flushable.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryUnderThePlatformHierarchySucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateKeyRegistry();

        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_PLATFORM, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool);

        using TpmPasswordSession auth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, input, [auth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM_RH_PLATFORM is one of Table 59's four admitted hierarchy selectors, so CreatePrimary must succeed under it (got '{result.ResponseCode}').");

        using(result.Value)
        {
            _ = await device.FlushContextAsync(result.Value.ObjectHandle.Value, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <c>TPM_RC_VALUE</c> refusal of <see cref="CreatePrimaryWithAnOutOfSetPermanentHandleReturnsValue"/>
    /// leaves no rented carrier behind: the primaryHandle refusal answers before the parsed
    /// <c>inSensitive</c>/<c>inPublic</c> template is adopted into any state, so every carrier the parse rented
    /// for it is released on the refusing path — the pool balance returns to its pre-command baseline.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryMeteredPoolAcrossTheOutOfSetHandleRefusal()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateKeyRegistry();

        long baseline = trackingPool.OutstandingCount;

        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_LOCKOUT, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool);
        using TpmPasswordSession auth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, input, [auth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode, "The seeding refusal must be the out-of-set-handle TPM_RC_VALUE.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A refused CreatePrimary must leave the pool exactly where it found it: the parsed template rents nothing that survives the refusal.");
    }

    /// <summary>
    /// Rotates <paramref name="hierarchy"/>'s authorization value over the plaintext arm and requires success,
    /// so a test's own setup never silently proceeds against a hierarchy it failed to provision.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="hierarchy">The hierarchy whose authorization value is replaced.</param>
    /// <param name="currentAuth">The hierarchy's current authorization value.</param>
    /// <param name="newAuth">The replacement authorization value.</param>
    private async Task RotateAsync(TpmDevice device, TpmRh hierarchy, ReadOnlyMemory<byte> currentAuth, ReadOnlyMemory<byte> newAuth)
    {
        TpmResult<HierarchyChangeAuthResponse> result = await device.ChangeHierarchyAuthWithPasswordAsync(
            hierarchy, currentAuth, newAuth, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Rotating '{hierarchy}' failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Issues <c>TPM2_HierarchyControl</c> directly over a plaintext session, for the direction/authority
    /// combinations the verb pair deliberately does not offer (a hierarchy re-enabling itself, or the platform
    /// enable being SET).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="authValue">The authorizing hierarchy's authorization value.</param>
    /// <param name="enable">The enable being written.</param>
    /// <param name="state">YES to SET the enable, NO to CLEAR it.</param>
    /// <returns>The command's result.</returns>
    private async Task<TpmResult<HierarchyControlResponse>> HierarchyControlWithPasswordAsync(
        TpmDevice device, TpmRh authHandle, ReadOnlyMemory<byte> authValue, TpmRh enable, TpmiYesNo state)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl);

        using TpmPasswordSession session = TpmPasswordSession.Create(authValue.Span, pool);
        var input = new HierarchyControlInput(authHandle, enable, state);

        return await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts a fresh unbound, unsalted policy session, folds <c>TPM2_PolicyAuthValue</c> (optionally preceded
    /// by <c>TPM2_PolicyCommandCode</c>, which moves the accumulated digest away from the installed policy), and
    /// offers it as the AUTHORIZING session of a <c>TPM2_PolicySecret</c> naming the owner hierarchy.
    /// </summary>
    /// <remarks>
    /// The session is self-referential - it authorizes the assertion it is also the target of - which keeps the
    /// composition to one session; the distinct-sessions case is covered in the sibling secure-channel tests.
    /// <c>TPM2_PolicyAuthValue</c> is folded in every case because Part 3, clause 23.4.1 requires the
    /// authorizing session to have <c>isAuthValueNeeded</c> or <c>isPasswordNeeded</c> SET, so a session without
    /// it would be refused with <c>TPM_RC_MODE</c> before the hierarchy's policy is ever consulted.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="foldCommandCodeFirst">Whether to fold an extra assertion so the accumulated digest differs from the installed policy.</param>
    /// <returns>The response code <c>TPM2_PolicySecret</c> answered with.</returns>
    private async Task<TpmRcConstants> AuthorizeOwnerPolicySecretOverAPolicySessionAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, bool foldCommandCodeFirst)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

            if(foldCommandCodeFirst)
            {
                TpmResult<PolicyCommandCodeResponse> commandCodeResult = await device.PolicyCommandCodeAsync(
                    sessionHandle, TpmCcConstants.TPM_CC_PolicySecret, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");
            }

            TpmResult<PolicyAuthValueResponse> authValueResult = await device.PolicyAuthValueAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

            using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_OWNER, sessionHandle, pool);
            TpmResult<PolicySecretResponse> secretResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            //TpmResult exposes ResponseCode only for a TPM error, so the success leg names TPM_RC_SUCCESS itself
            //rather than reading a property that throws on exactly the outcome this helper's caller most wants to
            //assert.
            if(secretResult.IsSuccess)
            {
                secretResult.Value.Dispose();

                return TpmRcConstants.TPM_RC_SUCCESS;
            }

            return secretResult.ResponseCode;
        }
        finally
        {
            _ = await device.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Transcribes the policy digest a session reaches by folding <c>TPM2_PolicyAuthValue</c> alone:
    /// <c>policyDigest = H(ZeroDigest ‖ TPM_CC_PolicyAuthValue)</c> (TPM 2.0 Library Part 3, clause 23.11), the
    /// value installed as a hierarchy's authorization policy wherever this file needs one a real session can
    /// satisfy.
    /// </summary>
    /// <returns>The policy digest.</returns>
    private static byte[] ComputePolicyAuthValueDigest()
    {
        byte[] digest = new byte[Sha256DigestSize];
        Span<byte> zero = stackalloc byte[Sha256DigestSize];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForAuthValue(zero, SessionAlg, digest, BaseMemoryPool.Shared);

        return digest;
    }

    /// <summary>
    /// Reads one <c>TPM_CAP_TPM_PROPERTIES</c> row through <c>TPM2_GetCapability</c> and returns its value,
    /// requiring the row to be the one asked for so a shifted window never passes silently.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="property">The <c>TPM_PT</c> tag to read.</param>
    /// <returns>The reported value.</returns>
    private async Task<uint> ReadPropertyAsync(TpmDevice device, BaseMemoryPool pool, uint property)
    {
        TpmResponseRegistry registry = new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            device, GetCapabilityInput.ForTpmProperties(property, count: 1), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"GetCapability failed: '{result.ResponseCode}'.");

        using GetCapabilityResponse response = result.Value;
        var properties = response.CapabilityData.TpmProperties;
        Assert.IsNotNull(properties);
        Assert.HasCount(1, properties);
        Assert.AreEqual(property, properties[0].Property, "The capability window must start at the property asked for.");

        return properties[0].Value;
    }

    /// <summary>Reads the TPM's clock information through <c>TPM2_ReadClock</c>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry carrying the ReadClock codec.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The reported clock information.</returns>
    private async Task<TpmsClockInfo> ReadClockInfoAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<ReadClockResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadClockResponse>(
            device, new ReadClockInput(), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadClock failed: '{result.ResponseCode}'.");

        return result.Value.CurrentTime.ClockInfo;
    }

    /// <summary>Reads the <c>pcrUpdateCounter</c> the TPM reports alongside a <c>TPM2_PCR_Read</c>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry carrying the PcrRead codec.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The reported counter.</returns>
    private async Task<uint> ReadPcrUpdateCounterAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using PcrReadInput input = PcrReadInput.ForPcrs(SessionAlg, [0], pool);
        TpmResult<PcrReadResponse> result = await TpmCommandExecutor.ExecuteAsync<PcrReadResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Read failed: '{result.ResponseCode}'.");

        using PcrReadResponse response = result.Value;

        return response.PcrUpdateCounter;
    }

    /// <summary>Creates an ECC P-256 signing primary under the owner hierarchy, returning the raw result for the caller to assert.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary result; on success the caller owns and disposes the response.</returns>
    private async Task<TpmResult<CreatePrimaryResponse>> CreateOwnerPrimaryAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(SessionAlg), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates the standard RSA endorsement-key-shaped decrypt key used as the salted overload's tpmKey.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry, already carrying the CreatePrimary codec.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The created primary key's response; the caller owns and disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Builds a <see cref="CreatePrimaryInput"/> for an RSA restricted storage key, shaped exactly as
    /// <see cref="CreatePrimaryInput.ForEccStorageParent"/> shapes its ECC counterpart (FIXED_TPM |
    /// FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | RESTRICTED | DECRYPT). Constructed directly
    /// because the RSA storage parent has no dedicated <c>CreatePrimaryInput</c> factory the way the ECC one
    /// does: <see cref="Tpm2bPublic.CreateRsaStorageParent"/> otherwise builds only the populated
    /// <c>outPublic</c> form a generated key returns, so passing an empty modulus here reproduces the
    /// caller-supplied, empty-unique <c>inPublic</c> shape a real <c>TPM2_CreatePrimary</c> command sends (TPM
    /// 2.0 Library Part 3, clause 24.1, Table 191).
    /// </summary>
    /// <param name="hierarchy">The hierarchy under which to create the parent.</param>
    /// <param name="password">Optional authValue for the parent (<see langword="null"/> for none).</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the sensitive-area and template carriers transfers to the constructed CreatePrimaryInput, whose Dispose releases both; every caller holds the input in a using, and a template rent that fails after the sensitive area already succeeded releases it in the catch before rethrowing.")]
    private static CreatePrimaryInput CreateRsaStorageParentInput(TpmRh hierarchy, string? password, BaseMemoryPool pool)
    {
        var objectAttributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.RESTRICTED |
            TpmaObject.DECRYPT;

        Tpm2bSensitiveCreate inSensitive = string.IsNullOrEmpty(password)
            ? Tpm2bSensitiveCreate.CreateEmpty(pool)
            : Tpm2bSensitiveCreate.WithPassword(password, pool);

        try
        {
            Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaStorageParent(
                TpmAlgIdConstants.TPM_ALG_SHA256, objectAttributes, Rsa2048KeyBits, ReadOnlySpan<byte>.Empty, pool);

            return new CreatePrimaryInput(hierarchy, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        }
        catch
        {
            inSensitive.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Recovers what a bus observer holding <paramref name="candidateAuthValue"/> would read out of a captured
    /// rotation's encrypted <c>newAuth</c> parameter. The decrypt companion is bound to the target hierarchy, so
    /// its session key is <c>KDFa(sessionAlg, strip(authValue), "ATH", nonceTPM, nonceCaller)</c> (TPM 2.0
    /// Library Part 1, clause 16.6.10, equation 20); a decrypt-only session's <c>sessionValue</c> is that key
    /// alone (clause 18.1), and the command-direction XOR mask derives from it with
    /// <c>nonceNewer</c> = nonceCaller and <c>nonceOlder</c> = the session's nonceTPM (clause 18.2). Uses the
    /// project's own KDF and parameter-encryption primitives over wire bytes only, so a match means the
    /// keystream was genuinely derivable from the candidate and a mismatch means it was not.
    /// </summary>
    /// <param name="pairs">The recorded command/response triples of one rotation.</param>
    /// <param name="candidateAuthValue">The authorization value the derivation is keyed on.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The bytes the derivation recovers from the encrypted <c>newAuth</c> parameter.</returns>
    private async Task<byte[]> RecoverNewAuthWithABoundSessionKeyAsync(
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs, ReadOnlyMemory<byte> candidateAuthValue, BaseMemoryPool pool)
    {
        byte[] rotationCommand = FirstCommand(pairs, TpmCcConstants.TPM_CC_HierarchyChangeAuth);
        List<(uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength)> entries =
            ReadCommandSessionEntries(rotationCommand, handleCount: 1);
        Assert.HasCount(2, entries, "The rotation carries the authorizing session and a separate decrypt companion.");

        (byte[] StartCommand, byte[] NonceTpm) decryptSessionStart = FindStartAuthSessionExchange(pairs, entries[1].Handle);
        byte[] startNonceCaller = ReadStartAuthSessionNonceCaller(decryptSessionStart.StartCommand);

        using IMemoryOwner<byte> sessionKey = await Kdfa.DeriveAsync(
            HashAlgorithmName.SHA256, StripTrailingZeros(candidateAuthValue), "ATH", decryptSessionStart.NonceTpm, startNonceCaller,
            Sha256DigestSize * 8, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] recovered = ReadNewAuthParameter(rotationCommand, handleCount: 1);
        await TpmParameterEncryption.XorAsync(
            HashAlgorithmName.SHA256, sessionKey.Memory[..Sha256DigestSize], entries[1].NonceCaller, decryptSessionStart.NonceTpm,
            recovered, pool, TestContext.CancellationToken).ConfigureAwait(false);

        return recovered;
    }

    /// <summary>
    /// Assembles the data a response authorization HMAC is computed over:
    /// <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c>, where
    /// <c>rpHash = H(responseCode ‖ commandCode ‖ parameters)</c> and every command in this family has no
    /// response parameters at all (TPM 2.0 Library Part 1, clauses 15.8 and 16.6.5).
    /// </summary>
    /// <param name="responseBytes">The captured response bytes, whose header supplies the response code.</param>
    /// <param name="commandCode">The command code folded into rpHash.</param>
    /// <param name="responseNonceTpm">The session entry's rolled nonceTPM.</param>
    /// <param name="commandNonceCaller">The caller nonce the command's own session entry carried.</param>
    /// <param name="sessionAttributes">The session entry's echoed attributes octet.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The assembled HMAC input.</returns>
    private async Task<byte[]> BuildResponseHmacDataAsync(
        byte[] responseBytes, TpmCcConstants commandCode, byte[] responseNonceTpm, byte[] commandNonceCaller, byte sessionAttributes, BaseMemoryPool pool)
    {
        var reader = new TpmReader(responseBytes);
        TpmHeader header = TpmHeader.Parse(ref reader);

        byte[] rpHashInput = new byte[sizeof(uint) + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(rpHashInput, header.Code);
        BinaryPrimitives.WriteUInt32BigEndian(rpHashInput.AsSpan(sizeof(uint)), (uint)commandCode);

        using DigestValue rpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            rpHashInput, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] data = new byte[Sha256DigestSize + responseNonceTpm.Length + commandNonceCaller.Length + sizeof(byte)];
        int offset = 0;
        rpHash.AsReadOnlySpan().CopyTo(data.AsSpan(offset));
        offset += Sha256DigestSize;
        responseNonceTpm.CopyTo(data.AsSpan(offset));
        offset += responseNonceTpm.Length;
        commandNonceCaller.CopyTo(data.AsSpan(offset));
        offset += commandNonceCaller.Length;
        data[offset] = sessionAttributes;

        return data;
    }

    /// <summary>
    /// Computes a session authorization HMAC: <c>HMAC_sessionAlg(sessionKey ‖ authValue, data)</c> (TPM 2.0
    /// Library Part 1, clause 16.6.5, equation 17). The caller supplies the whole concatenated key, which for
    /// an unbound, unsalted session reduces to the authorization value alone since such a session's key is the
    /// Empty Buffer (clause 16.6.9).
    /// </summary>
    /// <param name="sessionValue">The concatenated HMAC key, trailing zeros already removed from its authValue term.</param>
    /// <param name="data">The HMAC input.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The computed HMAC.</returns>
    private async Task<byte[]> ComputeSessionHmacAsync(ReadOnlyMemory<byte> sessionValue, ReadOnlyMemory<byte> data, BaseMemoryPool pool)
    {
        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            data, sessionValue, Sha256DigestSize, CryptoTags.HmacSha256Value, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return hmac.AsReadOnlySpan().ToArray();
    }

    /// <summary>Returns the command bytes of the first recorded triple whose command code equals <paramref name="code"/>.</summary>
    /// <param name="pairs">The recorded command/response triples.</param>
    /// <param name="code">The command code to locate.</param>
    /// <returns>The matching command bytes.</returns>
    private static byte[] FirstCommand(List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs, TpmCcConstants code)
    {
        foreach((TpmCcConstants Code, byte[] Command, byte[] Response) pair in pairs)
        {
            if(pair.Code == code)
            {
                return pair.Command;
            }
        }

        throw new InvalidOperationException($"No captured command with code '{code}' was recorded.");
    }

    /// <summary>
    /// Locates the <c>TPM2_StartAuthSession</c> exchange that created <paramref name="sessionHandle"/>: the
    /// command that requested the session and the nonceTPM its response carried, which is the session's
    /// <c>nonceOlder</c> for the first command sent over it (TPM 2.0 Library Part 1, clause 18.2).
    /// </summary>
    /// <param name="pairs">The recorded command/response triples.</param>
    /// <param name="sessionHandle">The session handle to find.</param>
    /// <returns>The starting command's bytes and the session's initial nonceTPM.</returns>
    private static (byte[] StartCommand, byte[] NonceTpm) FindStartAuthSessionExchange(
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs, uint sessionHandle)
    {
        foreach((TpmCcConstants Code, byte[] Command, byte[] Response) pair in pairs)
        {
            if(pair.Code != TpmCcConstants.TPM_CC_StartAuthSession || pair.Response.Length == 0)
            {
                continue;
            }

            var reader = new TpmReader(pair.Response);
            _ = TpmHeader.Parse(ref reader);
            if(reader.ReadUInt32() != sessionHandle)
            {
                continue;
            }

            ushort nonceSize = reader.ReadUInt16();

            return (pair.Command, reader.PeekBytes(nonceSize).ToArray());
        }

        throw new InvalidOperationException($"No captured TPM2_StartAuthSession created session handle 0x{sessionHandle:X8}.");
    }

    /// <summary>
    /// Reads the <c>nonceCaller</c> a captured <c>TPM2_StartAuthSession</c> command declared - the KDFa
    /// <c>contextV</c> of the session key it established (TPM 2.0 Library Part 3, clause 11.1).
    /// </summary>
    /// <param name="command">The captured command bytes.</param>
    /// <returns>The caller nonce.</returns>
    private static byte[] ReadStartAuthSessionNonceCaller(byte[] command)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32(); //tpmKey.
        _ = reader.ReadUInt32(); //bind.

        ushort nonceSize = reader.ReadUInt16();

        return reader.PeekBytes(nonceSize).ToArray();
    }

    /// <summary>
    /// Walks a built command's authorization area and yields each session entry's handle, caller nonce,
    /// attributes octet, and the position of its <c>hmac</c> field's data octets: handle area,
    /// <c>authorizationSize</c>, then one <c>sessionHandle ‖ nonceCaller ‖ sessionAttributes ‖ hmac</c> entry
    /// per session until the declared size is consumed (TPM 2.0 Library Part 1, clause 17.5).
    /// </summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The parsed session entries, in authorization-area order.</returns>
    private static List<(uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength)> ReadCommandSessionEntries(byte[] command, int handleCount)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint authorizationSize = reader.ReadUInt32();
        int authStart = reader.Consumed;

        var entries = new List<(uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength)>(2);
        while(reader.Consumed - authStart < (int)authorizationSize)
        {
            uint handle = reader.ReadUInt32();
            ushort nonceSize = reader.ReadUInt16();
            byte[] nonceCaller = reader.PeekBytes(nonceSize).ToArray();
            reader.Skip(nonceSize);
            byte attributes = reader.ReadByte();
            ushort hmacSize = reader.ReadUInt16();
            int hmacStart = reader.Consumed;
            reader.Skip(hmacSize);

            entries.Add((handle, nonceCaller, attributes, hmacStart, hmacSize));
        }

        return entries;
    }

    /// <summary>Reads every authorizing session's <c>nonceCaller</c> out of a built command's authorization area, in authorization-area order.</summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The caller nonces, in authorization-area order.</returns>
    private static byte[][] ReadCommandSessionNonces(byte[] command, int handleCount)
    {
        var nonces = new List<byte[]>(2);
        foreach((uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength) entry in ReadCommandSessionEntries(command, handleCount))
        {
            nonces.Add(entry.NonceCaller);
        }

        return [.. nonces];
    }

    /// <summary>
    /// Reads the (encrypted) <c>newAuth</c> parameter's data octets out of a built
    /// <c>TPM2_HierarchyChangeAuth</c> command: the command's sole parameter, a <c>TPM2B_AUTH</c> whose size
    /// field is never encrypted (TPM 2.0 Library Part 1, clause 18.1).
    /// </summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The parameter's data octets as sent.</returns>
    private static byte[] ReadNewAuthParameter(byte[] command, int handleCount)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint authorizationSize = reader.ReadUInt32();
        reader.Skip((int)authorizationSize);

        ushort newAuthSize = reader.ReadUInt16();

        return reader.PeekBytes(newAuthSize).ToArray();
    }

    /// <summary>
    /// Reads the FIRST session entry out of a framed response's authorization area and reports where its HMAC
    /// field's data octets sit, so a test can recompute or replace them: header, <c>parameterSize</c> (zero for
    /// a command with no response parameters), then <c>nonceTPM ‖ sessionAttributes ‖ hmac</c>.
    /// </summary>
    /// <param name="response">The captured response bytes.</param>
    /// <returns>The HMAC data's offset and length, the entry's rolled nonceTPM, and its echoed attributes octet.</returns>
    private static (int HmacStart, int HmacLength, byte[] NonceTpm, byte SessionAttributes) ReadFirstResponseSessionEntry(byte[] response)
    {
        var reader = new TpmReader(response);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32(); //parameterSize.

        ushort nonceSize = reader.ReadUInt16();
        byte[] nonceTpm = reader.PeekBytes(nonceSize).ToArray();
        reader.Skip(nonceSize);
        byte sessionAttributes = reader.ReadByte();
        ushort hmacSize = reader.ReadUInt16();

        return (reader.Consumed, hmacSize, nonceTpm, sessionAttributes);
    }

    /// <summary>
    /// Copies caller-assembled response octets into a pooled <see cref="TpmResponse"/> the executor under test
    /// consumes and disposes - the shape an active transport substitutes for the genuine framing.
    /// </summary>
    /// <param name="responseBytes">The response octets to hand back.</param>
    /// <param name="pool">The memory pool the response buffer is rented from.</param>
    /// <returns>The substituted response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The rented buffer's ownership transfers to the TpmResponse, which is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> CopyToResponse(byte[] responseBytes, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(responseBytes.Length);
        responseBytes.CopyTo(owner.Memory.Span);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, responseBytes.Length));
    }

    /// <summary>
    /// Sets a bit in the first authorizing session's <c>sessionAttributes</c> octet of a built command,
    /// navigating the handle and authorization areas with a <see cref="TpmReader"/> so it holds regardless of
    /// nonce and HMAC sizes. Mutates <paramref name="command"/> in place.
    /// </summary>
    /// <param name="command">The built command bytes to modify.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <param name="bit">The <c>TPMA_SESSION</c> bit to set.</param>
    private static void SetFirstSessionAttributeBit(byte[] command, int handleCount, byte bit)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        _ = reader.ReadUInt32(); //authorizationSize.
        _ = reader.ReadUInt32(); //sessionHandle.
        ushort nonceSize = reader.ReadUInt16();
        reader.Skip(nonceSize);

        int attributesIndex = reader.Consumed;
        command[attributesIndex] |= bit;
    }

    /// <summary>
    /// Removes trailing zero octets, the transformation an authorization value always undergoes before it is
    /// used in an authorization computation (TPM 2.0 Library Part 1, clause 16.6.4.3).
    /// </summary>
    /// <param name="value">The value to strip.</param>
    /// <returns>The value with trailing zero octets removed.</returns>
    private static ReadOnlyMemory<byte> StripTrailingZeros(ReadOnlyMemory<byte> value)
    {
        int length = value.Length;
        while(length > 0 && value.Span[length - 1] == 0)
        {
            length--;
        }

        return value[..length];
    }

    /// <summary>Reads a captured TPM command's header <c>code</c> field, leaving every other field unexamined.</summary>
    /// <param name="command">The captured command bytes.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(byte[] command)
    {
        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmCcConstants)header.Code;
    }

    /// <summary>Reports whether <paramref name="needle"/> occurs as a contiguous byte sequence within <paramref name="haystack"/>.</summary>
    /// <param name="haystack">The bytes to search.</param>
    /// <param name="needle">The bytes to search for; an empty needle never matches.</param>
    /// <returns><see langword="true"/> when found.</returns>
    private static bool ContainsSubsequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if(needle.IsEmpty || needle.Length > haystack.Length)
        {
            return false;
        }

        for(int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if(haystack.Slice(i, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Wraps a device whose transport appends every command it forwards to <paramref name="capturedCommands"/>, in submission order.</summary>
    /// <param name="simulator">The simulator the capturing transport forwards to.</param>
    /// <param name="capturedCommands">The list each observed command is appended to.</param>
    /// <returns>A device the caller disposes; its transport captures as a side effect of forwarding.</returns>
    private static TpmDevice CreateCapturingDevice(TpmSimulator simulator, List<byte[]> capturedCommands)
    {
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            capturedCommands.Add(command.ToArray());

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        return TpmDevice.Create(CaptureAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>
    /// Wraps a device whose transport records every <c>(commandCode, command bytes, response bytes)</c> triple
    /// into <paramref name="pairs"/> - the wire archaeology the confidentiality known-answer test needs,
    /// firewalled to the wire with no back-channel into session or simulator internals.
    /// </summary>
    /// <param name="simulator">The simulator the recording transport forwards to.</param>
    /// <param name="pairs">The list each observed triple is appended to, in submission order.</param>
    /// <returns>A device the caller disposes; its transport records as a side effect of forwarding.</returns>
    private static TpmDevice CreateRecordingDevice(TpmSimulator simulator, List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs)
    {
        async ValueTask<TpmResult<TpmResponse>> RecordAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] commandBytes = command.ToArray();
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
            byte[] responseBytes = result.IsSuccess ? result.Value.AsReadOnlySpan().ToArray() : [];
            pairs.Add((ReadCommandCode(commandBytes), commandBytes, responseBytes));

            return result;
        }

        return TpmDevice.Create(RecordAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>Creates a response codec registry for the raw rotation compositions this file drives directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRotationRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>Creates a response codec registry for the primary-key creations these tests drive directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateKeyRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>Creates a response codec registry for the clock and PCR readbacks the clear-effects test drives.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateClockAndPcrRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_ReadClock, TpmResponseCodec.ReadClock)
            .Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);

    /// <summary>Creates a response codec registry for the policy-session compositions the cross-feed closure drives.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreatePolicyRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Creates a simulator with the ECC and RSA backends wired (the CreatePrimary ladders and the salted
    /// overload's tpmKey need them), powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the
    /// operational phase.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-hierarchy", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, BaseMemoryPool.Shared).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task IssueStartupClearAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");
    }

    /// <summary>
    /// Issues <c>TPM2_Shutdown(TPM_SU_STATE)</c> directly against the simulator, framed the same unauthorized way
    /// <see cref="IssueStartupClearAsync"/> frames its own command, to record the orderly shutdown type that makes
    /// the following <c>TPM2_Startup(CLEAR)</c> a TPM Restart rather than a TPM Reset (TPM 2.0 Library Part 3,
    /// clause 9.3).
    /// </summary>
    /// <param name="simulator">The simulator to shut down.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task IssueShutdownStateAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new ShutdownInput(TpmSuConstants.TPM_SU_STATE);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Shutdown(STATE) must succeed at the transport level.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Shutdown(STATE) must succeed.");
    }
}
