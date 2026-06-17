using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Coverage for the dictionary-attack (lockout) extension, driving
/// <see cref="TpmDictionaryAttackExtensions.GetDictionaryAttackParametersAsync"/> through a
/// scripted <see cref="TpmDevice.Create"/> handler that returns canned GetCapability responses,
/// plus direct unit coverage of the <see cref="TpmDictionaryAttackParameters"/> lockout predicate.
/// </summary>
[TestClass]
internal sealed class TpmDictionaryAttackExtensionsTests
{
    private const int HeaderSize = 10;
    private const ushort TpmStNoSessions = 0x8001;
    private const uint TpmCapTpmProperties = 0x00000006;

    public TestContext TestContext { get; set; } = null!;

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> SuccessFrame(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, bytes.Length));
    }

    private static byte[] BuildTpmPropertiesFrame(bool moreData, (uint Property, uint Value)[] properties)
    {
        int parameterLength = sizeof(byte) + sizeof(uint) + sizeof(uint) + (properties.Length * 2 * sizeof(uint));
        int total = HeaderSize + parameterLength;
        byte[] frame = new byte[total];

        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0), TpmStNoSessions);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(2), (uint)total);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(6), 0u);

        int offset = HeaderSize;
        frame[offset] = (byte)(moreData ? 1 : 0);
        offset += sizeof(byte);

        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(offset), TpmCapTpmProperties);
        offset += sizeof(uint);

        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(offset), (uint)properties.Length);
        offset += sizeof(uint);

        foreach((uint property, uint value) in properties)
        {
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(offset), property);
            offset += sizeof(uint);
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(offset), value);
            offset += sizeof(uint);
        }

        return frame;
    }

    [TestMethod]
    public async Task GetDictionaryAttackParametersParsesLockoutProperties()
    {
        (uint Property, uint Value)[] lockout =
        [
            (TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, 3u),
            (TpmPtConstants.TPM_PT_MAX_AUTH_FAIL, 32u),
            (TpmPtConstants.TPM_PT_LOCKOUT_INTERVAL, 7200u),
            (TpmPtConstants.TPM_PT_LOCKOUT_RECOVERY, 86400u)
        ];

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            byte[] frame = BuildTpmPropertiesFrame(moreData: false, lockout);

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        TpmResult<TpmDictionaryAttackParameters> result = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result.ResponseCode}'.");
        TpmDictionaryAttackParameters parameters = result.Value;
        Assert.AreEqual(3u, parameters.LockoutCounter);
        Assert.AreEqual(32u, parameters.MaxAuthFail);
        Assert.AreEqual(TimeSpan.FromSeconds(7200), parameters.LockoutInterval);
        Assert.AreEqual(TimeSpan.FromSeconds(86400), parameters.LockoutRecovery);
        Assert.IsFalse(parameters.IsLockedOut);
    }

    [TestMethod]
    public async Task GetDictionaryAttackParametersReportsLockoutWhenCounterReachesMax()
    {
        (uint Property, uint Value)[] lockout =
        [
            (TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, 32u),
            (TpmPtConstants.TPM_PT_MAX_AUTH_FAIL, 32u),
            (TpmPtConstants.TPM_PT_LOCKOUT_INTERVAL, 7200u),
            (TpmPtConstants.TPM_PT_LOCKOUT_RECOVERY, 86400u)
        ];

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            byte[] frame = BuildTpmPropertiesFrame(moreData: false, lockout);

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        TpmResult<TpmDictionaryAttackParameters> result = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsTrue(result.Value.IsLockedOut);
    }

    [TestMethod]
    public async Task GetDictionaryAttackParametersSurfacesTransportError()
    {
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(0x1234u));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        TpmResult<TpmDictionaryAttackParameters> result = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTransportError);
    }

    [TestMethod]
    public void IsLockedOutTrueWhenCounterReachesMax()
    {
        var parameters = new TpmDictionaryAttackParameters(32u, 32u, TimeSpan.FromSeconds(7200), TimeSpan.FromSeconds(86400));

        Assert.IsTrue(parameters.IsLockedOut);
    }

    [TestMethod]
    public void IsLockedOutFalseBelowMax()
    {
        var parameters = new TpmDictionaryAttackParameters(31u, 32u, TimeSpan.FromSeconds(7200), TimeSpan.FromSeconds(86400));

        Assert.IsFalse(parameters.IsLockedOut);
    }

    [TestMethod]
    public void IsLockedOutFalseWhenProtectionDisabled()
    {
        var parameters = new TpmDictionaryAttackParameters(5u, 0u, TimeSpan.FromSeconds(7200), TimeSpan.FromSeconds(86400));

        Assert.IsFalse(parameters.IsLockedOut);
    }
}
