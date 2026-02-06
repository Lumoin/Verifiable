using System;
using System.Buffers;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Sessions;

/// <summary>
/// A password-based authorization session.
/// </summary>
/// <remarks>
/// <para>
/// Password sessions are the simplest form of TPM authorization. They use the
/// well-known handle <see cref="TpmRh.TPM_RH_PW"/> and send the object's authValue
/// as the HMAC field.
/// </para>
/// <para>
/// <b>Wire format (TPMS_AUTH_COMMAND for password session):</b>
/// </para>
/// <list type="bullet">
///   <item><description>sessionHandle = TPM_RH_PW (0x40000009).</description></item>
///   <item><description>nonceCaller = empty (size = 0).</description></item>
///   <item><description>sessionAttributes = 0 (continueSession not meaningful).</description></item>
///   <item><description>hmac = password/authValue bytes.</description></item>
/// </list>
/// <para>
/// Password sessions do not provide integrity protection or replay prevention.
/// For higher security, use HMAC sessions.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 1, Section 19.6.
/// </para>
/// </remarks>
public sealed class TpmPasswordSession: TpmSessionBase, IDisposable
{
    private readonly Tpm2bAuth password;
    private bool disposed;

    /// <summary>
    /// Initializes a password session with the specified password.
    /// </summary>
    /// <param name="password">The password/authValue. Ownership is transferred to this session.</param>
    private TpmPasswordSession(Tpm2bAuth password)
    {
        this.password = password;
    }

    /// <inheritdoc/>
    public override TpmHandle SessionHandle => TpmRh.TPM_RH_PW;

    /// <inheritdoc/>
    /// <remarks>
    /// Password sessions don't use a hash algorithm for HMAC computation.
    /// Returns TPM_ALG_NULL.
    /// </remarks>
    public override TpmAlgIdConstants HashAlgorithm => TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Creates a password session with no password (empty authValue).
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>A password session with empty password.</returns>
    public static TpmPasswordSession CreateEmpty(MemoryPool<byte> pool)
    {
        return new TpmPasswordSession(Tpm2bAuth.CreateEmpty(pool));
    }

    /// <summary>
    /// Creates a password session with the specified password string.
    /// </summary>
    /// <param name="password">The password string (UTF-8 encoded).</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>A password session with the specified password.</returns>
    public static TpmPasswordSession Create(string password, MemoryPool<byte> pool)
    {
        if(string.IsNullOrEmpty(password))
        {
            return CreateEmpty(pool);
        }

        var auth = Tpm2bAuth.CreateFromPassword(password, pool);
        return new TpmPasswordSession(auth);
    }

    /// <summary>
    /// Creates a password session with the specified password bytes.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>A password session with the specified password.</returns>
    public static TpmPasswordSession Create(ReadOnlySpan<byte> password, MemoryPool<byte> pool)
    {
        if(password.IsEmpty)
        {
            return CreateEmpty(pool);
        }

        var auth = Tpm2bAuth.Create(password, pool);
        return new TpmPasswordSession(auth);
    }

    /// <inheritdoc/>
    public override int GetAuthCommandSize()
    {
        // sessionHandle (4) + nonceCaller size (2) + nonceCaller (0) + attributes (1) + hmac
        return sizeof(uint) +          // sessionHandle
               sizeof(ushort) +        // nonceCaller.size (always 0)
               sizeof(byte) +          // sessionAttributes
               password.               SerializedSize; // hmac (TPM2B_AUTH)
    }

    /// <inheritdoc/>
    public override void WriteAuthCommand(ref TpmWriter writer, scoped ReadOnlySpan<byte> cpHash, MemoryPool<byte> pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //sessionHandle = TPM_RH_PW.
        TpmHandle handle = TpmRh.TPM_RH_PW;
        handle.WriteTo(ref writer);

        //nonceCaller = empty.
        writer.WriteUInt16(0);

        //sessionAttributes = 0 (no flags set for password sessions).
        writer.WriteByte(0);

        //hmac = password.
        password.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public override bool VerifyAndUpdate(TpmsAuthResponse response, scoped ReadOnlySpan<byte> rpHash, MemoryPool<byte> pool)
    {
        // Password sessions don't verify response HMAC.
        // The TPM returns empty nonce and empty hmac for password sessions.
        return true;
    }

    /// <summary>
    /// Releases the password memory.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            password.Dispose();
            disposed = true;
        }
    }
}