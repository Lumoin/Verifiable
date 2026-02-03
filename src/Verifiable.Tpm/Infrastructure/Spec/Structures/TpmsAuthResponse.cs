using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// TPMS_AUTH_RESPONSE - authorization response structure.
/// </summary>
/// <remarks>
/// <para>
/// This structure is returned in the authorization area of a response when sessions
/// are present (TPM_ST_SESSIONS). Each session contributes one TPMS_AUTH_RESPONSE
/// entry to the response authorization area.
/// </para>
/// <para>
/// This structure owns its <see cref="Tpm2bNonce"/> and <see cref="Tpm2bAuth"/> members.
/// Dispose this structure when done to return the memory to the pool.
/// </para>
/// <para>
/// Wire format (big-endian):
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0+: nonce (TPM2B_NONCE) - TPM's nonce for next command.</description></item>
///   <item><description>Next 1 byte: sessionAttributes (TPMA_SESSION).</description></item>
///   <item><description>Remaining: hmac (TPM2B_AUTH) - HMAC for verification.</description></item>
/// </list>
/// <para>
/// See TPM 2.0 Library Specification, Part 2: Structures, Section 10.10.2.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsAuthResponse: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the TPM's nonce for the next command.
    /// </summary>
    /// <remarks>
    /// This property returns <c>null</c> after <see cref="TakeNonceTPM"/> has been called.
    /// </remarks>
    public Tpm2bNonce? NonceTPM { get; private set; }

    /// <summary>
    /// Gets the session attributes returned by the TPM.
    /// </summary>
    public TpmaSession SessionAttributes { get; }

    /// <summary>
    /// Gets the HMAC for verification.
    /// </summary>
    /// <remarks>
    /// This property returns <c>null</c> after <see cref="TakeHmac"/> has been called.
    /// </remarks>
    public Tpm2bAuth? Hmac { get; private set; }

    /// <summary>
    /// Initializes a new authorization response.
    /// </summary>
    /// <param name="nonceTPM">The TPM's nonce.</param>
    /// <param name="sessionAttributes">The session attributes.</param>
    /// <param name="hmac">The HMAC.</param>
    public TpmsAuthResponse(Tpm2bNonce nonceTPM, TpmaSession sessionAttributes, Tpm2bAuth hmac)
    {
        NonceTPM = nonceTPM;
        SessionAttributes = sessionAttributes;
        Hmac = hmac;
    }

    /// <summary>
    /// Takes ownership of the TPM's nonce from this response.
    /// </summary>
    /// <returns>The TPM's nonce. Caller is responsible for disposing.</returns>
    /// <remarks>
    /// <para>
    /// After calling this method, <see cref="NonceTPM"/> returns <c>null</c> and
    /// <see cref="Dispose"/> will not dispose the nonce.
    /// </para>
    /// <para>
    /// This enables zero-copy transfer of the nonce to a <see cref="Sessions.TpmSession"/>
    /// without allocating a second copy.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">The nonce has already been taken.</exception>
    public Tpm2bNonce TakeNonceTPM()
    {
        if(NonceTPM is null)
        {
            throw new InvalidOperationException("NonceTPM has already been taken.");
        }

        Tpm2bNonce nonce = NonceTPM;
        NonceTPM = null;
        return nonce;
    }

    /// <summary>
    /// Takes ownership of the HMAC from this response.
    /// </summary>
    /// <returns>The HMAC. Caller is responsible for disposing.</returns>
    /// <remarks>
    /// <para>
    /// After calling this method, <see cref="Hmac"/> returns <c>null</c> and
    /// <see cref="Dispose"/> will not dispose the HMAC.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">The HMAC has already been taken.</exception>
    public Tpm2bAuth TakeHmac()
    {
        if(Hmac is null)
        {
            throw new InvalidOperationException("Hmac has already been taken.");
        }

        Tpm2bAuth hmac = Hmac;
        Hmac = null;
        return hmac;
    }

    /// <summary>
    /// Parses an authorization response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the auth response.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed authorization response.</returns>
    public static TpmsAuthResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        Tpm2bNonce nonceTPM = Tpm2bNonce.Parse(ref reader, pool);
        TpmaSession sessionAttributes = (TpmaSession)reader.ReadByte();
        Tpm2bAuth hmac = Tpm2bAuth.Parse(ref reader, pool);

        return new TpmsAuthResponse(nonceTPM, sessionAttributes, hmac);
    }

    /// <summary>
    /// Writes this authorization response to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <exception cref="InvalidOperationException">NonceTPM or Hmac has been taken.</exception>
    public void WriteTo(ref TpmWriter writer)
    {
        if(NonceTPM is null || Hmac is null)
        {
            throw new InvalidOperationException("Cannot write after ownership has been transferred.");
        }

        NonceTPM.WriteTo(ref writer);
        writer.WriteByte((byte)SessionAttributes);
        Hmac.WriteTo(ref writer);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    /// <exception cref="InvalidOperationException">NonceTPM or Hmac has been taken.</exception>
    public int GetSerializedSize()
    {
        if(NonceTPM is null || Hmac is null)
        {
            throw new InvalidOperationException("Cannot compute size after ownership has been transferred.");
        }

        return NonceTPM.GetSerializedSize() + sizeof(byte) + Hmac.GetSerializedSize();
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    /// <remarks>
    /// Members whose ownership has been transferred via <see cref="TakeNonceTPM"/>
    /// or <see cref="TakeHmac"/> are not disposed.
    /// </remarks>
    public void Dispose()
    {
        if(!disposed)
        {
            NonceTPM?.Dispose();
            Hmac?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMS_AUTH_RESPONSE({SessionAttributes}, hmac={Hmac?.Length ?? 0} bytes)";
}