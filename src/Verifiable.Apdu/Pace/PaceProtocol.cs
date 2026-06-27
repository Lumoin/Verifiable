using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Apdu.Pace;

/// <summary>
/// Drives the ICAO Doc 9303 Part 11 PACE protocol (ECDH) over an <see cref="ApduDevice"/>: MSE:Set AT
/// followed by the four chained GENERAL AUTHENTICATE rounds (encrypted nonce, nonce mapping, key agreement,
/// mutual authentication), establishing the AES session keys KSenc and KSmac. Both Generic Mapping and
/// Integrated Mapping are supported, dispatched from the mechanism the PACE OID selects.
/// </summary>
/// <remarks>
/// <para>
/// PACE uses GENERAL AUTHENTICATE with instruction byte <c>0x86</c> (Doc 9303 §4.4.4); the first
/// three rounds set command chaining in the class byte, the last does not. Each round's payload is a
/// dynamic authentication data object (tag <c>0x7C</c>) wrapping a single context-tagged value. The
/// nonce-mapping round (round 2) is the only one that differs by mechanism: Generic Mapping exchanges
/// ephemeral mapping public keys (<see cref="PaceGenericMapping"/>), while Integrated Mapping sends the
/// terminal's nonce <c>t</c> in the clear and maps it directly (<see cref="PaceIntegratedMapping"/>). The
/// terminal's ephemeral private keys and the Integrated Mapping nonce are supplied by the caller — sourced
/// from the entropy provider in production, and injected from a worked example in tests — so the flow is
/// deterministic, and the remaining cryptographic steps route through <see cref="PaceGenericMapping"/> and
/// <see cref="PaceKeyDerivation"/>.
/// </para>
/// </remarks>
public static class PaceProtocol
{
    /// <summary>The GENERAL AUTHENTICATE instruction byte PACE uses (Doc 9303 §4.4.4).</summary>
    private const byte GeneralAuthenticateInstruction = 0x86;

    /// <summary>The MANAGE SECURITY ENVIRONMENT instruction byte.</summary>
    private const byte ManageSecurityEnvironmentInstruction = 0x22;

    /// <summary>The class byte marking command chaining (the first three GENERAL AUTHENTICATE rounds).</summary>
    private const byte ChainingClass = 0x10;

    /// <summary>The plain class byte (MSE:Set AT and the last GENERAL AUTHENTICATE round).</summary>
    private const byte PlainClass = 0x00;

    /// <summary>BER-TLV tag for dynamic authentication data.</summary>
    private const byte DynamicAuthenticationDataTag = 0x7C;

    /// <summary>BER-TLV tag for the cryptographic-mechanism reference (the PACE OID) in MSE:Set AT.</summary>
    private const byte CryptographicMechanismTag = 0x80;

    /// <summary>BER-TLV tag for the password reference in MSE:Set AT.</summary>
    private const byte PasswordReferenceTag = 0x83;

    /// <summary>Context tags of the dynamic authentication data per GENERAL AUTHENTICATE round.</summary>
    private const byte EncryptedNonceTag = 0x80;
    private const byte TerminalMappingDataTag = 0x81;
    private const byte ChipMappingDataTag = 0x82;
    private const byte TerminalEphemeralKeyTag = 0x83;
    private const byte ChipEphemeralKeyTag = 0x84;
    private const byte TerminalTokenTag = 0x85;
    private const byte ChipTokenTag = 0x86;
    private const byte EncryptedChipAuthenticationDataTag = 0x8A;

    /// <summary>The expected maximal response length requested on each GENERAL AUTHENTICATE (Le).</summary>
    private const int MaximalResponseLength = 0;


    /// <summary>
    /// Establishes a PACE session, returning the AES session keys KSenc and KSmac.
    /// </summary>
    /// <param name="device">The card device.</param>
    /// <param name="nonceKey">The nonce key Kπ derived from the password via <see cref="PaceKeyDerivation.DerivePasswordKeyAsync"/>. Borrowed, not disposed.</param>
    /// <param name="objectIdentifier">The PACE protocol OID value bytes (without the outer 0x06 tag).</param>
    /// <param name="passwordReference">The password reference (<c>0x01</c> for the MRZ).</param>
    /// <param name="curve">A tag carrying the curve <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>.</param>
    /// <param name="mappingMaterial">
    /// The terminal's contribution to the nonce-mapping round, drawn from the entropy provider: for Generic
    /// Mapping the mapping ephemeral private key SK_Map,IFD; for Integrated Mapping the additional nonce
    /// <c>t</c> sent in the clear. The mechanism the OID selects fixes the interpretation.
    /// </param>
    /// <param name="keyAgreementPrivateKey">The terminal's key-agreement ephemeral private key, from the entropy provider.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="staticChipPublicKey">
    /// The chip's static Chip Authentication public key PK_IC (SEC1 uncompressed), from EF.CardSecurity. Required
    /// only for Chip Authentication Mapping, where the terminal checks PK_Map,IC = CA_IC · PK_IC; ignored for
    /// Generic and Integrated Mapping.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The AES session keys KSenc and KSmac, and the chip's PACE ephemeral public key from the key-agreement round (its <c>Comp()</c> is the chip identifier <c>ID_IC</c> a subsequent Terminal Authentication binds, BSI TR-03110-3 §A.2.2.3). The caller disposes all three.</returns>
    /// <exception cref="InvalidOperationException">Thrown on a card or transport error, when the chip's authentication token does not verify, or when Chip Authentication Mapping fails to authenticate the chip.</exception>
    public static async ValueTask<(SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey, EncodedEcPoint ChipEphemeralPublicKey)> EstablishAsync(
        ApduDevice device,
        SymmetricKeyMemory nonceKey,
        ReadOnlyMemory<byte> objectIdentifier,
        byte passwordReference,
        Tag curve,
        ReadOnlyMemory<byte> mappingMaterial,
        ReadOnlyMemory<byte> keyAgreementPrivateKey,
        BaseMemoryPool pool,
        ReadOnlyMemory<byte> staticChipPublicKey = default,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(nonceKey);
        ArgumentNullException.ThrowIfNull(pool);

        PaceMappingType mappingType = PaceObjectIdentifier.GetMappingType(objectIdentifier.Span);
        if(mappingType == PaceMappingType.ChipAuthenticationMapping && staticChipPublicKey.IsEmpty)
        {
            throw new ArgumentException("Chip Authentication Mapping requires the chip's static public key PK_IC.", nameof(staticChipPublicKey));
        }

        await SetAuthenticationTemplateAsync(device, objectIdentifier, passwordReference, pool, cancellationToken).ConfigureAwait(false);

        //Round 1: obtain and decrypt the nonce s.
        using DynamicAuthenticationData emptyData = WrapEmpty(pool);
        using DynamicAuthenticationData encryptedNonce = await GeneralAuthenticateAsync(
            device, ChainingClass, emptyData, EncryptedNonceTag, pool, cancellationToken).ConfigureAwait(false);
        using DecryptedContent nonce = await PaceKeyDerivation.DecryptNonceAsync(
            nonceKey, encryptedNonce.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

        EcMultiplyPointDelegate multiplyPoint = Resolve<EcMultiplyPointDelegate>();

        //Round 2: map the nonce to the ephemeral generator Ĝ, by the mechanism the OID selects. Chip
        //Authentication Mapping additionally retains the chip's mapping public key PK_Map,IC for round 4.
        (EncodedEcPoint mappedGenerator, EncodedEcPoint? chipMappingPublicKey) = await MapNonceRoundAsync(
            device, mappingType, nonce.AsReadOnlyMemory(), mappingMaterial, curve, pool, cancellationToken).ConfigureAwait(false);

        SymmetricKeyMemory encryptionKey;
        SymmetricKeyMemory macKey;
        EncodedEcPoint? chipEphemeralPublicKey = null;
        using(mappedGenerator)
        using(chipMappingPublicKey)
        using(EncodedEcPoint terminalEphemeralKey = await multiplyPoint(keyAgreementPrivateKey, mappedGenerator.AsReadOnlyMemory(), curve, pool, cancellationToken).ConfigureAwait(false))
        using(DynamicAuthenticationData terminalEphemeralData = WrapDynamicAuthenticationData(TerminalEphemeralKeyTag, terminalEphemeralKey.AsReadOnlySpan(), pool))
        using(EncodedEcPoint chipEphemeralKey = await ReceiveEphemeralPublicKeyAsync(device, ChainingClass, terminalEphemeralData, ChipEphemeralKeyTag, curve, pool, cancellationToken).ConfigureAwait(false))
        {
            //Round 3: derive the session keys from the agreement over the mapped generator.
            using SharedSecret sharedSecret = await chipEphemeralKey.AgreeSharedSecretAsync(
                keyAgreementPrivateKey, curve, pool, cancellationToken).ConfigureAwait(false);
            (encryptionKey, macKey) = await PaceKeyDerivation.DeriveSessionKeysAsync(
                sharedSecret.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

            try
            {
                //Retain a surviving copy of the chip's PACE ephemeral public key: a subsequent Terminal
                //Authentication uses Comp() of it as the chip identifier ID_IC (BSI TR-03110-3 §A.2.2.3).
                chipEphemeralPublicKey = EncodedEcPoint.FromBytes(chipEphemeralKey.AsReadOnlySpan(), curve, pool);

                //Round 4: exchange authentication tokens and verify the chip's (fail-closed). Chip Authentication
                //Mapping additionally recovers the encrypted CA data and authenticates the chip's static key.
                if(mappingType == PaceMappingType.ChipAuthenticationMapping)
                {
                    await ExchangeAndVerifyChipAuthenticationMappingTokensAsync(
                        device, encryptionKey, macKey, chipEphemeralKey, terminalEphemeralKey, chipMappingPublicKey!,
                        staticChipPublicKey, objectIdentifier, curve, pool, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await ExchangeAndVerifyTokensAsync(
                        device, macKey, chipEphemeralKey, terminalEphemeralKey, objectIdentifier, pool, cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                encryptionKey.Dispose();
                macKey.Dispose();
                chipEphemeralPublicKey?.Dispose();
                throw;
            }
        }

        //Reached only when the using block completed without throwing, so the ephemeral key was assigned.
        return (encryptionKey, macKey, chipEphemeralPublicKey!);
    }


    /// <summary>
    /// Computes the terminal token, sends it, and verifies the chip's token (fail-closed).
    /// </summary>
    private static async ValueTask ExchangeAndVerifyTokensAsync(
        ApduDevice device,
        SymmetricKeyMemory macKey,
        EncodedEcPoint chipEphemeralKey,
        EncodedEcPoint terminalEphemeralKey,
        ReadOnlyMemory<byte> objectIdentifier,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using MacValue terminalToken = await macKey.ComputeAuthenticationTokenAsync(
            chipEphemeralKey, objectIdentifier, pool, cancellationToken).ConfigureAwait(false);

        using DynamicAuthenticationData terminalTokenData = WrapDynamicAuthenticationData(TerminalTokenTag, terminalToken.AsReadOnlySpan(), pool);
        using DynamicAuthenticationData chipToken = await GeneralAuthenticateAsync(
            device, PlainClass, terminalTokenData, ChipTokenTag, pool, cancellationToken).ConfigureAwait(false);

        using MacValue expectedChipToken = await macKey.ComputeAuthenticationTokenAsync(
            terminalEphemeralKey, objectIdentifier, pool, cancellationToken).ConfigureAwait(false);

        if(!CryptographicOperations.FixedTimeEquals(chipToken.AsReadOnlySpan(), expectedChipToken.AsReadOnlySpan()))
        {
            throw new InvalidOperationException("PACE mutual authentication failed: the chip's authentication token did not verify.");
        }
    }


    /// <summary>
    /// Round 4 under Chip Authentication Mapping: sends the terminal token, parses the chip's response (the chip
    /// token DO'86' and the Encrypted Chip Authentication Data DO'8A'), verifies the chip token (fail-closed),
    /// then recovers CA_IC and authenticates the chip via <c>PK_Map,IC = CA_IC · PK_IC</c>.
    /// </summary>
    private static async ValueTask ExchangeAndVerifyChipAuthenticationMappingTokensAsync(
        ApduDevice device,
        SymmetricKeyMemory encryptionKey,
        SymmetricKeyMemory macKey,
        EncodedEcPoint chipEphemeralKey,
        EncodedEcPoint terminalEphemeralKey,
        EncodedEcPoint chipMappingPublicKey,
        ReadOnlyMemory<byte> staticChipPublicKey,
        ReadOnlyMemory<byte> objectIdentifier,
        Tag curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using MacValue terminalToken = await macKey.ComputeAuthenticationTokenAsync(
            chipEphemeralKey, objectIdentifier, pool, cancellationToken).ConfigureAwait(false);
        using DynamicAuthenticationData terminalTokenData = WrapDynamicAuthenticationData(TerminalTokenTag, terminalToken.AsReadOnlySpan(), pool);

        using CommandApdu command = CommandApdu.BuildCase4(
            PlainClass, GeneralAuthenticateInstruction, 0x00, 0x00, terminalTokenData.AsReadOnlySpan(), MaximalResponseLength, pool);
        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(device, command.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            throw new InvalidOperationException($"PACE GENERAL AUTHENTICATE failed with a transport error 0x{result.TransportErrorCode:X8}.");
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess)
        {
            throw new InvalidOperationException($"PACE GENERAL AUTHENTICATE was rejected: {response.StatusWord}.");
        }

        (DynamicAuthenticationData chipToken, DynamicAuthenticationData encryptedChipAuthenticationData) =
            ParseChipAuthenticationMappingResponse(response.Data, pool);
        using(chipToken)
        using(encryptedChipAuthenticationData)
        {
            //Verify the chip's authentication token over the terminal's ephemeral public key (fail-closed).
            using MacValue expectedChipToken = await macKey.ComputeAuthenticationTokenAsync(
                terminalEphemeralKey, objectIdentifier, pool, cancellationToken).ConfigureAwait(false);
            if(!CryptographicOperations.FixedTimeEquals(chipToken.AsReadOnlySpan(), expectedChipToken.AsReadOnlySpan()))
            {
                throw new InvalidOperationException("PACE mutual authentication failed: the chip's authentication token did not verify.");
            }

            //Recover CA_IC and authenticate the chip: PK_Map,IC = CA_IC · PK_IC (Doc 9303 §4.4.3.5.2).
            using ChipAuthenticationData chipAuthenticationData = await PaceChipAuthenticationMapping.DecryptAsync(
                encryptedChipAuthenticationData.AsReadOnlyMemory(), encryptionKey, curve, pool, cancellationToken).ConfigureAwait(false);
            using EncodedEcPoint staticPublicKey = EncodedEcPoint.FromBytes(staticChipPublicKey.Span, curve, pool);
            bool authentic = await PaceChipAuthenticationMapping.VerifyAsync(
                chipAuthenticationData, staticPublicKey, chipMappingPublicKey, curve, pool, cancellationToken).ConfigureAwait(false);
            if(!authentic)
            {
                throw new InvalidOperationException("PACE Chip Authentication Mapping failed: the chip's static key did not authenticate.");
            }
        }
    }


    /// <summary>
    /// Parses the round-4 Chip Authentication Mapping response — <c>7C ‖ {86 ‖ chip token} ‖ {8A ‖ A_IC}</c> —
    /// copying the chip token and the Encrypted Chip Authentication Data into pooled carriers.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of both returned objects transfers to the caller, which disposes them; the chip token is disposed if reading the second object throws.")]
    private static (DynamicAuthenticationData ChipToken, DynamicAuthenticationData EncryptedChipAuthenticationData) ParseChipAuthenticationMappingResponse(
        ReadOnlySpan<byte> responseData, BaseMemoryPool pool)
    {
        var reader = new ApduReader(responseData);
        if(reader.ReadByte() != DynamicAuthenticationDataTag)
        {
            throw new InvalidOperationException("The PACE response is not a dynamic authentication data object.");
        }

        _ = reader.ReadTlvLength();
        DynamicAuthenticationData chipToken = ReadContextObject(ref reader, ChipTokenTag, pool);
        try
        {
            DynamicAuthenticationData encryptedChipAuthenticationData = ReadContextObject(ref reader, EncryptedChipAuthenticationDataTag, pool);

            return (chipToken, encryptedChipAuthenticationData);
        }
        catch
        {
            chipToken.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Reads one context-tagged object (its tag must be <paramref name="expectedTag"/>) and copies its value into
    /// a pooled <see cref="DynamicAuthenticationData"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned object transfers to the caller, which disposes it.")]
    private static DynamicAuthenticationData ReadContextObject(ref ApduReader reader, byte expectedTag, BaseMemoryPool pool)
    {
        byte tag = reader.ReadByte();
        if(tag != expectedTag)
        {
            throw new InvalidOperationException($"The PACE response carried tag 0x{tag:X2}, expected 0x{expectedTag:X2}.");
        }

        int length = reader.ReadTlvLength();
        ReadOnlySpan<byte> value = reader.ReadBytes(length);

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            value.CopyTo(owner.Memory.Span);

            return new DynamicAuthenticationData(owner);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Runs the nonce-mapping round (round 2) by the mechanism the OID selects and returns the mapped generator Ĝ,
    /// plus the chip's mapping public key PK_Map,IC when Chip Authentication Mapping needs it in round 4.
    /// </summary>
    /// <remarks>
    /// Generic Mapping exchanges ephemeral mapping public keys — the terminal sends <c>SK_Map,IFD·G</c> in DO'81'
    /// and reads the chip's mapping public key from DO'82' — then maps the nonce to <c>Ĝ = s·G + H</c>. Integrated
    /// Mapping instead sends the terminal's nonce <c>t</c> in DO'81' and the chip answers with an empty DO'82'
    /// (Doc 9303 §4.4.5.2.2), so both sides map the nonce to <c>Ĝ = f_G(R_p(s,t))</c> independently. Chip
    /// Authentication Mapping shares the Generic Mapping mapping phase but additionally retains PK_Map,IC.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the mapped generator and the chip mapping public key transfers to the caller, which disposes them; the mapped generator is disposed if reifying the mapping key throws.")]
    private static async ValueTask<(EncodedEcPoint MappedGenerator, EncodedEcPoint? ChipMappingPublicKey)> MapNonceRoundAsync(
        ApduDevice device,
        PaceMappingType mappingType,
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> mappingMaterial,
        Tag curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(mappingType == PaceMappingType.IntegratedMapping)
        {
            using DynamicAuthenticationData terminalNonce = WrapDynamicAuthenticationData(TerminalMappingDataTag, mappingMaterial.Span, pool);
            await SendGeneralAuthenticateAsync(device, ChainingClass, terminalNonce, pool, cancellationToken).ConfigureAwait(false);

            EncodedEcPoint integratedGenerator = await PaceIntegratedMapping.MapNonceAsync(nonce, mappingMaterial, curve, pool, cancellationToken).ConfigureAwait(false);

            return (integratedGenerator, null);
        }

        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        using EncodedEcPoint terminalMappingKey = await multiplyGenerator(mappingMaterial, curve, pool, cancellationToken).ConfigureAwait(false);
        using DynamicAuthenticationData terminalMappingData = WrapDynamicAuthenticationData(TerminalMappingDataTag, terminalMappingKey.AsReadOnlySpan(), pool);
        using DynamicAuthenticationData chipMappingKey = await GeneralAuthenticateAsync(device, ChainingClass, terminalMappingData, ChipMappingDataTag, pool, cancellationToken).ConfigureAwait(false);

        EncodedEcPoint mappedGenerator = await PaceGenericMapping.MapNonceAsync(nonce, mappingMaterial, chipMappingKey.AsReadOnlyMemory(), curve, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            //Chip Authentication Mapping verifies PK_Map,IC = CA_IC · PK_IC in round 4, so keep the chip's mapping public key.
            EncodedEcPoint? chipMappingPublicKey = mappingType == PaceMappingType.ChipAuthenticationMapping
                ? EncodedEcPoint.FromBytes(chipMappingKey.AsReadOnlySpan(), curve, pool)
                : null;

            return (mappedGenerator, chipMappingPublicKey);
        }
        catch
        {
            mappedGenerator.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Sends one GENERAL AUTHENTICATE round and verifies it succeeded, discarding the response data object —
    /// the Integrated Mapping mapping round, whose chip response (an empty DO'82') carries nothing the terminal needs.
    /// </summary>
    private static async ValueTask SendGeneralAuthenticateAsync(
        ApduDevice device, byte classByte, DynamicAuthenticationData commandDataObject, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using CommandApdu command = CommandApdu.BuildCase4(
            classByte, GeneralAuthenticateInstruction, 0x00, 0x00, commandDataObject.AsReadOnlySpan(), MaximalResponseLength, pool);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(device, command.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            throw new InvalidOperationException($"PACE GENERAL AUTHENTICATE failed with a transport error 0x{result.TransportErrorCode:X8}.");
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess)
        {
            throw new InvalidOperationException($"PACE GENERAL AUTHENTICATE was rejected: {response.StatusWord}.");
        }
    }


    /// <summary>
    /// Sends MSE:Set AT to select the PACE mechanism (OID) and password reference.
    /// </summary>
    private static async ValueTask SetAuthenticationTemplateAsync(
        ApduDevice device, ReadOnlyMemory<byte> objectIdentifier, byte passwordReference, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> data = pool.Rent(SetAuthenticationTemplateDataLength(objectIdentifier.Length));
        WriteSetAuthenticationTemplateData(objectIdentifier.Span, passwordReference, data.Memory.Span);
        using CommandApdu command = CommandApdu.BuildCase3(
            PlainClass, ManageSecurityEnvironmentInstruction, 0xC1, 0xA4, data.Memory.Span, pool);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(device, command.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            throw new InvalidOperationException($"PACE MSE:Set AT failed with a transport error 0x{result.TransportErrorCode:X8}.");
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess)
        {
            throw new InvalidOperationException($"PACE MSE:Set AT was rejected: {response.StatusWord}.");
        }
    }


    /// <summary>
    /// Sends one GENERAL AUTHENTICATE round and returns the value of the expected response data object.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned DynamicAuthenticationData transfers to the caller, which disposes it.")]
    private static async ValueTask<DynamicAuthenticationData> GeneralAuthenticateAsync(
        ApduDevice device, byte classByte, DynamicAuthenticationData commandDataObject, byte expectedResponseTag, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using CommandApdu command = CommandApdu.BuildCase4(
            classByte, GeneralAuthenticateInstruction, 0x00, 0x00, commandDataObject.AsReadOnlySpan(), MaximalResponseLength, pool);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(device, command.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            throw new InvalidOperationException($"PACE GENERAL AUTHENTICATE failed with a transport error 0x{result.TransportErrorCode:X8}.");
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess)
        {
            throw new InvalidOperationException($"PACE GENERAL AUTHENTICATE was rejected: {response.StatusWord}.");
        }

        return ParseDynamicAuthenticationData(response.Data, expectedResponseTag, pool);
    }


    /// <summary>
    /// Runs a GENERAL AUTHENTICATE round whose response carries an ephemeral public key and reifies that key
    /// as a pooled, curve-tagged <see cref="EncodedEcPoint"/> rather than an opaque data object, so the
    /// key-agreement and token steps compose over the semantic type.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned EncodedEcPoint transfers to the caller, which disposes it.")]
    private static async ValueTask<EncodedEcPoint> ReceiveEphemeralPublicKeyAsync(
        ApduDevice device, byte classByte, DynamicAuthenticationData commandDataObject, byte expectedResponseTag, Tag curve, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using DynamicAuthenticationData response = await GeneralAuthenticateAsync(
            device, classByte, commandDataObject, expectedResponseTag, pool, cancellationToken).ConfigureAwait(false);

        return EncodedEcPoint.FromBytes(response.AsReadOnlySpan(), curve, pool);
    }


    /// <summary>
    /// Writes the MSE:Set AT data field — <c>80 ‖ OID</c> then <c>83 ‖ password reference</c> — into
    /// <paramref name="destination"/>, and returns the number of bytes written.
    /// </summary>
    private static int WriteSetAuthenticationTemplateData(ReadOnlySpan<byte> objectIdentifier, byte passwordReference, Span<byte> destination)
    {
        int offset = 0;

        destination[offset++] = CryptographicMechanismTag;
        offset += WriteBerLength(objectIdentifier.Length, destination[offset..]);
        objectIdentifier.CopyTo(destination[offset..]);
        offset += objectIdentifier.Length;

        destination[offset++] = PasswordReferenceTag;
        destination[offset++] = 0x01;
        destination[offset++] = passwordReference;

        return offset;
    }


    /// <summary>
    /// The encoded length of the MSE:Set AT data field for an OID of <paramref name="objectIdentifierLength"/> bytes.
    /// </summary>
    private static int SetAuthenticationTemplateDataLength(int objectIdentifierLength) =>
        1 + BerLengthSize(objectIdentifierLength) + objectIdentifierLength + 3;


    /// <summary>
    /// Wraps a single context-tagged value in a dynamic authentication data object (tag 0x7C).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned DynamicAuthenticationData transfers to the caller, which disposes it.")]
    private static DynamicAuthenticationData WrapDynamicAuthenticationData(byte innerTag, ReadOnlySpan<byte> value, BaseMemoryPool pool)
    {
        int innerLength = 1 + BerLengthSize(value.Length) + value.Length;
        IMemoryOwner<byte> owner = pool.Rent(1 + BerLengthSize(innerLength) + innerLength);
        try
        {
            Span<byte> buffer = owner.Memory.Span;
            int offset = 0;

            buffer[offset++] = DynamicAuthenticationDataTag;
            offset += WriteBerLength(innerLength, buffer[offset..]);
            buffer[offset++] = innerTag;
            offset += WriteBerLength(value.Length, buffer[offset..]);
            value.CopyTo(buffer[offset..]);

            return new DynamicAuthenticationData(owner);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// The empty dynamic authentication data object <c>7C 00</c> for the first GENERAL AUTHENTICATE round.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned DynamicAuthenticationData transfers to the caller, which disposes it.")]
    private static DynamicAuthenticationData WrapEmpty(BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(2);
        owner.Memory.Span[0] = DynamicAuthenticationDataTag;
        owner.Memory.Span[1] = 0x00;

        return new DynamicAuthenticationData(owner);
    }


    /// <summary>
    /// Parses a dynamic authentication data response and copies the value of its single inner object,
    /// which must carry <paramref name="expectedInnerTag"/>, into a pooled buffer.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned DynamicAuthenticationData transfers to the caller, which disposes it.")]
    private static DynamicAuthenticationData ParseDynamicAuthenticationData(ReadOnlySpan<byte> responseData, byte expectedInnerTag, BaseMemoryPool pool)
    {
        var reader = new ApduReader(responseData);
        if(reader.ReadByte() != DynamicAuthenticationDataTag)
        {
            throw new InvalidOperationException("The PACE response is not a dynamic authentication data object.");
        }

        _ = reader.ReadTlvLength();
        byte innerTag = reader.ReadByte();
        if(innerTag != expectedInnerTag)
        {
            throw new InvalidOperationException($"The PACE response carried tag 0x{innerTag:X2}, expected 0x{expectedInnerTag:X2}.");
        }

        int innerLength = reader.ReadTlvLength();
        ReadOnlySpan<byte> value = reader.ReadBytes(innerLength);

        IMemoryOwner<byte> owner = pool.Rent(innerLength);
        try
        {
            value.CopyTo(owner.Memory.Span);

            return new DynamicAuthenticationData(owner);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// The number of bytes a BER-TLV definite length field occupies for <paramref name="length"/>.
    /// </summary>
    private static int BerLengthSize(int length) =>
        length <= 0x7F ? 1 : length <= 0xFF ? 2 : 3;


    /// <summary>
    /// Writes a BER-TLV definite length field for <paramref name="length"/> into <paramref name="destination"/>.
    /// </summary>
    private static int WriteBerLength(int length, Span<byte> destination)
    {
        if(length <= 0x7F)
        {
            destination[0] = (byte)length;
            return 1;
        }

        if(length <= 0xFF)
        {
            destination[0] = 0x81;
            destination[1] = (byte)length;
            return 2;
        }

        destination[0] = 0x82;
        destination[1] = (byte)(length >> 8);
        destination[2] = (byte)length;
        return 3;
    }


    /// <summary>
    /// Resolves a registered delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
