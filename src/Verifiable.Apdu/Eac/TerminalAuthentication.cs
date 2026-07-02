using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu.Mrz;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;

namespace Verifiable.Apdu.Eac;

/// <summary>
/// The terminal side of Extended Access Control Terminal Authentication (ICAO Doc 9303 Part 11 §7.1): the
/// terminal presents its card-verifiable certificate chain to the chip and proves possession of the private
/// key matching its terminal (Inspection System) certificate.
/// </summary>
/// <remarks>
/// <para>
/// Terminal Authentication runs over the Secure Messaging session an access protocol established, after Chip
/// Authentication (or PACE Chip Authentication Mapping) has produced the terminal's ephemeral key the
/// signature binds to. The flow (§7.1.5) is, for each certificate in the chain in issuing order: MSE:Set DST
/// to name the public key that verifies it, then PSO:Verify Certificate to present it; followed by MSE:Set AT
/// to select the terminal's key, GET CHALLENGE for the chip's nonce, and EXTERNAL AUTHENTICATE carrying the
/// terminal's signature.
/// </para>
/// <para>
/// The chip verifies each certificate against the public key the preceding one (or, for the first, the
/// trusted Country Verifying Certification Authority) carries, and imports it, so the terminal presents the
/// Document Verifier certificate first and the terminal certificate last.
/// </para>
/// <para>
/// MSE:Set AT names the Terminal Authentication protocol with the terminal key's <c>id-TA-*</c> object
/// identifier (DO'80') and selects the terminal key by holder reference (DO'83'); the chip checks the
/// identifier matches the terminal certificate it imported. Once the EXTERNAL AUTHENTICATE succeeds the chip
/// grants the terminal the effective access authorization (the bitwise AND of the chain's Certificate Holder
/// Authorization Templates, BSI TR-03110-3 §2.7), which gates its subsequent reads of the sensitive data
/// groups EF.DG3 (fingerprints) and EF.DG4 (iris).
/// </para>
/// </remarks>
public static class TerminalAuthentication
{
    /// <summary>The class byte of the Terminal Authentication commands.</summary>
    private const byte TerminalAuthenticationClass = 0x00;

    /// <summary>P1 of MSE:Set DST — set the Digital Signature Template naming the public key for the next certificate verification.</summary>
    private const byte SetDigitalSignatureTemplateP1 = 0x81;

    /// <summary>P2 of MSE:Set DST — the Digital Signature Template (DST) tag.</summary>
    private const byte SetDigitalSignatureTemplateP2 = 0xB6;

    /// <summary>P1 of PSO:Verify Certificate — the data field carries the certificate to verify (no chaining).</summary>
    private const byte VerifyCertificateP1 = 0x00;

    /// <summary>P2 of PSO:Verify Certificate — verify a self-descriptive certificate (ISO/IEC 7816-8).</summary>
    private const byte VerifyCertificateP2 = 0xBE;

    /// <summary>P1 of MSE:Set AT for Terminal Authentication — set the Authentication Template (distinct from PACE's P1 0xC1).</summary>
    private const byte SetAuthenticationTemplateP1 = 0x81;

    /// <summary>P2 of MSE:Set AT — the Authentication Template (AT) tag.</summary>
    private const byte SetAuthenticationTemplateP2 = 0xA4;

    /// <summary>BER-TLV tag for the public-key reference in MSE:Set DST and MSE:Set AT (DO'83').</summary>
    private const byte PublicKeyReferenceTag = 0x83;

    /// <summary>BER-TLV tag for the cryptographic-mechanism reference in MSE:Set AT (DO'80', the TA protocol object identifier).</summary>
    private const byte CryptographicMechanismReferenceTag = 0x80;

    /// <summary>The length of the chip challenge r_IC the GET CHALLENGE step requests (Doc 9303 Part 11 §7.1.5).</summary>
    private const int ChipChallengeLength = 8;


    /// <summary>
    /// Presents a card-verifiable certificate chain to the chip, verifying each certificate against the key
    /// the chip already trusts: MSE:Set DST then PSO:Verify Certificate for each, in issuing order.
    /// </summary>
    /// <param name="device">The card device. Borrowed, not disposed.</param>
    /// <param name="session">The Secure Messaging session the commands run over. Borrowed, not disposed.</param>
    /// <param name="chain">The certificates to present, in issuing order (Document Verifier first, terminal last); the first names the chip's trusted Country Verifying Certification Authority as its authority.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the chip accepted every certificate; otherwise <see langword="false"/> (a card or transport error, or a chip rejection).</returns>
    public static async ValueTask<bool> PresentCertificateChainAsync(
        ApduDevice device,
        SecureMessagingSession session,
        IReadOnlyList<CardVerifiableCertificate> chain,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(pool);

        foreach(CardVerifiableCertificate certificate in chain)
        {
            bool selected = await SetDigitalSignatureTemplateAsync(
                device, session, certificate.CertificationAuthorityReference, pool, cancellationToken).ConfigureAwait(false);
            if(!selected)
            {
                return false;
            }

            bool verified = await VerifyCertificateAsync(
                device, session, certificate.Content, pool, cancellationToken).ConfigureAwait(false);
            if(!verified)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Runs the full Terminal Authentication exchange: presents the certificate chain, selects the terminal
    /// key, gets the chip's challenge, and proves possession of the terminal private key with an EXTERNAL
    /// AUTHENTICATE signature over <c>ID_IC ‖ r_IC ‖ Comp(PK_DH,IFD)</c>.
    /// </summary>
    /// <param name="device">The card device. Borrowed, not disposed.</param>
    /// <param name="session">The Secure Messaging session (from Chip Authentication or PACE Chip Authentication Mapping) the exchange runs over. Borrowed, not disposed.</param>
    /// <param name="chain">The certificate chain to present, in issuing order (Document Verifier first, terminal last); the terminal certificate ends the chain.</param>
    /// <param name="terminalPrivateKey">The terminal's Terminal Authentication private key (matching the terminal certificate's public key). Borrowed.</param>
    /// <param name="terminalEphemeralPublicKey">The terminal's ephemeral public key <c>PK_DH,IFD</c> (uncompressed SEC1) from Chip Authentication or PACE Chip Authentication Mapping.</param>
    /// <param name="chipIdentifier">The chip identifier <c>ID_IC</c> the access protocol produced (the MRZ document number including its check digit after Basic Access Control).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the chip accepted the chain and the terminal's signature; otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> AuthenticateAsync(
        ApduDevice device,
        SecureMessagingSession session,
        IReadOnlyList<CardVerifiableCertificate> chain,
        ReadOnlyMemory<byte> terminalPrivateKey,
        ReadOnlyMemory<byte> terminalEphemeralPublicKey,
        ReadOnlyMemory<byte> chipIdentifier,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(pool);

        if(!await PrepareAsync(device, session, chain, pool, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        CardVerifiableCertificatePublicKey terminalKey = chain[^1].PublicKey;

        using IMemoryOwner<byte>? challenge = await RequestChallengeAsync(device, session, pool, cancellationToken).ConfigureAwait(false);
        if(challenge is null)
        {
            return false;
        }

        //The terminal proves possession of its key by signing ID_IC ‖ r_IC ‖ Comp(PK_DH,IFD); an elliptic-curve
        //terminal signs with ECDSA over its curve, an RSA terminal with the certificate's id-TA-RSA scheme.
        using Signature signature = terminalKey.IsEllipticCurve
            ? await TerminalAuthenticationSignature.SignAsync(
                terminalPrivateKey, terminalKey.EllipticCurvePoint!.Tag, chipIdentifier, challenge.Memory[..ChipChallengeLength], terminalEphemeralPublicKey,
                pool, cancellationToken).ConfigureAwait(false)
            : await TerminalAuthenticationSignature.SignWithRsaAsync(
                terminalPrivateKey, terminalKey.SignatureScheme, chipIdentifier, challenge.Memory[..ChipChallengeLength], terminalEphemeralPublicKey,
                pool, cancellationToken).ConfigureAwait(false);

        return await SendExternalAuthenticateAsync(device, session, signature, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Runs the full Terminal Authentication exchange with a terminal key whose signing primitive is bound to
    /// the key itself, so the terminal's Terminal Authentication private key may live in hardware (for example a
    /// TPM) and never leave it: presents the certificate chain, selects the terminal key, gets the chip's
    /// challenge, and proves possession with an EXTERNAL AUTHENTICATE signature over
    /// <c>ID_IC ‖ r_IC ‖ Comp(PK_DH,IFD)</c> that <paramref name="terminalKey"/> produces.
    /// </summary>
    /// <remarks>
    /// The chip side is unchanged: it still verifies the signature against the terminal certificate's public
    /// key, so the certificate must have been minted over the public key matching <paramref name="terminalKey"/>.
    /// The certificate (its <c>id-TA-*</c> scheme and holder reference), not the private key, still drives
    /// MSE:Set AT, so a hardware key and a software key follow the identical exchange.
    /// </remarks>
    /// <param name="device">The card device. Borrowed, not disposed.</param>
    /// <param name="session">The Secure Messaging session (from Chip Authentication or PACE Chip Authentication Mapping) the exchange runs over. Borrowed, not disposed.</param>
    /// <param name="chain">The certificate chain to present, in issuing order (Document Verifier first, terminal last); the terminal certificate ends the chain.</param>
    /// <param name="terminalKey">The terminal's Terminal Authentication private key with its signing function bound (matching the terminal certificate's public key). Borrowed.</param>
    /// <param name="terminalEphemeralPublicKey">The terminal's ephemeral public key <c>PK_DH,IFD</c> (uncompressed SEC1) from Chip Authentication or PACE Chip Authentication Mapping.</param>
    /// <param name="chipIdentifier">The chip identifier <c>ID_IC</c> the access protocol produced.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the chip accepted the chain and the terminal's signature; otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> AuthenticateAsync(
        ApduDevice device,
        SecureMessagingSession session,
        IReadOnlyList<CardVerifiableCertificate> chain,
        PrivateKey terminalKey,
        ReadOnlyMemory<byte> terminalEphemeralPublicKey,
        ReadOnlyMemory<byte> chipIdentifier,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(terminalKey);
        ArgumentNullException.ThrowIfNull(pool);

        if(!await PrepareAsync(device, session, chain, pool, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        using IMemoryOwner<byte>? challenge = await RequestChallengeAsync(device, session, pool, cancellationToken).ConfigureAwait(false);
        if(challenge is null)
        {
            return false;
        }

        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            terminalKey, chipIdentifier, challenge.Memory[..ChipChallengeLength], terminalEphemeralPublicKey, pool, cancellationToken).ConfigureAwait(false);

        return await SendExternalAuthenticateAsync(device, session, signature, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Presents the certificate chain and selects the terminal key with MSE:Set AT — the shared prologue of the
    /// AuthenticateAsync overloads — returning whether every step succeeded. MSE:Set AT is driven by the terminal
    /// certificate (its signature scheme and holder reference), so a software and a hardware terminal key are
    /// indistinguishable here.
    /// </summary>
    private static async ValueTask<bool> PrepareAsync(
        ApduDevice device, SecureMessagingSession session, IReadOnlyList<CardVerifiableCertificate> chain, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        if(chain.Count == 0)
        {
            return false;
        }

        CardVerifiableCertificate terminalCertificate = chain[^1];

        if(!await PresentCertificateChainAsync(device, session, chain, pool, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        return await SetAuthenticationTemplateAsync(
            device, session, terminalCertificate.PublicKey.SignatureScheme, terminalCertificate.CertificateHolderReference, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends EXTERNAL AUTHENTICATE carrying the terminal's signature <c>s_IFD</c> and reports whether the chip
    /// accepted it (granting the effective access authorization).
    /// </summary>
    private static ValueTask<bool> SendExternalAuthenticateAsync(
        ApduDevice device, SecureMessagingSession session, Signature signature, BaseMemoryPool pool, CancellationToken cancellationToken) =>
        SendProtectedCommandAsync(
            device, session, InstructionCode.ExternalAuthenticate.Code, 0x00, 0x00, signature.AsReadOnlyMemory(), pool, cancellationToken);


    /// <summary>
    /// The Basic Access Control chip identifier <c>ID_IC</c> (Doc 9303 Part 11 §7.1.2): the MRZ document
    /// number including its check digit. Used by both the terminal and the chip so the signed message matches.
    /// </summary>
    /// <param name="documentNumber">The MRZ document number field (nine characters with filler for the common case).</param>
    /// <returns>The document number with its appended check digit.</returns>
    public static string ChipIdentifierForBasicAccessControl(string documentNumber)
    {
        ArgumentNullException.ThrowIfNull(documentNumber);

        return documentNumber + MachineReadableZone.ComputeCheckDigit(documentNumber);
    }


    /// <summary>
    /// The PACE chip identifier <c>ID_IC</c> (BSI TR-03110-3 §A.2.2.3): <c>Comp()</c> of the chip's PACE
    /// ephemeral public key — its x-coordinate. When PACE rather than Basic Access Control established the
    /// session, this replaces the document number as the identifier the Terminal Authentication signature
    /// binds, so the chip and the terminal must derive it identically. The chip's PACE ephemeral public key is
    /// the one the chip returned in the PACE key-agreement round.
    /// </summary>
    /// <param name="chipPaceEphemeralPublicKey">The chip's PACE ephemeral public key (uncompressed SEC1) from the PACE key-agreement round.</param>
    /// <returns>The chip identifier — a view into <paramref name="chipPaceEphemeralPublicKey"/>'s memory, not a copy.</returns>
    public static ReadOnlyMemory<byte> ChipIdentifierForPace(EncodedEcPoint chipPaceEphemeralPublicKey)
    {
        ArgumentNullException.ThrowIfNull(chipPaceEphemeralPublicKey);

        return TerminalAuthenticationSignature.Compress(chipPaceEphemeralPublicKey);
    }


    /// <summary>
    /// Sends MSE:Set AT naming the Terminal Authentication protocol (DO'80', the terminal key's
    /// <c>id-TA-*</c> object identifier) and selecting the terminal certificate's key (DO'83', the holder
    /// reference) for EXTERNAL AUTHENTICATE.
    /// </summary>
    private static async ValueTask<bool> SetAuthenticationTemplateAsync(
        ApduDevice device, SecureMessagingSession session, CvcSignatureScheme scheme, string terminalReference, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ReadOnlySpan<byte> objectIdentifier = TerminalAuthenticationObjectIdentifier.ValueBytes(scheme);
        int referenceLength = Encoding.ASCII.GetByteCount(terminalReference);
        int dataLength = BerTlvWriter.ElementSize(CryptographicMechanismReferenceTag, objectIdentifier.Length)
            + BerTlvWriter.ElementSize(PublicKeyReferenceTag, referenceLength);

        using IMemoryOwner<byte> data = pool.Rent(dataLength);
        int written = WriteAuthenticationTemplateData(objectIdentifier, terminalReference, data.Memory.Span);

        return await SendProtectedCommandAsync(
            device, session, InstructionCode.ManageSecurityEnvironment.Code, SetAuthenticationTemplateP1, SetAuthenticationTemplateP2,
            data.Memory[..written], pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Writes the MSE:Set AT data field — the cryptographic-mechanism reference DO'80' (the TA object
    /// identifier) then the public-key reference DO'83' (the terminal holder reference) — returning the byte count.
    /// </summary>
    private static int WriteAuthenticationTemplateData(ReadOnlySpan<byte> objectIdentifier, string terminalReference, Span<byte> destination)
    {
        var writer = new BerTlvWriter(destination);
        writer.WriteElement(CryptographicMechanismReferenceTag, objectIdentifier);
        writer.WriteHeader(PublicKeyReferenceTag, Encoding.ASCII.GetByteCount(terminalReference));
        writer.WriteAscii(terminalReference);

        return writer.Written;
    }


    /// <summary>
    /// Sends a Secure-Messaging-protected GET CHALLENGE and returns the chip's challenge r_IC, or
    /// <see langword="null"/> on a transport error, an unsuccessful status word, or an unexpected length.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented challenge buffer transfers to the caller, which disposes it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>?> RequestChallengeAsync(
        ApduDevice device, SecureMessagingSession session, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using ProtectedCommandApdu protectedCommand = await session.ProtectCommandAsync(
            TerminalAuthenticationClass, InstructionCode.GetChallenge.Code, 0x00, 0x00,
            ReadOnlyMemory<byte>.Empty, ChipChallengeLength, pool, cancellationToken).ConfigureAwait(false);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, protectedCommand.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            return null;
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess)
        {
            return null;
        }

        using SecureMessagingResponse unprotected = await session.UnprotectResponseAsync(
            response.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(!unprotected.StatusWord.IsSuccess || unprotected.Length != ChipChallengeLength)
        {
            return null;
        }

        IMemoryOwner<byte> challenge = pool.Rent(ChipChallengeLength);
        unprotected.Data[..ChipChallengeLength].CopyTo(challenge.Memory.Span);

        return challenge;
    }


    /// <summary>
    /// Sends MSE:Set DST naming the public key (by holder reference) that verifies the next certificate.
    /// </summary>
    private static async ValueTask<bool> SetDigitalSignatureTemplateAsync(
        ApduDevice device, SecureMessagingSession session, string publicKeyReference, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int referenceLength = Encoding.ASCII.GetByteCount(publicKeyReference);
        using IMemoryOwner<byte> data = pool.Rent(BerTlvWriter.ElementSize(PublicKeyReferenceTag, referenceLength));
        int dataLength = WritePublicKeyReference(publicKeyReference, referenceLength, data.Memory.Span);

        return await SendProtectedCommandAsync(
            device, session, InstructionCode.ManageSecurityEnvironment.Code, SetDigitalSignatureTemplateP1, SetDigitalSignatureTemplateP2,
            data.Memory[..dataLength], pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends PSO:Verify Certificate carrying a certificate's content (the body and signature data objects).
    /// </summary>
    private static async ValueTask<bool> VerifyCertificateAsync(
        ApduDevice device, SecureMessagingSession session, ReadOnlyMemory<byte> certificateContent, BaseMemoryPool pool, CancellationToken cancellationToken) =>
        await SendProtectedCommandAsync(
            device, session, InstructionCode.PerformSecurityOperation.Code, VerifyCertificateP1, VerifyCertificateP2,
            certificateContent, pool, cancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Protects a Case 3 command (data, no response data) over the session, sends it, and reports whether the
    /// chip's protected response was a success status word.
    /// </summary>
    private static async ValueTask<bool> SendProtectedCommandAsync(
        ApduDevice device, SecureMessagingSession session, byte instruction, byte p1, byte p2, ReadOnlyMemory<byte> data, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using ProtectedCommandApdu protectedCommand = await session.ProtectCommandAsync(
            TerminalAuthenticationClass, instruction, p1, p2, data, expectedResponseLength: null, pool, cancellationToken).ConfigureAwait(false);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, protectedCommand.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            return false;
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess)
        {
            return false;
        }

        using SecureMessagingResponse unprotected = await session.UnprotectResponseAsync(
            response.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

        return unprotected.StatusWord.IsSuccess;
    }


    /// <summary>
    /// Writes the public-key reference data object <c>83 ‖ length ‖ reference</c> (ASCII) into
    /// <paramref name="destination"/>, returning the byte count.
    /// </summary>
    private static int WritePublicKeyReference(string publicKeyReference, int referenceLength, Span<byte> destination)
    {
        var writer = new BerTlvWriter(destination);
        writer.WriteHeader(PublicKeyReferenceTag, referenceLength);
        writer.WriteAscii(publicKeyReference);

        return writer.Written;
    }
}
