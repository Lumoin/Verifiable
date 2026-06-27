using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates ICAO Doc 9303 Part 11 Basic Access Control against the worked example in Appendix D.2
/// (MRZ-derived access keys) and Appendix D.3 (mutual authentication and session establishment),
/// then composes the established session into the Appendix D.4 Secure Messaging protect step.
/// </summary>
/// <remarks>
/// <para>
/// The mutual-authentication exchange runs against a <see cref="VirtualCard"/> registered with the
/// exact GET CHALLENGE and EXTERNAL AUTHENTICATE command/response pairs from Appendix D.3. Because
/// the card matches commands by content, a passing exchange also proves Basic Access Control built
/// the correct <c>EIFD || MIFD</c> token. Driving the resulting session's protect step to the
/// Appendix D.4 byte string proves the derived KSenc / KSmac / SSC are correct end to end.
/// </para>
/// </remarks>
[TestClass]
internal sealed class BasicAccessControlTests
{
    //The TD2 worked example of Appendix D.2: document number L898902C<, DOB 690806, expiry 940623.
    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";
    private const string MrzInformation = "L898902C<369080619406236";

    //Appendix D.3 terminal randomness.
    private const string TerminalNonce = "781723860C06C226";
    private const string TerminalKeyingMaterial = "0B795240CB7049B01C19B33E32804F0B";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public void ComputesMrzCheckDigitsPerAppendixD2()
    {
        Assert.AreEqual('3', BasicAccessControl.ComputeCheckDigit(DocumentNumber), "Document number check digit.");
        Assert.AreEqual('1', BasicAccessControl.ComputeCheckDigit(DateOfBirth), "Date of birth check digit.");
        Assert.AreEqual('6', BasicAccessControl.ComputeCheckDigit(DateOfExpiry), "Date of expiry check digit.");
    }


    [TestMethod]
    public void BuildsMrzInformationPerAppendixD2()
    {
        Assert.AreEqual(MrzInformation,
            BasicAccessControl.BuildMrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry),
            "The MRZ information must concatenate each field with its check digit.");
    }


    [TestMethod]
    public async Task DerivesAccessKeysPerAppendixD2()
    {
        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) =
            await BasicAccessControl.DeriveAccessKeysAsync(MrzInformation, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreEqual("AB94FDECF2674FDFB9B391F85D7F76F2", Convert.ToHexString(encryptionKey.AsReadOnlySpan()),
                "KEnc must match Doc 9303 Appendix D.2.");
            Assert.AreEqual("7962D9ECE03D1ACD4C76089DCE131543", Convert.ToHexString(macKey.AsReadOnlySpan()),
                "KMAC must match Doc 9303 Appendix D.2.");
        }
        finally
        {
            encryptionKey.Dispose();
            macKey.Dispose();
        }
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The access keys are disposed in the finally block; the session takes ownership of the derived session keys and is disposed via its using declaration.")]
    public async Task EstablishesSessionAndProtectsTheAppendixD3AndD4Exchange()
    {
        var card = new VirtualCard();
        //GET CHALLENGE -> RND.IC (Appendix D.3).
        card.Register(Convert.FromHexString("0084000008"), Convert.FromHexString("4608F919887022129000"));
        //EXTERNAL AUTHENTICATE(EIFD || MIFD) -> EIC || MIC (Appendix D.3).
        card.Register(
            Convert.FromHexString("008200002872C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A728"),
            Convert.FromHexString("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D74499000"));

        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) =
            await BasicAccessControl.DeriveAccessKeysAsync(MrzInformation, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using SecureMessagingSession session = await BasicAccessControl.EstablishSessionAsync(
                device, encryptionKey, macKey,
                Convert.FromHexString(TerminalNonce), Convert.FromHexString(TerminalKeyingMaterial),
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            //The derived session must protect SELECT EF.COM to the Appendix D.4 byte string.
            using ProtectedCommandApdu protectedSelect = await session.ProtectCommandAsync(
                0x00, 0xA4, 0x02, 0x0C, Convert.FromHexString("011E"), null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800",
                Convert.ToHexString(protectedSelect.AsReadOnlySpan()),
                "The session established by BAC must protect SELECT exactly as Appendix D.4 shows.");
        }
        finally
        {
            encryptionKey.Dispose();
            macKey.Dispose();
        }
    }
}
