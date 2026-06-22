using System.Buffers;
using Verifiable.Core.Model.Did;

namespace Verifiable.DidComm;

/// <summary>
/// Pack and unpack for DIDComm plaintext messages — the building block the signed and encrypted
/// envelopes wrap, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#didcomm-plaintext-messages">DIDComm Messaging v2.1 §DIDComm Plaintext Messages</see>.
/// </summary>
/// <remarks>
/// Plaintext on its own has no confidentiality, integrity, or authenticity guarantees and is not
/// normally transported across a security boundary; it is the application-level form that signing
/// and encryption protect. Pack serializes a validated message to
/// <c>application/didcomm-plain+json</c>; unpack parses and applies the §Message Headers
/// structural requirements.
/// </remarks>
public static class DidCommPlaintextExtensions
{
    /// <summary>
    /// Validates the required headers and serializes <paramref name="message"/> to its
    /// <c>application/didcomm-plain+json</c> bytes.
    /// </summary>
    /// <param name="message">The message to pack.</param>
    /// <param name="serializer">The serializer producing the plaintext JWM artifact.</param>
    /// <param name="memoryPool">The pool the returned artifact's owned buffer is drawn from.</param>
    /// <returns>The validated <see cref="DidCommPlaintextMessage"/> wire artifact.</returns>
    /// <exception cref="FormatException">Thrown when the message violates a structural requirement.</exception>
    public static DidCommPlaintextMessage PackPlaintext(this DidCommMessage message, DidCommMessageSerializer serializer, MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(serializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        ValidateStructure(message);

        return serializer(message, memoryPool);
    }


    /// <summary>
    /// Parses <paramref name="plaintextMessage"/> and validates the §Message Headers structural
    /// requirements, returning the validated message.
    /// </summary>
    /// <param name="plaintextMessage">The serialized plaintext message artifact.</param>
    /// <param name="parser">The parser producing the message from the plaintext bytes.</param>
    /// <returns>The parsed and validated message.</returns>
    /// <exception cref="FormatException">Thrown when the message violates a structural requirement.</exception>
    public static DidCommMessage UnpackPlaintext(this DidCommPlaintextMessage plaintextMessage, DidCommMessageParser parser)
    {
        ArgumentNullException.ThrowIfNull(plaintextMessage);

        return UnpackPlaintext(plaintextMessage.AsReadOnlySpan(), parser);
    }


    /// <summary>
    /// Parses <paramref name="plaintextJson"/> and validates the §Message Headers structural
    /// requirements, returning the validated message.
    /// </summary>
    /// <param name="plaintextJson">The UTF-8 <c>application/didcomm-plain+json</c> bytes.</param>
    /// <param name="parser">The parser producing the message from the plaintext bytes.</param>
    /// <returns>The parsed and validated message.</returns>
    /// <exception cref="FormatException">Thrown when the message violates a structural requirement.</exception>
    public static DidCommMessage UnpackPlaintext(ReadOnlySpan<byte> plaintextJson, DidCommMessageParser parser)
    {
        ArgumentNullException.ThrowIfNull(parser);

        DidCommMessage message = parser(plaintextJson);
        ValidateStructure(message);

        return message;
    }


    //The structural requirements common to producing and consuming a plaintext message
    //(DIDComm v2.1 §Message Headers). The integer typing of created_time / expires_time is enforced
    //by the parser at the wire level; unknown headers are preserved by the parser into
    //AdditionalHeaders and are intentionally not validated here.
    private static void ValidateStructure(DidCommMessage message)
    {
        if(string.IsNullOrEmpty(message.Id))
        {
            throw new FormatException(
                "A DIDComm plaintext message MUST carry a non-empty 'id' header (DIDComm v2.1 §Message Headers).");
        }

        if(string.IsNullOrEmpty(message.Type))
        {
            throw new FormatException(
                "A DIDComm plaintext message MUST carry a non-empty 'type' header (DIDComm v2.1 §Message Headers).");
        }

        if(!MessageTypeUri.TryParse(message.Type, out _))
        {
            throw new FormatException(
                $"The DIDComm message 'type' '{message.Type}' is not a valid Message Type URI " +
                "(DIDComm v2.1 §Message Type URI).");
        }

        if(message.To is not null)
        {
            foreach(string recipient in message.To)
            {
                if(!IsValidRecipientIdentifier(recipient))
                {
                    throw new FormatException(
                        $"The DIDComm 'to' entry '{recipient}' MUST be a DID or DID URL without a " +
                        "fragment component (DIDComm v2.1 §Message Headers).");
                }
            }
        }

        //The sender identifier, when present, is likewise a DID or DID URL without a fragment.
        if(message.From is not null && !IsValidRecipientIdentifier(message.From))
        {
            throw new FormatException(
                $"The DIDComm 'from' header '{message.From}' MUST be a DID or DID URL without a " +
                "fragment component (DIDComm v2.1 §Message Headers).");
        }
    }


    //A 'to' entry MUST be a valid DID or DID URL without the fragment component: an absolute DID
    //URL (carrying a method and method-specific id) whose fragment is absent.
    private static bool IsValidRecipientIdentifier(string identifier)
    {
        if(string.IsNullOrEmpty(identifier) || !DidUrl.TryParse(identifier, out DidUrl? didUrl))
        {
            return false;
        }

        return didUrl.IsAbsolute
            && !string.IsNullOrEmpty(didUrl.Method)
            && !string.IsNullOrEmpty(didUrl.MethodSpecificId)
            && string.IsNullOrEmpty(didUrl.Fragment);
    }
}
