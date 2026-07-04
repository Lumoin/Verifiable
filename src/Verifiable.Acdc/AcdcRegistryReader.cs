using System.Collections.Generic;
using System.Globalization;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// Reads a decoded ACDC registry event field map into a typed <see cref="AcdcRegistryEvent"/>. This is the
/// serialization-agnostic parse of a transaction-event-log registry event: it works on a neutral field map, so it
/// is identical whether the bytes were JSON, CBOR, MGPK, or CESR-native. It validates the fixed field set and order
/// the specification gives each event type and decodes the hexadecimal sequence number.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#registry-inception-event-fields">
/// registry inception</see> and <see href="https://trustoverip.github.io/kswg-acdc-specification/#update-event-fields">
/// update event</see> field definitions: a registry event has a fixed, fully required field set in a fixed order,
/// so the present fields MUST equal the event type's field order exactly. The non-blindable events <c>rip</c> and
/// <c>upd</c> are read here; the blindable update <c>bup</c>, whose blinded attribute SAID is a CESR-native
/// fixed-field computation, is read by a separate path not yet present.
/// </remarks>
public static class AcdcRegistryReader
{
    /// <summary>
    /// Reads a decoded registry event field map into its typed event.
    /// </summary>
    /// <param name="fields">The decoded field map in serialization order, keyed by <see cref="AcdcRegistryFields"/>.</param>
    /// <returns>The typed registry event.</returns>
    /// <exception cref="AcdcException">The message type is missing or not a non-blindable registry event, a field is missing or out of order, or the sequence number is not valid hexadecimal.</exception>
    public static AcdcRegistryEvent Read(MessageFieldMap fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        string messageType = RequireString(fields, AcdcRegistryFields.MessageType);

        return messageType switch
        {
            _ when messageType == AcdcMessageTypes.RegistryInception => ReadInception(fields),
            _ when messageType == AcdcMessageTypes.RegistryUpdate => ReadUpdate(fields),
            _ when messageType == AcdcMessageTypes.RegistryBlindableUpdate => throw new AcdcException("ACDC blindable registry update 'bup' is not modeled yet; its blinded attribute SAID is a CESR-native fixed-field computation."),
            _ => throw new AcdcException($"ACDC registry event has message type '{messageType}', which is not a non-blindable registry event ('rip' or 'upd').")
        };

        static RegistryInceptionEvent ReadInception(MessageFieldMap fields)
        {
            RequireExactOrder(fields, AcdcRegistryFields.InceptionFieldOrder);

            return new RegistryInceptionEvent(
                VersionString: RequireString(fields, AcdcRegistryFields.Version),
                Said: RequireString(fields, AcdcRegistryFields.Said),
                Uuid: RequireString(fields, AcdcRegistryFields.Uuid),
                Issuer: RequireString(fields, AcdcRegistryFields.Issuer),
                SequenceNumber: RequireSequenceNumber(fields),
                Datetime: RequireString(fields, AcdcRegistryFields.Datetime));
        }

        static RegistryUpdateEvent ReadUpdate(MessageFieldMap fields)
        {
            RequireExactOrder(fields, AcdcRegistryFields.UpdateFieldOrder);

            return new RegistryUpdateEvent(
                VersionString: RequireString(fields, AcdcRegistryFields.Version),
                Said: RequireString(fields, AcdcRegistryFields.Said),
                RegistryDigest: RequireString(fields, AcdcRegistryFields.RegistryDigest),
                SequenceNumber: RequireSequenceNumber(fields),
                PriorSaid: RequireString(fields, AcdcRegistryFields.PriorSaid),
                Datetime: RequireString(fields, AcdcRegistryFields.Datetime),
                TransactionAcdcSaid: RequireString(fields, AcdcRegistryFields.TransactionAcdcSaid),
                TransactionState: RequireString(fields, AcdcRegistryFields.TransactionState));
        }

        //Every field that appears MUST equal the event type's field order exactly: a registry event has a fixed,
        //fully required field set, so the present labels and their order must match the type's order one for one.
        static void RequireExactOrder(MessageFieldMap fields, IReadOnlyList<string> order)
        {
            if(fields.Count != order.Count)
            {
                throw new AcdcException($"ACDC registry event has {fields.Count} fields; its type requires exactly {order.Count} in a fixed order.");
            }

            int position = 0;
            foreach(string label in fields.Keys)
            {
                if(!string.Equals(label, order[position], StringComparison.Ordinal))
                {
                    throw new AcdcException($"ACDC registry event field '{label}' at position {position} is not the required field '{order[position]}'; registry event fields MUST appear in the fixed order the specification gives.");
                }

                position++;
            }
        }

        static string RequireString(MessageFieldMap fields, string label)
        {
            if(!fields.TryGetString(label, out string? text))
            {
                throw new AcdcException($"ACDC registry event is missing the required string field '{label}'.");
            }

            return text;
        }

        static long RequireSequenceNumber(MessageFieldMap fields)
        {
            string text = RequireString(fields, AcdcRegistryFields.SequenceNumber);
            if(!long.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long sequenceNumber) || sequenceNumber < 0)
            {
                throw new AcdcException($"ACDC registry event has an invalid hexadecimal sequence number '{text}'.");
            }

            return sequenceNumber;
        }
    }
}
