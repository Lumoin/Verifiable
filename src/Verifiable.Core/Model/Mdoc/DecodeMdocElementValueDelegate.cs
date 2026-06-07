using System;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Decodes a CBOR-encoded <c>IssuerSignedItem</c> element value
/// (<see cref="MdocIssuerSignedItem.EncodedElementValue"/>) into its string
/// representation for surfacing as an extracted claim.
/// </summary>
/// <remarks>
/// <para>
/// The CBOR seam the mdoc VP-token verifier composes but does not perform
/// itself — element values arrive as raw CBOR and the OID4VP flow layer cannot
/// decode CBOR. Wired by the application to a small adapter over
/// <c>Verifiable.Cbor.CborValueConverter.ReadValue</c> that renders the decoded
/// CLR value as a string.
/// </para>
/// </remarks>
/// <param name="encodedElementValue">The raw CBOR encoding of one element value.</param>
/// <returns>The decoded value's string representation.</returns>
public delegate string DecodeMdocElementValueDelegate(ReadOnlyMemory<byte> encodedElementValue);
