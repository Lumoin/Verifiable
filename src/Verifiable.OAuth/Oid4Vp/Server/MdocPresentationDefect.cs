namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Why an mdoc VP token (ISO/IEC 18013-5 <c>DeviceResponse</c>, OID4VP 1.0 Appendix B.2) is a malformed presentation: a part of it
/// the reading that owns its wire shape refuses, before or while it is read, never a failure of a delegate the verification
/// composes beyond its reading.
/// </summary>
public enum MdocPresentationDefect
{
    /// <summary>The <c>vp_token</c> value is no base64url text: the decoder refused it (RFC 4648 section 5).</summary>
    NotBase64UrlText,

    /// <summary>The <c>DeviceResponse</c> the value decodes to is no CBOR structure of the shape ISO/IEC 18013-5 section 8.3.2.1.2.2 defines: its parse refused it.</summary>
    DeviceResponseMalformed,

    /// <summary>A document's <c>IssuerAuth</c> is no COSE_Sign1 (RFC 9052 section 4.2): its parse refused it.</summary>
    IssuerAuthMalformed,

    /// <summary>A document's device signature is no COSE_Sign1 with a detached payload (ISO/IEC 18013-5 section 9.1.3.4): its parse refused it.</summary>
    DeviceSignatureMalformed,

    /// <summary>The device key the Mobile Security Object commits to is no COSE_Key the library reconstructs: its reading refused it.</summary>
    DeviceKeyMalformed,

    /// <summary>An issuer-signed item's element value is no CBOR value its decoding reads: the decoding refused it.</summary>
    ElementValueMalformed
}
