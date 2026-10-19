namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Why an SD-CWT presented as an SD-CWT Key Binding Token (draft-ietf-spice-sd-cwt section 7.1) is a malformed presentation: a part
/// of it the reading that owns its wire shape refuses, its refusal being the reading's <see cref="FormatException"/>, never a
/// failure of a delegate the verification composes beyond its reading - the issuer-key resolver, the credential's verification,
/// the signature structure's encoder or a signature or digest backend. A reading that refuses with another exception, as a CBOR
/// reader's own content exception, states no refusal of the presentation, and that exception surfaces as a fault.
/// </summary>
public enum SdCwtPresentationDefect
{
    /// <summary>The <c>vp_token</c> value is no base64url text: the decoder refused it (RFC 4648 section 5).</summary>
    NotBase64UrlText,

    /// <summary>The Key Binding Token is no COSE_Sign1 (RFC 9052 section 4.2): its parse refused it.</summary>
    KeyBindingTokenMalformed,

    /// <summary>
    /// The embedded presentation SD-CWT is absent from the Key Binding Token's <c>kcwt</c> protected-header parameter or is no
    /// SD-CWT: its extraction or its parse refused it.
    /// </summary>
    EmbeddedCredentialMalformed,

    /// <summary>The embedded SD-CWT's <c>cnf</c> confirmation key is no COSE_Key the reading reconstructs: its reading refused it.</summary>
    HolderKeyMalformed,

    /// <summary>The Key Binding Token's payload claims (<c>aud</c>, <c>iat</c>, <c>cnonce</c>) are not of their defined types: their reading refused them.</summary>
    KeyBindingClaimsMalformed,

    /// <summary>The embedded SD-CWT's <c>iss</c>, <c>vct</c> or <c>status</c> claim is not of its defined type: its reading refused it.</summary>
    CredentialClaimMalformed,

    /// <summary>The embedded SD-CWT's <c>x5chain</c> is no chain of DER certificates: its extraction refused it.</summary>
    CertificateChainMalformed
}
