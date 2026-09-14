namespace Verifiable.Xml;

/// <summary>
/// Character classes and reserved character sequences of
/// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">Extensible Markup Language (XML) 1.0 (Fifth
/// Edition)</see> and
/// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>,
/// implemented directly from the productions so the reading surface has no platform XML dependency.
/// </summary>
internal static class XmlCharacters
{
    /// <summary>
    /// The namespace name the <c>xml</c> prefix is bound to by definition, per
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>
    /// section 3.
    /// </summary>
    public static ReadOnlySpan<byte> XmlNamespaceUri => "http://www.w3.org/XML/1998/namespace"u8;

    /// <summary>
    /// The namespace name the <c>xmlns</c> prefix is bound to by definition and that must never be declared,
    /// per <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3.
    /// </summary>
    public static ReadOnlySpan<byte> XmlnsNamespaceUri => "http://www.w3.org/2000/xmlns/"u8;

    /// <summary>
    /// The reserved <c>xml</c> prefix.
    /// </summary>
    public static ReadOnlySpan<byte> XmlPrefix => "xml"u8;

    /// <summary>
    /// The reserved <c>xmlns</c> prefix.
    /// </summary>
    public static ReadOnlySpan<byte> XmlnsPrefix => "xmlns"u8;


    /// <summary>
    /// Tells whether the octet is white space per production <c>S</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.3:
    /// <c>(#x20 | #x9 | #xD | #xA)</c>.
    /// </summary>
    /// <param name="octet">The octet to classify.</param>
    /// <returns><see langword="true"/> when the octet is XML white space.</returns>
    public static bool IsWhitespace(byte octet)
    {
        return octet is 0x20 or 0x09 or 0x0D or 0x0A;
    }


    /// <summary>
    /// Tells whether the code point is a legal XML character per production <c>Char</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.2:
    /// <c>#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]</c>. The boolean
    /// expression below mirrors the production's own alternation one range at a time; a named predicate
    /// per range would only rename the citation, not simplify it.
    /// </summary>
    /// <param name="codePoint">The Unicode code point to classify.</param>
    /// <returns><see langword="true"/> when the code point matches <c>Char</c>.</returns>
    public static bool IsChar(int codePoint)
    {
        return codePoint is 0x9 or 0xA or 0xD
            or (>= 0x20 and <= 0xD7FF) or (>= 0xE000 and <= 0xFFFD) or (>= 0x10000 and <= 0x10FFFF);
    }


    /// <summary>
    /// Tells whether the code point may start a colon-free name, per production <c>NameStartChar</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.3
    /// with the colon removed, which is the first character of production <c>NCName</c> of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>
    /// section 3. The boolean expression below mirrors the production's own alternation one range at a
    /// time; a named predicate per range would only rename the citation, not simplify it.
    /// </summary>
    /// <param name="codePoint">The Unicode code point to classify.</param>
    /// <returns><see langword="true"/> when the code point may start an <c>NCName</c>.</returns>
    public static bool IsNameStartCharacter(int codePoint)
    {
        return codePoint is (>= 'A' and <= 'Z') or '_'
            or (>= 'a' and <= 'z') or (>= 0xC0 and <= 0xD6) or (>= 0xD8 and <= 0xF6) or (>= 0xF8 and <= 0x2FF) or (>= 0x370 and <= 0x37D) or (>= 0x37F and <= 0x1FFF) or (>= 0x200C and <= 0x200D) or (>= 0x2070 and <= 0x218F) or (>= 0x2C00 and <= 0x2FEF) or (>= 0x3001 and <= 0xD7FF) or (>= 0xF900 and <= 0xFDCF) or (>= 0xFDF0 and <= 0xFFFD) or (>= 0x10000 and <= 0xEFFFF);
    }


    /// <summary>
    /// Tells whether the code point may continue a colon-free name, per production <c>NameChar</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.3
    /// with the colon removed: <c>NameStartChar | "-" | "." | [0-9] | #xB7 | [#x0300-#x036F] |
    /// [#x203F-#x2040]</c>. The boolean expression below mirrors the production's own alternation one
    /// alternative at a time; a named predicate per alternative would only rename the citation, not
    /// simplify it.
    /// </summary>
    /// <param name="codePoint">The Unicode code point to classify.</param>
    /// <returns><see langword="true"/> when the code point may continue an <c>NCName</c>.</returns>
    public static bool IsNameCharacter(int codePoint)
    {
        return IsNameStartCharacter(codePoint)
            || codePoint == '-'
            || codePoint == '.'
            || (codePoint >= '0' && codePoint <= '9')
            || codePoint == 0xB7
            || (codePoint >= 0x300 && codePoint <= 0x36F)
            || (codePoint >= 0x203F && codePoint <= 0x2040);
    }


    /// <summary>
    /// Tells whether the URI reference is absolute by the syntactic discrimination of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">IETF RFC 3986 section 4.2</see>: a
    /// reference is absolute exactly when it begins with a <c>scheme ":"</c>, where <c>scheme</c> is
    /// <c>ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )</c> per section 3.1. The comparison is over exact
    /// octets; nothing is normalized or resolved. The scheme-character check below mirrors the
    /// <c>ALPHA / DIGIT / "+" / "-" / "."</c> alternation directly; a named predicate per alternative
    /// would only rename the citation, not simplify it.
    /// </summary>
    /// <param name="uriReference">The URI reference octets.</param>
    /// <returns><see langword="true"/> when the reference carries a scheme.</returns>
    public static bool IsAbsoluteUri(ReadOnlySpan<byte> uriReference)
    {
        if(uriReference.Length == 0)
        {
            return false;
        }

        byte first = uriReference[0];
        bool isAlpha = first is (>= ((byte)'A') and <= ((byte)'Z')) or (>= ((byte)'a') and <= ((byte)'z'));
        if(!isAlpha)
        {
            return false;
        }

        for(int i = 1; i < uriReference.Length; ++i)
        {
            byte octet = uriReference[i];
            if(octet == (byte)':')
            {
                return true;
            }

            bool isSchemeCharacter = octet is (>= ((byte)'A') and <= ((byte)'Z')) or (>= ((byte)'a') and <= ((byte)'z')) or (>= ((byte)'0') and <= ((byte)'9')) or (byte)'+' or (byte)'-' or (byte)'.';
            if(!isSchemeCharacter)
            {
                return false;
            }
        }

        return false;
    }


    /// <summary>
    /// Maps the name of one of the five predefined entities of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 4.6
    /// (<c>amp</c>, <c>lt</c>, <c>gt</c>, <c>apos</c>, <c>quot</c>) to its replacement character. These are
    /// the only entities a document with no document type declaration may reference, per the Entity Declared
    /// well-formedness constraint of section 4.1.
    /// </summary>
    /// <param name="entityName">The entity name between <c>&amp;</c> and <c>;</c>.</param>
    /// <param name="replacement">The replacement character octet.</param>
    /// <returns><see langword="true"/> when the name is one of the five predefined entities.</returns>
    public static bool TryGetPredefinedEntityReplacement(ReadOnlySpan<byte> entityName, out byte replacement)
    {
        if(entityName.SequenceEqual("amp"u8))
        {
            replacement = (byte)'&';

            return true;
        }

        if(entityName.SequenceEqual("lt"u8))
        {
            replacement = (byte)'<';

            return true;
        }

        if(entityName.SequenceEqual("gt"u8))
        {
            replacement = (byte)'>';

            return true;
        }

        if(entityName.SequenceEqual("apos"u8))
        {
            replacement = (byte)'\'';

            return true;
        }

        if(entityName.SequenceEqual("quot"u8))
        {
            replacement = (byte)'"';

            return true;
        }

        replacement = 0;

        return false;
    }
}
