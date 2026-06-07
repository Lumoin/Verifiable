using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Expresses an enveloping-secured Verifiable Presentation, per W3C VC Data Model 2.0.
/// </summary>
/// <remarks>
/// <para>
/// An enveloping-secured presentation (JOSE, COSE) is an opaque secured string, not a
/// JSON-LD presentation object. VC-DM 2.0 defines this type to express it: the
/// <see cref="Context"/> MUST be present and include a context (such as the base
/// context) defining the <c>id</c>, <c>type</c>, and
/// <c>EnvelopedVerifiablePresentation</c> terms; the <see cref="Id"/> MUST be a
/// <c>data:</c> URL (RFC 2397) expressing the secured presentation, for example
/// <c>data:application/vp+jwt,&lt;compact-jws&gt;</c>; and the <see cref="Type"/> MUST
/// be <c>"EnvelopedVerifiablePresentation"</c>.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-presentations">
/// VC-DM 2.0 §4.13 Enveloped Verifiable Presentations</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("EnvelopedVerifiablePresentation(Id = {Id})")]
public sealed class EnvelopedVerifiablePresentation
{
    /// <summary>
    /// The JSON-LD context. MUST be present and include a context that defines the
    /// <c>id</c>, <c>type</c>, and <c>EnvelopedVerifiablePresentation</c> terms,
    /// such as <see cref="Common.Context.Credentials20"/>.
    /// </summary>
    public Context? Context { get; set; }

    /// <summary>
    /// The <c>data:</c> URL (RFC 2397) carrying the enveloping-secured presentation,
    /// for example <c>data:application/vp+jwt,&lt;compact-jws&gt;</c>.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// The type, which must be <c>"EnvelopedVerifiablePresentation"</c>.
    /// </summary>
    public List<string>? Type { get; set; }
}
