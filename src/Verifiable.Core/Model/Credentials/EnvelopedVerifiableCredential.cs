using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Wraps an enveloping-secured Verifiable Credential for inclusion in a
/// <see cref="VerifiablePresentation"/>, per W3C VC Data Model 2.0.
/// </summary>
/// <remarks>
/// <para>
/// An enveloping-secured credential (JOSE, COSE, SD-JWT, SD-CWT) is an opaque secured
/// string, not a JSON-LD credential object. To carry it inside a presentation's
/// <c>verifiableCredential</c> array, VC-DM 2.0 defines this type: its <see cref="Id"/>
/// is a <c>data:</c> URL (RFC 2397) whose media type identifies the securing format and
/// whose body is the secured credential, and its <see cref="Type"/> is
/// <c>"EnvelopedVerifiableCredential"</c>.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#presentations">VC-DM 2.0 §3.3
/// Presentations</see> and the EnvelopedVerifiableCredential definition therein.
/// </para>
/// </remarks>
[DebuggerDisplay("EnvelopedVerifiableCredential(Id = {Id})")]
public sealed class EnvelopedVerifiableCredential
{
    /// <summary>
    /// The JSON-LD context. Per VC-DM 2.0 the object's <c>@context</c> MUST be present
    /// and include a context that defines the <c>id</c>, <c>type</c>, and
    /// <c>EnvelopedVerifiableCredential</c> terms, such as
    /// <see cref="Common.Context.Credentials20"/>. When this object rides inside a
    /// presentation's <c>verifiableCredential</c> array the member is still emitted —
    /// the requirement is on the object itself.
    /// </summary>
    public Context? Context { get; set; }

    /// <summary>
    /// The <c>data:</c> URL (RFC 2397) carrying the enveloping-secured credential,
    /// for example <c>data:application/vc+jwt,&lt;compact-jws&gt;</c>.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// The credential type, which must include <c>"EnvelopedVerifiableCredential"</c>.
    /// </summary>
    public List<string>? Type { get; set; }
}
