namespace Verifiable.Acdc;

/// <summary>
/// A typed, serialization-agnostic ACDC field-map message body (message type <c>acm</c>): the top-level fields of an
/// Authentic Chained Data Container, with each section held as an <see cref="AcdcSection"/> that is either the
/// section's SAID (compact) or its expanded block. This is produced by <see cref="AcdcReader"/> from a decoded
/// field map and is independent of the serialization the bytes arrived in.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#top-level-fields">
/// top-level fields</see>. The presence or absence of the UUID, <c>u</c>, determines the privacy variant: absent is
/// a public ACDC, a high-entropy value is a private ACDC, and an empty string is a metadata ACDC. The attribute
/// section, <c>a</c>, and the aggregate section, <c>A</c>, are mutually exclusive, so at most one of
/// <see cref="Attribute"/> and <see cref="Aggregate"/> is non-<see langword="null"/>.
/// </para>
/// </remarks>
/// <param name="VersionString">The version string <c>v</c>: protocol, version, serialization, and size.</param>
/// <param name="MessageType">The message type <c>t</c>: <c>acm</c> (explicit, or implied when absent in a field map).</param>
/// <param name="Said">The top-level SAID <c>d</c>, taken over the ACDC's most-compact form.</param>
/// <param name="Uuid">The UUID <c>u</c>, or <see langword="null"/> when absent (a public ACDC); an empty string denotes a metadata ACDC.</param>
/// <param name="Issuer">The issuer AID <c>i</c>, whose control authority is established via KERI key state.</param>
/// <param name="RegistryDigest">The registry SAID <c>rd</c>, or <see langword="null"/> when absent.</param>
/// <param name="Schema">The schema section <c>s</c> (required).</param>
/// <param name="Attribute">The attribute section <c>a</c>, or <see langword="null"/> when absent; mutually exclusive with <paramref name="Aggregate"/>.</param>
/// <param name="Aggregate">The selectively disclosable aggregate section <c>A</c>, or <see langword="null"/> when absent; mutually exclusive with <paramref name="Attribute"/>.</param>
/// <param name="Edge">The edge section <c>e</c>, or <see langword="null"/> when absent.</param>
/// <param name="Rule">The rule section <c>r</c>, or <see langword="null"/> when absent.</param>
public sealed record AcdcMessage(
    string VersionString,
    string MessageType,
    string Said,
    string? Uuid,
    string Issuer,
    string? RegistryDigest,
    AcdcSection Schema,
    AcdcSection? Attribute,
    AcdcAggregateSection? Aggregate,
    AcdcSection? Edge,
    AcdcSection? Rule);
