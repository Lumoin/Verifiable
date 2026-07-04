namespace Verifiable.Keri;

/// <summary>
/// A KERI seal: a verifiable, nonrepudiable commitment to external serialized data, carried as a field map in an
/// event's anchor list (field <c>a</c>). A seal binds a digest of the external data to the key state at the seal's
/// location in the KEL, providing evidence of authenticity while keeping the data itself confidential. The concrete
/// seal types differ in what they commit to and how the committed item's context (such as its AID) is supplied.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#seals">
/// seals</see>. The field labels are <see cref="KeriSealFields"/>; the type is determined by which labels a seal
/// carries. These records are the post-decode, typed form a serializer-agnostic reader produces from a neutral
/// field map.
/// </para>
/// </remarks>
public abstract record KeriSeal;

/// <summary>
/// A digest seal: an undifferentiated cryptographic digest (field <c>d</c>) of some external data item; when the
/// data is a self-addressing data structure, the value is its SAID.
/// </summary>
/// <remarks>Seal count codes <c>-Q</c> / <c>--Q</c> (DigestSealSingles); field order <c>[d]</c>.</remarks>
/// <param name="Digest">The cryptographic digest of the external data (field <c>d</c>).</param>
public sealed record KeriDigestSeal(string Digest): KeriSeal;

/// <summary>
/// A Merkle tree root digest seal: the root (field <c>rd</c>) of a Merkle tree of digests of external data, a
/// compact commitment to a large number of data items that admits inclusion proofs without disclosing the tree.
/// </summary>
/// <remarks>Seal count codes <c>-R</c> / <c>--R</c> (MerkleRootSealSingles); field order <c>[rd]</c>.</remarks>
/// <param name="RootDigest">The Merkle tree root digest (field <c>rd</c>).</param>
public sealed record KeriMerkleRootSeal(string RootDigest): KeriSeal;

/// <summary>
/// A source event seal: a commitment to an event (an issuance, delegation, or transaction event) whose associated
/// AID is implied by the context in which the seal appears, providing an implicit endorsement of that event.
/// </summary>
/// <remarks>Seal count codes <c>-S</c> / <c>--S</c> (SealSourceCouples); field order <c>[s, d]</c>.</remarks>
/// <param name="SequenceNumber">The sequence number of the sealed source event (field <c>s</c>, decoded from hexadecimal).</param>
/// <param name="Said">The SAID of the sealed source event (field <c>d</c>).</param>
public sealed record KeriSourceEventSeal(long SequenceNumber, string Said): KeriSeal;

/// <summary>
/// A key event seal: a commitment to an event in another (external) event log, naming that log's AID explicitly,
/// used to endorse delegated events and external issuances.
/// </summary>
/// <remarks>Seal count codes <c>-T</c> / <c>--T</c> (SealSourceTriples); field order <c>[i, s, d]</c>.</remarks>
/// <param name="Prefix">The AID of the external event log (field <c>i</c>).</param>
/// <param name="SequenceNumber">The sequence number of the sealed external event (field <c>s</c>, decoded from hexadecimal).</param>
/// <param name="Said">The SAID of the sealed external event (field <c>d</c>).</param>
public sealed record KeriKeyEventSeal(string Prefix, long SequenceNumber, string Said): KeriSeal;

/// <summary>
/// A latest establishment event seal: a commitment to the key state of the latest establishment event of an
/// external KEL named by its AID (field <c>i</c>), without designating a specific event.
/// </summary>
/// <remarks>Seal count codes <c>-U</c> / <c>--U</c> (SealSourceLastSingles); field order <c>[i]</c>.</remarks>
/// <param name="Prefix">The AID of the external KEL whose latest establishment event is sealed (field <c>i</c>).</param>
public sealed record KeriLatestEstablishmentEventSeal(string Prefix): KeriSeal;

/// <summary>
/// A registrar backer seal: a commitment to the metadata SAD of a ledger registrar backer, required (with the
/// <c>RB</c> configuration trait) in the establishment event that designates a registrar backer.
/// </summary>
/// <remarks>Seal count codes <c>-V</c> / <c>--V</c> (BackerRegistrarSealCouples); field order <c>[bi, d]</c>.</remarks>
/// <param name="BackerIdentifier">The non-transferable AID of the registrar backer (field <c>bi</c>).</param>
/// <param name="Said">The SAID of the associated registrar backer metadata SAD (field <c>d</c>).</param>
public sealed record KeriRegistrarBackerSeal(string BackerIdentifier, string Said): KeriSeal;

/// <summary>
/// A typed seal: a digest commitment (field <c>d</c>) to external data tagged with a versioned seal type (field
/// <c>t</c>), a generic facility allowing different digest semantics and derivations (for example, different
/// Merkle tree constructions) each to be versioned independently.
/// </summary>
/// <remarks>Seal count codes <c>-W</c> / <c>--W</c> (TypedDigestSealCouples); field order <c>[t, d]</c>.</remarks>
/// <param name="SealType">The versioned seal type, a qb64 text primitive of four type plus three version characters (field <c>t</c>).</param>
/// <param name="Digest">The cryptographic digest of the external data (field <c>d</c>).</param>
public sealed record KeriTypedSeal(string SealType, string Digest): KeriSeal;
