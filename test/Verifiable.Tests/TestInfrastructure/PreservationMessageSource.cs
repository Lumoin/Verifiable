using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Builds the messages and payloads of the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> that the protocol-vocabulary tests put under test, and counts what a pool hands
/// out so that "the message disposes everything it owns" can be asserted rather than assumed.
/// </summary>
/// <remarks>
/// Every payload is rented from the pool the caller supplies and every builder documents who disposes what, the
/// same discipline the library's own contexts and results state.
/// </remarks>
internal static class PreservationMessageSource
{
    /// <summary>Builds one preservation object carrying the octets of a piece of text.</summary>
    /// <param name="content">The text the object carries.</param>
    /// <param name="pool">The pool the payload carrier is rented from.</param>
    /// <param name="formatId">The format identifier, or <see langword="null"/> to state a media type instead.</param>
    /// <param name="mimeType">The media type, or <see langword="null"/>.</param>
    /// <param name="contentForm">Which alternative of the value choice the octets came from.</param>
    /// <returns>The object. The caller, or the message it is put into, disposes it.</returns>
    internal static PreservationObject Object(
        string content,
        MemoryPool<byte> pool,
        string? formatId = "http://uri.etsi.org/ades/CAdES",
        string? mimeType = null,
        PreservationContentForm contentForm = PreservationContentForm.BinaryData) =>
        new()
        {
            Content = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(content), pool, PreservationTags.PreservationObject),
            ContentForm = contentForm,
            FormatId = formatId,
            MimeType = mimeType
        };


    /// <summary>Builds one preservation evidence carrying the octets of a piece of text.</summary>
    /// <param name="content">The text the evidence carries.</param>
    /// <param name="pool">The pool the payload carrier is rented from.</param>
    /// <param name="formatId">The evidence format identifier, which the evidence component makes mandatory.</param>
    /// <returns>The evidence. The caller, or the message it is put into, disposes it.</returns>
    internal static PreservationEvidence Evidence(
        string content,
        MemoryPool<byte> pool,
        string? formatId = null) =>
        new()
        {
            Content = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(content), pool, PreservationTags.PreservationEvidence),
            ContentForm = PreservationContentForm.BinaryData,
            FormatId = formatId ?? PreservationFormatWellKnown.EvidenceRecordEvidenceFormat
        };


    /// <summary>Builds one sub-component carried verbatim, of the kind the base components and a profile admit.</summary>
    /// <param name="content">The octets the peer's syntax stated for the sub-component.</param>
    /// <param name="pool">The pool the carrier is rented from.</param>
    /// <param name="identifier">What the syntax named it, or <see langword="null"/>.</param>
    /// <returns>The element. The caller, or the message it is put into, disposes it.</returns>
    internal static PreservationOpaqueElement OpaqueElement(string content, MemoryPool<byte> pool, string? identifier = null) =>
        new()
        {
            Content = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(content), pool, PreservationTags.OpaqueElement),
            Identifier = identifier
        };


    /// <summary>
    /// Builds a profile that satisfies every obligation clause 5.4.7 states — the identifier, one operation, one
    /// policy, the validity period, the storage model, one goal and one evidence format.
    /// </summary>
    /// <param name="storageModel">The storage model the profile announces.</param>
    /// <param name="retentionPeriod">The evidence retention period, which a temporary-storage profile has to state.</param>
    /// <param name="extensions">The extensions the profile carries; the profile disposes them.</param>
    /// <returns>The profile. The caller, or the response it is put into, disposes it.</returns>
    internal static PreservationProfile Profile(
        string? storageModel = null,
        string? retentionPeriod = null,
        IReadOnlyList<PreservationOpaqueElement>? extensions = null) =>
        new()
        {
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            Operations =
            [
                new PreservationOperationDescriptor
                {
                    Name = PreservationWellKnown.RetrieveInfoOperation
                },
                new PreservationOperationDescriptor
                {
                    Name = PreservationWellKnown.PreservePreservationObjectOperation,
                    InputFormats = [new PreservationFormatDescriptor { FormatId = PreservationFormatWellKnown.CadesSignatureFormat }],
                    OutputFormats = [new PreservationFormatDescriptor { FormatId = PreservationFormatWellKnown.EvidenceRecordContainerFormat }]
                }
            ],
            Policies = [new PreservationPolicyReference { PolicyType = PreservationWellKnown.PreservationEvidencePolicyType }],
            ValidityPeriod = new PreservationValidityPeriod { ValidFrom = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero) },
            StorageModel = storageModel ?? PreservationWellKnown.WithStorageModel,
            PreservationGoals = [PreservationWellKnown.GeneralDataGoal],
            EvidenceFormats = [new PreservationFormatDescriptor { FormatId = PreservationFormatWellKnown.EvidenceRecordEvidenceFormat }],
            SchemeIdentifier = PreservationWellKnown.StorageWithEvidenceRecordsScheme,
            PreservationEvidenceRetentionPeriod = retentionPeriod,
            Extensions = extensions ?? []
        };


    /// <summary>Builds the result component a successful response carries.</summary>
    /// <param name="resultMinor">The minor code, which on a success is a warning or nothing at all.</param>
    /// <returns>The result.</returns>
    internal static PreservationResult SuccessfulResult(string? resultMinor = null) =>
        new()
        {
            ResultMajor = "urn:oasis:names:tc:dss:1.0:resultmajor:Success",
            ResultMinor = resultMinor
        };


    /// <summary>
    /// A memory pool that counts what it hands out and what comes back, delegating every rental to the house pool
    /// so that rentals stay exact-length.
    /// </summary>
    /// <remarks>
    /// It exists for one assertion the protocol vocabulary needs and nothing else can make: a message owns a tree
    /// of payload carriers, and disposing the message has to return every one of them. Counting is the only way
    /// to see that from outside.
    /// </remarks>
    internal sealed class CountingMemoryPool: MemoryPool<byte>
    {
        /// <summary>How many carriers have been rented from this pool.</summary>
        private int rentedCount;

        /// <summary>How many of them have been returned.</summary>
        private int returnedCount;


        /// <summary>How many carriers this pool has handed out.</summary>
        internal int RentedCount => Volatile.Read(ref rentedCount);

        /// <summary>How many of the handed-out carriers have been disposed.</summary>
        internal int ReturnedCount => Volatile.Read(ref returnedCount);

        /// <summary>How many carriers are still outstanding.</summary>
        internal int OutstandingCount => RentedCount - ReturnedCount;

        /// <summary>The largest buffer the underlying house pool serves.</summary>
        public override int MaxBufferSize => BaseMemoryPool.Shared.MaxBufferSize;


        /// <summary>Rents a carrier from the house pool and counts it out.</summary>
        /// <param name="minBufferSize">The number of octets wanted.</param>
        /// <returns>The rented carrier, which counts itself back in when it is disposed.</returns>
        public override IMemoryOwner<byte> Rent(int minBufferSize = -1)
        {
            IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(minBufferSize);
            _ = Interlocked.Increment(ref rentedCount);

            return new CountedOwner(this, owner);
        }


        /// <summary>Releases nothing: this pool owns no resource of its own.</summary>
        /// <param name="disposing">Whether managed state is being released.</param>
        protected override void Dispose(bool disposing)
        {
        }


        /// <summary>Counts one carrier back in when whoever holds it disposes it.</summary>
        private void Return() => Interlocked.Increment(ref returnedCount);


        /// <summary>One rented carrier that tells its pool when it is disposed.</summary>
        /// <param name="pool">The pool that handed it out.</param>
        /// <param name="inner">The carrier the house pool rented.</param>
        private sealed class CountedOwner(CountingMemoryPool pool, IMemoryOwner<byte> inner): IMemoryOwner<byte>
        {
            /// <summary>Whether this carrier has already been returned, so a double dispose counts once.</summary>
            private bool isReturned;


            /// <summary>The rented buffer, exactly as the house pool served it.</summary>
            public Memory<byte> Memory => inner.Memory;


            /// <summary>Returns the buffer to the house pool and counts it in.</summary>
            public void Dispose()
            {
                if(!isReturned)
                {
                    isReturned = true;
                    pool.Return();
                }

                inner.Dispose();
            }
        }
    }
}
