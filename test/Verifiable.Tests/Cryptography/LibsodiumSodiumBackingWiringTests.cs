using System;
using System.Buffers;
using Lumoin.Base;
using Lumoin.Base.Sodium;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests the wiring this repository owns between <see cref="Verifiable.Libsodium"/> and the family
    /// <see cref="SodiumBacking"/> allocator: constructing a <see cref="BaseMemoryPool"/> whose Native
    /// tier is backed by <see cref="SodiumBacking.Allocate(int)"/>, and confirming this project's own
    /// <c>libsodium</c> native asset reference is what makes <see cref="SodiumBacking.IsAvailable"/>
    /// observably <see langword="true"/> in this process — no separate native-asset wiring is needed
    /// beyond the <c>libsodium</c> NuGet package this project already references for its own P/Invoke
    /// bindings. The allocator MACHINERY itself (guard pages, canaries, mlock, zero-on-free) belongs to
    /// and is tested by the <c>Lumoin.Base.Sodium</c> package's own repository, not here. The Ed25519
    /// sign/keygen/private-key-conversion round trips that also exercise this scratch path end to end
    /// are already covered by <see cref="LibsodiumCryptographicTests"/> and are not duplicated here.
    /// </summary>
    [TestClass]
    internal sealed class LibsodiumSodiumBackingWiringTests
    {
        /// <summary>
        /// A <see cref="BaseMemoryPool"/> whose Native tier is backed by
        /// <see cref="SodiumBacking.Allocate(int)"/>, per <see cref="AllocationKind.Native"/> requests
        /// degrading is disallowed (a misconfiguration should surface, not silently fall back to pinned
        /// managed memory).
        /// </summary>
        private static BaseMemoryPool CreateSodiumBackedPool() =>
            new(SodiumBacking.Allocate, allowNativeDegradation: false, NativeRentMode.PerRentIsolated);


        /// <summary>
        /// Renting the <see cref="AllocationKind.Native"/> tier from a <see cref="SodiumBacking"/>-backed
        /// <see cref="BaseMemoryPool"/> round-trips written content and exposes exactly the requested
        /// length, never any rounding the family allocator performs internally.
        /// </summary>
        [TestMethod]
        public void NativeTierRentViaSodiumBackingRoundTripsContentAtExactRequestedLength()
        {
            using BaseMemoryPool pool = CreateSodiumBackedPool();
            byte[] expected = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            // An odd, non-page-aligned size so any leaked internal rounding would be visible.
            using IMemoryOwner<byte> owner = pool.Rent(37, AllocationKind.Native);
            expected.CopyTo(owner.Memory.Span);

            Assert.HasCount(37, owner.Memory, "The Native-tier rental must expose exactly the requested length.");
            Assert.IsTrue(
                owner.Memory.Span[..expected.Length].SequenceEqual(expected),
                "Content written to a SodiumBacking-backed Native-tier rental must read back unchanged.");
        }


        /// <summary>
        /// Many small <see cref="AllocationKind.Native"/> rentals, each disposed immediately, all succeed
        /// without exhausting the family allocator or corrupting later rentals — exercising the same
        /// <see cref="SodiumBacking.Allocate(int)"/>/dispose pair repeatedly through the pool.
        /// </summary>
        [TestMethod]
        public void NativeTierViaSodiumBackingSurvivesManySmallRentsAndDisposals()
        {
            using BaseMemoryPool pool = CreateSodiumBackedPool();
            Span<byte> expected = stackalloc byte[16];

            for(int i = 0; i < 64; i++)
            {
                byte fillValue = (byte)i;
                using IMemoryOwner<byte> owner = pool.Rent(16, AllocationKind.Native);
                owner.Memory.Span.Fill(fillValue);

                expected.Fill(fillValue);
                Assert.IsTrue(
                    owner.Memory.Span.SequenceEqual(expected),
                    $"Rental #{i} must round-trip its fill value without residue from a prior rental.");
            }
        }


        /// <summary>
        /// Configuring a <see cref="SodiumBacking"/>-backed Native tier does not disturb the pool's
        /// Managed or Pinned tiers: both still round-trip content correctly and independently of the
        /// Native tier's backing.
        /// </summary>
        [TestMethod]
        public void ManagedAndPinnedTiersUnaffectedBySodiumBackingNativeBacking()
        {
            using BaseMemoryPool pool = CreateSodiumBackedPool();
            byte[] managedExpected = [11, 22, 33];
            byte[] pinnedExpected = [44, 55, 66, 77];

            using IMemoryOwner<byte> managedOwner = pool.Rent(managedExpected.Length, AllocationKind.Managed);
            managedExpected.CopyTo(managedOwner.Memory.Span);

            using IMemoryOwner<byte> pinnedOwner = pool.Rent(pinnedExpected.Length, AllocationKind.Pinned);
            pinnedExpected.CopyTo(pinnedOwner.Memory.Span);

            Assert.HasCount(managedExpected.Length, managedOwner.Memory);
            Assert.IsTrue(
                managedOwner.Memory.Span.SequenceEqual(managedExpected),
                "The Managed tier must round-trip content independently of the Native tier's SodiumBacking.");

            Assert.HasCount(pinnedExpected.Length, pinnedOwner.Memory);
            Assert.IsTrue(
                pinnedOwner.Memory.Span.SequenceEqual(pinnedExpected),
                "The Pinned tier must round-trip content independently of the Native tier's SodiumBacking.");
        }


        /// <summary>
        /// <see cref="SodiumBacking.IsAvailable"/> observes the native library as loaded in this process
        /// purely because this project's own <c>libsodium</c> PackageReference already ships the native
        /// asset that <see cref="Verifiable.Libsodium"/>'s own P/Invokes resolve against: the family
        /// package carries no native asset of its own and needs none deployed separately.
        /// </summary>
        [TestMethod]
        public void SodiumBackingIsAvailableGivenThisProjectsOwnLibsodiumNativeAsset()
        {
            Assert.IsTrue(
                SodiumBacking.IsAvailable,
                "SodiumBacking.IsAvailable must observe the native library this project's own libsodium PackageReference already deploys.");
        }
    }
}
