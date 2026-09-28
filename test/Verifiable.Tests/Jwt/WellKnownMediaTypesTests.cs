using System.Text;
using Verifiable.JCose;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vci.Wallet;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jwt
{
    /// <summary>
    /// Tests that canonicalization of media type values works correctly.
    /// </summary>
    [TestClass]
    internal sealed class WellKnownMediaTypesTests
    {
        /// <summary>
        /// The application media types exercised by <see cref="ApplicationMediaTypeValuesCompareCorrectly"/>.
        /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 Section 8.3.1</see>:
        /// "The type and subtype tokens are case-insensitive."
        /// </summary>
        public static IEnumerable<object[]> GetApplicationMediaTypeValues()
        {
            yield return new object[] { WellKnownMediaTypes.Application.VcLdJwt, new Func<string, bool>(WellKnownMediaTypes.Application.IsVcLdJwt) };
            yield return new object[] { WellKnownMediaTypes.Application.VpLdJwt, new Func<string, bool>(WellKnownMediaTypes.Application.IsVpLdJwt) };
            yield return new object[] { WellKnownMediaTypes.Application.VcJwt, new Func<string, bool>(WellKnownMediaTypes.Application.IsVcJwt) };
            yield return new object[] { WellKnownMediaTypes.Application.VpJwt, new Func<string, bool>(WellKnownMediaTypes.Application.IsVpJwt) };
            yield return new object[] { WellKnownMediaTypes.Application.VcLdCose, new Func<string, bool>(WellKnownMediaTypes.Application.IsVcLdCose) };
            yield return new object[] { WellKnownMediaTypes.Application.VpLdCose, new Func<string, bool>(WellKnownMediaTypes.Application.IsVpLdCose) };
            yield return new object[] { WellKnownMediaTypes.Application.VcCose, new Func<string, bool>(WellKnownMediaTypes.Application.IsVcCose) };
            yield return new object[] { WellKnownMediaTypes.Application.VpCose, new Func<string, bool>(WellKnownMediaTypes.Application.IsVpCose) };
            yield return new object[] { WellKnownMediaTypes.Application.Json, new Func<string, bool>(WellKnownMediaTypes.Application.IsJson) };
            yield return new object[] { WellKnownMediaTypes.Application.ProblemJson, new Func<string, bool>(WellKnownMediaTypes.Application.IsProblemJson) };
            yield return new object[] { WellKnownMediaTypes.Application.ClientAuthenticationJwt, new Func<string, bool>(WellKnownMediaTypes.Application.IsClientAuthenticationJwt) };
            yield return new object[] { WellKnownMediaTypes.Application.FormUrlEncoded, new Func<string, bool>(WellKnownMediaTypes.Application.IsFormUrlEncoded) };
        }


        /// <summary>
        /// The JWT type values exercised by <see cref="JwtTypValuesCompareCorrectly"/>.
        /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 Section 8.3.1</see>:
        /// "The type and subtype tokens are case-insensitive."
        /// </summary>
        public static IEnumerable<object[]> GetJwtTypValues()
        {
            yield return new object[] { WellKnownMediaTypes.Jwt.VcLdJwt, new Func<string, bool>(WellKnownMediaTypes.Jwt.IsVcLdJwt) };
            yield return new object[] { WellKnownMediaTypes.Jwt.VpLdJwt, new Func<string, bool>(WellKnownMediaTypes.Jwt.IsVpLdJwt) };
            yield return new object[] { WellKnownMediaTypes.Jwt.VcJwt, new Func<string, bool>(WellKnownMediaTypes.Jwt.IsVcJwt) };
            yield return new object[] { WellKnownMediaTypes.Jwt.VpJwt, new Func<string, bool>(WellKnownMediaTypes.Jwt.IsVpJwt) };
            yield return new object[] { WellKnownMediaTypes.Jwt.ClientAuthenticationJwt, new Func<string, bool>(WellKnownMediaTypes.Jwt.IsClientAuthenticationJwt) };
        }


        /// <summary>
        /// The local catalog recognizes each media type through its predicate and canonical instance.
        /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 Section 8.3.1</see>:
        /// "The type and subtype tokens are case-insensitive."
        /// </summary>
        /// <param name="mediaType">The media type to test.</param>
        /// <param name="isCorrectMediaType">The function that checks if the media type is recognized.</param>
        [TestMethod]
        [DynamicData(nameof(GetApplicationMediaTypeValues))]
        public void ApplicationMediaTypeValuesCompareCorrectly(string mediaType, Func<string, bool> isCorrectMediaType)
        {
            //A newly created instance should not reference the canonicalized version.
            //This means a different version even with the same case will not reference
            //the same object. This is a premise check for the implementation of the
            //GetCanonicalizedValue that relies on this optimization to avoid comparing
            //the actual strings if the references are the same.
            string instanceMediaType = new(mediaType);
            Assert.IsFalse(object.ReferenceEquals(mediaType, instanceMediaType), "Instance created from canonical should not reference equal to it.");

            //The correct media type should be correctly identified even if it's not the canonicalized version.
            //This is a premise check for the GetCanonicalizedValue, now the comparison is done with the actual strings.
            Assert.IsTrue(isCorrectMediaType(instanceMediaType), "Is<SomeMediaType> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownMediaTypes.Application.GetCanonicalizedValue(instanceMediaType);
            Assert.IsTrue(object.ReferenceEquals(mediaType, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should still match since media types are case-insensitive per RFC 2045.
            string differentCaseMediaType = instanceMediaType.ToggleCaseForLetterAt(0);
            Assert.IsTrue(isCorrectMediaType(differentCaseMediaType), "Media type comparison should be case-insensitive per RFC 2045.");
        }


        /// <summary>
        /// The local catalog recognizes each JWT type through its predicate and canonical instance.
        /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 Section 8.3.1</see>:
        /// "The type and subtype tokens are case-insensitive."
        /// </summary>
        /// <param name="typ">The typ value to test.</param>
        /// <param name="isCorrectTyp">The function that checks if the typ is recognized.</param>
        [TestMethod]
        [DynamicData(nameof(GetJwtTypValues))]
        public void JwtTypValuesCompareCorrectly(string typ, Func<string, bool> isCorrectTyp)
        {
            //A newly created instance should not reference the canonicalized version.
            string instanceTyp = new(typ);
            Assert.IsFalse(object.ReferenceEquals(typ, instanceTyp), "Instance created from canonical should not reference equal to it.");

            //The correct typ should be correctly identified even if it's not the canonicalized version.
            Assert.IsTrue(isCorrectTyp(instanceTyp), "Is<SomeTyp> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownMediaTypes.Jwt.GetCanonicalizedValue(instanceTyp);
            Assert.IsTrue(object.ReferenceEquals(typ, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should still match since typ comparison is case-insensitive per RFC 7515.
            string differentCaseTyp = instanceTyp.ToggleCaseForLetterAt(0);
            Assert.IsTrue(isCorrectTyp(differentCaseTyp), "Typ comparison should be case-insensitive per RFC 7515.");
        }


        /// <summary>
        /// Tests that the Application.Equals method correctly compares media types case-insensitively.
        /// </summary>
        [TestMethod]
        public void ApplicationEqualsComparesCaseInsensitively()
        {
            Assert.IsTrue(WellKnownMediaTypes.Application.Equals("application/vc+ld+jwt", "APPLICATION/VC+LD+JWT"), "Equals should be case-insensitive.");
            Assert.IsTrue(WellKnownMediaTypes.Application.Equals("application/vc+jwt", "Application/Vc+Jwt"), "Equals should be case-insensitive.");
            Assert.IsFalse(WellKnownMediaTypes.Application.Equals("application/vc+ld+jwt", "application/vp+ld+jwt"), "Different media types should not be equal.");
        }


        /// <summary>
        /// Tests that the Jwt.Equals method correctly compares typ values case-insensitively.
        /// </summary>
        [TestMethod]
        public void JwtEqualsComparesCaseInsensitively()
        {
            Assert.IsTrue(WellKnownMediaTypes.Jwt.Equals("vc+ld+jwt", "VC+LD+JWT"), "Equals should be case-insensitive.");
            Assert.IsTrue(WellKnownMediaTypes.Jwt.Equals("vc+jwt", "Vc+Jwt"), "Equals should be case-insensitive.");
            Assert.IsFalse(WellKnownMediaTypes.Jwt.Equals("vc+ld+jwt", "vp+ld+jwt"), "Different typ values should not be equal.");
        }


        /// <summary>
        /// The short forms exercised by <see cref="JwtEqualsTreatsShortAndLongFormsAsTheSameMediaType"/>.
        /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 Section 4.1.9</see>:
        /// "A recipient using the media type value MUST treat it as if "application/" were prepended
        /// to any "typ" value not containing a '/'."
        /// </summary>
        public static IEnumerable<object[]> GetTypShortFormsForMediaTypeEquivalence()
        {
            yield return new object[] { WellKnownMediaTypes.Jwt.OauthIdJagJwt };
            yield return new object[] { WellKnownMediaTypes.Jwt.DpopJwt };
            yield return new object[] { WellKnownMediaTypes.Jwt.AtJwt };
            yield return new object[] { WellKnownMediaTypes.Jwt.ClientAuthenticationJwt };
        }


        /// <summary>
        /// Tests that a <c>typ</c> value's short form, its <c>application/</c> long form, an
        /// upper-case variant of each, and the short-against-long pair all compare equal, while a
        /// different subtype and a different top-level type do not.
        /// </summary>
        /// <param name="shortForm">The typ short form under test.</param>
        /// <remarks>
        /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 Section 4.1.9</see>:
        /// "A recipient using the media type value MUST treat it as if "application/" were prepended
        /// to any "typ" value not containing a '/'."
        /// </remarks>
        [TestMethod]
        [DynamicData(nameof(GetTypShortFormsForMediaTypeEquivalence))]
        public void JwtEqualsTreatsShortAndLongFormsAsTheSameMediaType(string shortForm)
        {
            string longForm = "application/" + shortForm;
            string upperShortForm = shortForm.ToUpperInvariant();
            string upperLongForm = longForm.ToUpperInvariant();

            Assert.IsTrue(WellKnownMediaTypes.Jwt.Equals(shortForm, longForm), $"'{shortForm}' should equal its long form '{longForm}'.");
            Assert.IsTrue(WellKnownMediaTypes.Jwt.Equals(longForm, shortForm), $"'{longForm}' should equal its short form '{shortForm}'.");
            Assert.IsTrue(WellKnownMediaTypes.Jwt.Equals(shortForm, upperShortForm), "An upper-case short form should still be equal.");
            Assert.IsTrue(WellKnownMediaTypes.Jwt.Equals(longForm, upperLongForm), "An upper-case long form should still be equal.");
            Assert.IsTrue(WellKnownMediaTypes.Jwt.Equals(shortForm, upperLongForm), "A short form should equal an upper-case long form.");

            Assert.IsFalse(WellKnownMediaTypes.Jwt.Equals(shortForm, "text/" + shortForm), "A different top-level type must not compare equal.");
            Assert.IsFalse(WellKnownMediaTypes.Jwt.Equals(shortForm, "jwt"), "A different subtype must not compare equal.");
        }


        /// <summary>
        /// RFC 7515 §4.1.9's implicit <c>application/</c> prefix is conditioned on the WHOLE <c>typ</c>
        /// value carrying no <c>/</c>, not merely on its <c>type/subtype</c> portion once parameters are
        /// dropped: "a 'typ' value of 'example' SHOULD be used to represent the 'application/example'
        /// media type, whereas the media type 'application/example;part="1/2"' cannot be shortened to
        /// 'example;part="1/2"'." A value whose only <c>/</c> lives inside a parameter names no media
        /// type this rule covers and so equals nothing but itself; a value that already carries an
        /// explicit <c>type/subtype</c> compares on that portion with its parameters dropped, the way
        /// <see cref="WellKnownMediaTypes.Application.Equals(string, string)"/> compares HTTP media types.
        /// </summary>
        /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>.</remarks>
        [TestMethod]
        public void JwtEqualsAppliesTheImplicitPrefixOnlyWhenTheWholeValueCarriesNoSlash()
        {
            Assert.IsFalse(
                WellKnownMediaTypes.Jwt.Equals("example;part=\"1/2\"", "application/example;part=\"1/2\""),
                "A value whose only '/' lives inside a parameter is not shortened to that long form.");
            Assert.IsFalse(
                WellKnownMediaTypes.Jwt.Equals("example;part=\"1/2\"", "application/example"),
                "A value whose only '/' lives inside a parameter names no media type this rule covers.");

            Assert.IsTrue(
                WellKnownMediaTypes.Jwt.Equals("application/example;part=\"1/2\"", "application/example"),
                "Parameters are dropped once the value already carries an explicit type/subtype.");
            Assert.IsTrue(
                WellKnownMediaTypes.Jwt.Equals("application/example;part=\"1/2\"", "example"),
                "The explicit long form still equals the implicit short form once parameters are dropped.");
        }


        /// <summary>
        /// Tests that unknown media types are not recognized and returned as-is.
        /// </summary>
        [TestMethod]
        public void UnknownMediaTypeIsNotRecognizedAndReturnedAsIs()
        {
            Assert.IsFalse(WellKnownMediaTypes.Application.IsVcLdJwt("application/json"), "Unknown media type should not be recognized as VcLdJwt.");
            Assert.IsFalse(WellKnownMediaTypes.Application.IsVpLdJwt("text/plain"), "Unknown media type should not be recognized as VpLdJwt.");

            string unknownCanonical = WellKnownMediaTypes.Application.GetCanonicalizedValue("application/unknown");
            Assert.AreEqual("application/unknown", unknownCanonical, "Unknown media type should be returned as-is.");
        }


        /// <summary>
        /// Tests that unknown JWT typ values are not recognized and returned as-is.
        /// </summary>
        [TestMethod]
        public void UnknownJwtTypIsNotRecognizedAndReturnedAsIs()
        {
            Assert.IsFalse(WellKnownMediaTypes.Jwt.IsVcLdJwt("unknown"), "Unknown typ should not be recognized as VcLdJwt.");
            Assert.IsFalse(WellKnownMediaTypes.Jwt.IsVpLdJwt("jwt"), "Unknown typ should not be recognized as VpLdJwt.");

            string unknownCanonical = WellKnownMediaTypes.Jwt.GetCanonicalizedValue("unknown");
            Assert.AreEqual("unknown", unknownCanonical, "Unknown typ should be returned as-is.");
        }


        /// <summary>
        /// The local catalog's full media types correspond to their JWT type short forms.
        /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 Section 4.1.9</see>:
        /// "A recipient using the media type value MUST treat it as if "application/" were prepended
        /// to any "typ" value not containing a '/'."
        /// </summary>
        [TestMethod]
        public void ApplicationAndJwtValuesCorrespond()
        {
            //The Application values should have the "application/" prefix over the Jwt values.
            Assert.AreEqual("application/" + WellKnownMediaTypes.Jwt.VcLdJwt, WellKnownMediaTypes.Application.VcLdJwt, "Application.VcLdJwt should be 'application/' + Jwt.VcLdJwt.");
            Assert.AreEqual("application/" + WellKnownMediaTypes.Jwt.VpLdJwt, WellKnownMediaTypes.Application.VpLdJwt, "Application.VpLdJwt should be 'application/' + Jwt.VpLdJwt.");
            Assert.AreEqual("application/" + WellKnownMediaTypes.Jwt.VcJwt, WellKnownMediaTypes.Application.VcJwt, "Application.VcJwt should be 'application/' + Jwt.VcJwt.");
            Assert.AreEqual("application/" + WellKnownMediaTypes.Jwt.VpJwt, WellKnownMediaTypes.Application.VpJwt, "Application.VpJwt should be 'application/' + Jwt.VpJwt.");
            Assert.AreEqual("application/" + WellKnownMediaTypes.Jwt.ClientAuthenticationJwt, WellKnownMediaTypes.Application.ClientAuthenticationJwt, "The client authentication media type must use its typ value as the subtype.");
        }


        /// <summary>
        /// The local catalog spells the problem details media type and its UTF-8 twin exactly.
        /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3">RFC 9457 Section 3</see>:
        /// "When serialized in a JSON document, that format is identified with the "application/problem+json" media type."
        /// </summary>
        [TestMethod]
        public void ProblemJsonMediaTypeSpellsItsDefiningName()
        {
            Assert.AreEqual("application/problem+json", WellKnownMediaTypes.Application.ProblemJson);
            Assert.AreEqual("application/problem+json", Encoding.UTF8.GetString(WellKnownMediaTypes.Application.ProblemJsonUtf8));
        }


        /// <summary>
        /// The local catalog spells the client authentication JWT media type and its UTF-8 twin exactly.
        /// The Internet-Draft <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-8.1.1">rfc7523bis-11 Section 8.1.1</see>
        /// registers "Type name: application" and "Subtype name: client-authentication+jwt".
        /// </summary>
        [TestMethod]
        public void ClientAuthenticationMediaTypeSpellsItsRegisteredName()
        {
            Assert.AreEqual("application/client-authentication+jwt", WellKnownMediaTypes.Application.ClientAuthenticationJwt);
            Assert.AreEqual("application/client-authentication+jwt", Encoding.UTF8.GetString(WellKnownMediaTypes.Application.ClientAuthenticationJwtUtf8));
        }


        /// <summary>
        /// The local catalog spells the client authentication JWT <c>typ</c> value and its UTF-8 twin exactly.
        /// The Internet-Draft <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">rfc7523bis-11 Section 4</see>:
        /// "Client authentication JWTs SHOULD be explicitly typed by using the typ header parameter value client-authentication+jwt".
        /// </summary>
        [TestMethod]
        public void ClientAuthenticationTypSpellsItsExplicitType()
        {
            Assert.AreEqual("client-authentication+jwt", WellKnownMediaTypes.Jwt.ClientAuthenticationJwt);
            Assert.AreEqual("client-authentication+jwt", Encoding.UTF8.GetString(WellKnownMediaTypes.Jwt.ClientAuthenticationJwtUtf8));
        }


        /// <summary>
        /// The client authentication <c>typ</c> short form and its <c>application/</c> long form, written as
        /// literals in any casing, name the same media type.
        /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 Section 4.1.9</see>:
        /// "A recipient using the media type value MUST treat it as if "application/" were prepended
        /// to any "typ" value not containing a '/'."
        /// </summary>
        /// <param name="received">The literal received <c>typ</c> or media type value.</param>
        [TestMethod]
        [DataRow("client-authentication+jwt")]
        [DataRow("application/client-authentication+jwt")]
        [DataRow("CLIENT-AUTHENTICATION+JWT")]
        [DataRow("Application/Client-Authentication+JWT")]
        public void ClientAuthenticationTypIsRecognizedInItsShortAndLongForms(string received)
        {
            Assert.IsTrue(WellKnownMediaTypes.Jwt.IsClientAuthenticationJwt(received));
        }


        /// <summary>
        /// The problem details and client authentication media types, written as literals in any casing,
        /// are recognized by their predicates.
        /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 Section 8.3.1</see>:
        /// "The type and subtype tokens are case-insensitive."
        /// </summary>
        /// <param name="received">The literal received media type.</param>
        /// <param name="isProblemJson">Whether the literal names the problem details media type.</param>
        [TestMethod]
        [DataRow("application/problem+json", true)]
        [DataRow("Application/Problem+JSON", true)]
        [DataRow("APPLICATION/CLIENT-AUTHENTICATION+JWT", false)]
        [DataRow("application/client-authentication+jwt", false)]
        public void ProblemAndClientAuthenticationMediaTypesAreRecognizedRegardlessOfCase(string received, bool isProblemJson)
        {
            Assert.AreEqual(isProblemJson, WellKnownMediaTypes.Application.IsProblemJson(received));
            Assert.AreEqual(!isProblemJson, WellKnownMediaTypes.Application.IsClientAuthenticationJwt(received));
        }


        /// <summary>
        /// Every OpenID Federation 1.0 <c>typ</c> value, its dedicated recognition check, and a
        /// neighbouring value from the same catalog that check must not recognize.
        /// </summary>
        public static IEnumerable<object[]> GetFederationTypValues()
        {
            yield return new object[] { WellKnownFederationMediaTypes.EntityStatementJwt, new Func<string, bool>(WellKnownFederationMediaTypes.IsEntityStatementJwt), WellKnownFederationMediaTypes.TrustMarkJwt };
            yield return new object[] { WellKnownFederationMediaTypes.ResolveResponseJwt, new Func<string, bool>(WellKnownFederationMediaTypes.IsResolveResponseJwt), WellKnownFederationMediaTypes.EntityStatementJwt };
            yield return new object[] { WellKnownFederationMediaTypes.ExplicitRegistrationResponseJwt, new Func<string, bool>(WellKnownFederationMediaTypes.IsExplicitRegistrationResponseJwt), WellKnownFederationMediaTypes.ResolveResponseJwt };
            yield return new object[] { WellKnownFederationMediaTypes.TrustMarkJwt, new Func<string, bool>(WellKnownFederationMediaTypes.IsTrustMarkJwt), WellKnownFederationMediaTypes.ExplicitRegistrationResponseJwt };
            yield return new object[] { WellKnownFederationMediaTypes.TrustMarkDelegationJwt, new Func<string, bool>(WellKnownFederationMediaTypes.IsTrustMarkDelegationJwt), WellKnownFederationMediaTypes.TrustMarkJwt };
            yield return new object[] { WellKnownFederationMediaTypes.HistoricalKeysJwt, new Func<string, bool>(WellKnownFederationMediaTypes.IsHistoricalKeysJwt), WellKnownFederationMediaTypes.TrustMarkDelegationJwt };
            yield return new object[] { WellKnownFederationMediaTypes.TrustMarkStatusResponseJwt, new Func<string, bool>(WellKnownFederationMediaTypes.IsTrustMarkStatusResponseJwt), WellKnownFederationMediaTypes.HistoricalKeysJwt };
        }


        /// <summary>
        /// Each OpenID Federation 1.0 <c>typ</c> value's dedicated check recognizes the value itself
        /// and an upper-case spelling — media type values are case insensitive per RFC 2045 — but not
        /// a neighbouring value from the same catalog.
        /// </summary>
        /// <param name="typ">The typ value under test.</param>
        /// <param name="isCorrectTyp">Its dedicated recognition function.</param>
        /// <param name="neighborTyp">A different typ value of the same catalog.</param>
        [TestMethod]
        [DynamicData(nameof(GetFederationTypValues))]
        public void FederationTypValuesAreRecognizedRegardlessOfCase(string typ, Func<string, bool> isCorrectTyp, string neighborTyp)
        {
            Assert.IsTrue(isCorrectTyp(typ), $"'{typ}' must be recognized by its own check.");
            Assert.IsTrue(isCorrectTyp(typ.ToUpperInvariant()), "An upper-case spelling declares the same type.");
            Assert.IsFalse(isCorrectTyp(neighborTyp), $"'{neighborTyp}' is a different Federation typ and must not be recognized.");
        }


        /// <summary>
        /// "A recipient using the media type value MUST treat it as if 'application/' were prepended
        /// to any 'typ' value not containing a '/'." Each Federation <c>typ</c> value's long
        /// <c>application/</c> form, in any casing, is recognized by its dedicated check; a
        /// <c>text/</c> top-level type is not.
        /// </summary>
        /// <param name="typ">The typ value under test.</param>
        /// <param name="isCorrectTyp">Its dedicated recognition function.</param>
        /// <param name="neighborTyp">Unused here; shared with the sibling test's DynamicData source.</param>
        /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>.</remarks>
        [TestMethod]
        [DynamicData(nameof(GetFederationTypValues))]
        public void FederationTypValuesAreRecognizedInTheirLongMediaTypeForm(string typ, Func<string, bool> isCorrectTyp, string neighborTyp)
        {
            _ = neighborTyp;
            string longForm = "application/" + typ;

            Assert.IsTrue(isCorrectTyp(longForm), $"The long media-type form of '{typ}' must be recognized.");
            Assert.IsTrue(isCorrectTyp(longForm.ToUpperInvariant()), "An upper-case long form must still be recognized.");
            Assert.IsFalse(isCorrectTyp("text/" + typ), "A 'text/' top-level type must not be recognized.");
        }


        /// <summary>
        /// Every OID4VCI 1.0 <c>typ</c> value with a recognition check of its own, that check,
        /// and a neighbouring value from the same group that check must not recognize.
        /// </summary>
        public static IEnumerable<object[]> GetOid4VciTypValues()
        {
            yield return new object[] { Oid4VciProofIssuance.ProofJwtType, new Func<string, bool>(Oid4VciProofIssuance.IsProofJwtType), AttestationProofParameterNames.KeyAttestationJwtType };
            yield return new object[] { AttestationProofParameterNames.KeyAttestationJwtType, new Func<string, bool>(AttestationProofParameterNames.IsKeyAttestationJwtType), SignedCredentialIssuerMetadata.SignedMetadataType };
            yield return new object[] { SignedCredentialIssuerMetadata.SignedMetadataType, new Func<string, bool>(SignedCredentialIssuerMetadata.IsSignedMetadataType), Oid4VciProofIssuance.ProofJwtType };
        }


        /// <summary>
        /// Each OID4VCI 1.0 <c>typ</c> value's dedicated check recognizes the value itself and an
        /// upper-case spelling, but not a neighbouring value from the same group.
        /// </summary>
        /// <param name="typ">The typ value under test.</param>
        /// <param name="isCorrectTyp">Its dedicated recognition function.</param>
        /// <param name="neighborTyp">A different OID4VCI typ value.</param>
        [TestMethod]
        [DynamicData(nameof(GetOid4VciTypValues))]
        public void Oid4VciTypValuesAreRecognizedRegardlessOfCase(string typ, Func<string, bool> isCorrectTyp, string neighborTyp)
        {
            Assert.IsTrue(isCorrectTyp(typ), $"'{typ}' must be recognized by its own check.");
            Assert.IsTrue(isCorrectTyp(typ.ToUpperInvariant()), "An upper-case spelling declares the same type.");
            Assert.IsFalse(isCorrectTyp(neighborTyp), $"'{neighborTyp}' is a different OID4VCI typ and must not be recognized.");
        }


        /// <summary>
        /// Each OID4VCI 1.0 <c>typ</c> value's long <c>application/</c> form, in any casing, is
        /// recognized by its dedicated check; a <c>text/</c> top-level type is not.
        /// </summary>
        /// <param name="typ">The typ value under test.</param>
        /// <param name="isCorrectTyp">Its dedicated recognition function.</param>
        /// <param name="neighborTyp">Unused here; shared with the sibling test's DynamicData source.</param>
        /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>.</remarks>
        [TestMethod]
        [DynamicData(nameof(GetOid4VciTypValues))]
        public void Oid4VciTypValuesAreRecognizedInTheirLongMediaTypeForm(string typ, Func<string, bool> isCorrectTyp, string neighborTyp)
        {
            _ = neighborTyp;
            string longForm = "application/" + typ;

            Assert.IsTrue(isCorrectTyp(longForm), $"The long media-type form of '{typ}' must be recognized.");
            Assert.IsTrue(isCorrectTyp(longForm.ToUpperInvariant()), "An upper-case long form must still be recognized.");
            Assert.IsFalse(isCorrectTyp("text/" + typ), "A 'text/' top-level type must not be recognized.");
        }
    }
}
