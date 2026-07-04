namespace Verifiable.Tests.Acdc;

/// <summary>
/// The ACDC specification's worked Accreditation ACDC example, reproduced as the over-the-wire compact JSON the
/// SAID is taken over (no inter-token whitespace, fields in canonical order). Shared by the ACDC tests so the
/// specification vectors live in one place: the JSON decode/encode round-trip, the SAID conformance, the reader,
/// and the most-compact-form compaction all check against the same published serializations and SAIDs.
/// </summary>
internal static class AcdcExampleVectors
{
    /// <summary>The published top-level SAID of the Accreditation ACDC, taken over its most-compact form.</summary>
    public const string AccreditationSaid = "EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi";

    /// <summary>The published schema (<c>s</c>) section SAID.</summary>
    public const string SchemaSaid = "EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG";

    /// <summary>The published attribute (<c>a</c>) section SAID.</summary>
    public const string AttributeSectionSaid = "EK799owRYyk8UPFWUmfsm5AJfJmU7jZGtZXJFbg2I0KL";

    /// <summary>The published rule (<c>r</c>) section SAID.</summary>
    public const string RuleSectionSaid = "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU";

    /// <summary>The UUID (<c>u</c>) of the Accreditation ACDC.</summary>
    public const string Uuid = "0ABhY2Rjc3BlY3dvcmtyYXdh";

    /// <summary>The issuer AID (<c>i</c>): the accreditation agency.</summary>
    public const string IssuerAid = "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT";

    /// <summary>The registry SAID (<c>rd</c>) the ACDC is bound to.</summary>
    public const string RegistrySaid = "EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw";

    /// <summary>
    /// The byte size the most-compact form's version string declares: the <c>AAF3</c> size field of
    /// <c>ACDCCAACAAJSONAAF3.</c> is the Base64URL value 375.
    /// </summary>
    public const int CompactByteSize = 375;

    /// <summary>The version string of the most-compact form.</summary>
    public const string CompactVersionString = "ACDCCAACAAJSONAAF3.";

    /// <summary>The version string of the fully expanded form.</summary>
    public const string ExpandedVersionString = "ACDCCAACAAJSONAAKX.";


    /// <summary>The Accreditation ACDC in its most-compact form, the serialization the top-level SAID is taken over.</summary>
    public const string CompactAcdc =
        """{"v":"ACDCCAACAAJSONAAF3.","t":"acm","d":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi","u":"0ABhY2Rjc3BlY3dvcmtyYXdh","i":"ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT","rd":"EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw","s":"EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG","a":"EK799owRYyk8UPFWUmfsm5AJfJmU7jZGtZXJFbg2I0KL","r":"EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU"}""";

    /// <summary>The Accreditation ACDC in its fully expanded form: the attribute and rule sections are blocks; the schema stays a SAID.</summary>
    public const string ExpandedAcdc =
        """{"v":"ACDCCAACAAJSONAAKX.","t":"acm","d":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi","u":"0ABhY2Rjc3BlY3dvcmtyYXdh","i":"ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT","rd":"EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw","s":"EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG","a":{"d":"EK799owRYyk8UPFWUmfsm5AJfJmU7jZGtZXJFbg2I0KL","u":"0ABhY2Rjc3BlY3dvcmtyYXc3","i":"ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz","name":"Sunspot College","level":"gold"},"r":{"d":"EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU","l":"Issuer provides this ACDC on an AS IS basis. This ACDC in whole or in part MUST NOT be shared with any other entity besides the intended recipient."}}""";

    /// <summary>The attribute (<c>a</c>) section in its block-level expanded form, the serialization its SAID is taken over.</summary>
    public const string AttributeSection =
        """{"d":"EK799owRYyk8UPFWUmfsm5AJfJmU7jZGtZXJFbg2I0KL","u":"0ABhY2Rjc3BlY3dvcmtyYXc3","i":"ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz","name":"Sunspot College","level":"gold"}""";

    /// <summary>The rule (<c>r</c>) section in its block-level expanded form, the serialization its SAID is taken over.</summary>
    public const string RuleSection =
        """{"d":"EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU","l":"Issuer provides this ACDC on an AS IS basis. This ACDC in whole or in part MUST NOT be shared with any other entity besides the intended recipient."}""";


    /// <summary>The published SAID of the specification's partially-disclosable nested rule section (the rule-section, top-level rule-group).</summary>
    public const string NestedRuleSectionSaid = "EL7oXtsH1t7YqOOCS0fMhWfUKx1fHwiQ2u47fVba4lAA";

    /// <summary>The published SAID of the <c>disclaimers</c> rule-group nested in the partially-disclosable rule section.</summary>
    public const string DisclaimersGroupSaid = "EIRP8ZLuMNb1I_Uk1GgnD3qZ_MAh6GaXV1JmzFKLebb3";

    /// <summary>The published SAID of the <c>warrantyDisclaimer</c> rule nested in the <c>disclaimers</c> rule-group.</summary>
    public const string WarrantyDisclaimerSaid = "EA84ClmyIMrSl5XaAWENAxTVZH25_YZGmu0WQm_VBBeV";

    /// <summary>The published SAID of the <c>liabilityDisclaimer</c> rule nested in the <c>disclaimers</c> rule-group.</summary>
    public const string LiabilityDisclaimerSaid = "ECENp0nXYDm_bLgr7TlJ8ns8I1QI2qzyqxoXnYG8B-ac";

    /// <summary>The published SAID of the <c>permittedUse</c> rule nested in the partially-disclosable rule section.</summary>
    public const string PermittedUseSaid = "EIn94r7ax0PmalGUddjP3ElnU2Lzz92UFE1uIinoVeVs";


    /// <summary>
    /// The specification's partially-disclosable rule section in fully disclosed (uncompacted) form: a top-level
    /// rule-group with a nested <c>disclaimers</c> rule-group (holding two rules) and a <c>permittedUse</c> rule.
    /// </summary>
    public const string NestedRuleSectionExpanded =
        """{"d":"EL7oXtsH1t7YqOOCS0fMhWfUKx1fHwiQ2u47fVba4lAA","u":"0ABhY2Rjc3BlY3dvcmtyYXcw","disclaimers":{"d":"EIRP8ZLuMNb1I_Uk1GgnD3qZ_MAh6GaXV1JmzFKLebb3","u":"0ABhY2Rjc3BlY3dvcmtyYXcx","l":"The person or legal entity identified by this ACDC's Issuer AID (Issuer) makes the following disclaimers:","warrantyDisclaimer":{"d":"EA84ClmyIMrSl5XaAWENAxTVZH25_YZGmu0WQm_VBBeV","u":"0ABhY2Rjc3BlY3dvcmtyYXcy","l":"Issuer provides this ACDC on an AS IS basis."},"liabilityDisclaimer":{"d":"ECENp0nXYDm_bLgr7TlJ8ns8I1QI2qzyqxoXnYG8B-ac","u":"0ABhY2Rjc3BlY3dvcmtyYXcz","l":"The Issuer SHALL NOT be liable for ANY damages arising as a result of this credential."}},"permittedUse":{"d":"EIn94r7ax0PmalGUddjP3ElnU2Lzz92UFE1uIinoVeVs","u":"0ABhY2Rjc3BlY3dvcmtyYXc0","l":"The Issuee (controller of the Issuee AID) MAY only use this ACDC for non-commercial purposes."}}""";

    /// <summary>
    /// The same rule section in its most-compact (partially disclosed) form — the serialization its top-level SAID
    /// is taken over: each nested rule-group and rule is its SAID.
    /// </summary>
    public const string NestedRuleSectionPartiallyDisclosed =
        """{"d":"EL7oXtsH1t7YqOOCS0fMhWfUKx1fHwiQ2u47fVba4lAA","u":"0ABhY2Rjc3BlY3dvcmtyYXcw","disclaimers":"EIRP8ZLuMNb1I_Uk1GgnD3qZ_MAh6GaXV1JmzFKLebb3","permittedUse":"EIn94r7ax0PmalGUddjP3ElnU2Lzz92UFE1uIinoVeVs"}""";

    /// <summary>
    /// The <c>disclaimers</c> rule-group in its block-level expanded form — the serialization its SAID is taken
    /// over: its own reserved fields followed by its two nested rules, each compacted to its SAID.
    /// </summary>
    public const string DisclaimersGroupBlock =
        """{"d":"EIRP8ZLuMNb1I_Uk1GgnD3qZ_MAh6GaXV1JmzFKLebb3","u":"0ABhY2Rjc3BlY3dvcmtyYXcx","l":"The person or legal entity identified by this ACDC's Issuer AID (Issuer) makes the following disclaimers:","warrantyDisclaimer":"EA84ClmyIMrSl5XaAWENAxTVZH25_YZGmu0WQm_VBBeV","liabilityDisclaimer":"ECENp0nXYDm_bLgr7TlJ8ns8I1QI2qzyqxoXnYG8B-ac"}""";

    /// <summary>The <c>warrantyDisclaimer</c> rule in its block-level expanded form, the serialization its SAID is taken over.</summary>
    public const string WarrantyDisclaimerRule =
        """{"d":"EA84ClmyIMrSl5XaAWENAxTVZH25_YZGmu0WQm_VBBeV","u":"0ABhY2Rjc3BlY3dvcmtyYXcy","l":"Issuer provides this ACDC on an AS IS basis."}""";

    /// <summary>The <c>liabilityDisclaimer</c> rule in its block-level expanded form, the serialization its SAID is taken over.</summary>
    public const string LiabilityDisclaimerRule =
        """{"d":"ECENp0nXYDm_bLgr7TlJ8ns8I1QI2qzyqxoXnYG8B-ac","u":"0ABhY2Rjc3BlY3dvcmtyYXcz","l":"The Issuer SHALL NOT be liable for ANY damages arising as a result of this credential."}""";

    /// <summary>The <c>permittedUse</c> rule in its block-level expanded form, the serialization its SAID is taken over.</summary>
    public const string PermittedUseRule =
        """{"d":"EIn94r7ax0PmalGUddjP3ElnU2Lzz92UFE1uIinoVeVs","u":"0ABhY2Rjc3BlY3dvcmtyYXc0","l":"The Issuee (controller of the Issuee AID) MAY only use this ACDC for non-commercial purposes."}""";


    /// <summary>The published SAID of the Transcript ACDC's edge section (the top-level edge-group).</summary>
    public const string EdgeSectionSaid = "ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0";

    /// <summary>The published SAID of the <c>accreditation</c> edge (a targeted edge with a far-node schema constraint).</summary>
    public const string AccreditationEdgeSaid = "EAFj8JaNEC3mdFNJKrXW8E03_k9qqb_xM9NjAPVHw-xJ";

    /// <summary>The published SAID of the <c>reports</c> edge-group (an <c>OR</c> group of two edges).</summary>
    public const string ReportsGroupSaid = "EOObmbCppe1S-7vtLuy766_4-RcfrC7p4ciFtBxdexuz";

    /// <summary>The published SAID of the <c>research</c> edge nested in the <c>reports</c> edge-group.</summary>
    public const string ResearchEdgeSaid = "EN9ngstOcFHqsjqf75JZFKtCRmW76NkeRrUSxTLoqqkI";

    /// <summary>The published SAID of the <c>project</c> edge nested in the <c>reports</c> edge-group.</summary>
    public const string ProjectEdgeSaid = "EFwHz5qJ4_8c7IefP7_zugX2eIgtoyY8Up_WZ3osXwkI";

    /// <summary>The far-node SAID the <c>accreditation</c> edge points to: the Accreditation ACDC.</summary>
    public const string AccreditationFarNode = "EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi";


    /// <summary>
    /// The Transcript ACDC's edge section in fully disclosed (uncompacted) form: a top-level edge-group with a
    /// targeted <c>accreditation</c> edge and a nested <c>reports</c> edge-group (an <c>OR</c> of two untargeted
    /// edges).
    /// </summary>
    public const string EdgeSectionExpanded =
        """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","u":"0ABhY2Rjc3BlY3dvcmtyYXcy","accreditation":{"d":"EAFj8JaNEC3mdFNJKrXW8E03_k9qqb_xM9NjAPVHw-xJ","u":"0ABhY2Rjc3BlY3dvcmtyYXcz","n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi","s":"EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG"},"reports":{"d":"EOObmbCppe1S-7vtLuy766_4-RcfrC7p4ciFtBxdexuz","u":"0ABhY2Rjc3BlY3dvcmtyYXc0","o":"OR","research":{"d":"EN9ngstOcFHqsjqf75JZFKtCRmW76NkeRrUSxTLoqqkI","u":"0ABhY2Rjc3BlY3dvcmtyYXc2","n":"EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5","o":"NI2I"},"project":{"d":"EFwHz5qJ4_8c7IefP7_zugX2eIgtoyY8Up_WZ3osXwkI","u":"0ABhY2Rjc3BlY3dvcmtyYXc1","n":"EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M","o":"NI2I"}}}""";

    /// <summary>
    /// The edge section's most-compact (block-level expanded) form — the serialization its top-level SAID is taken
    /// over: each nested edge and edge-group is its SAID. This is also the partially disclosed form a reader folds.
    /// </summary>
    public const string EdgeSectionPartiallyDisclosed =
        """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","u":"0ABhY2Rjc3BlY3dvcmtyYXcy","accreditation":"EAFj8JaNEC3mdFNJKrXW8E03_k9qqb_xM9NjAPVHw-xJ","reports":"EOObmbCppe1S-7vtLuy766_4-RcfrC7p4ciFtBxdexuz"}""";

    /// <summary>
    /// The <c>reports</c> edge-group in its block-level expanded form — the serialization its SAID is taken over:
    /// its reserved fields and <c>OR</c> operator followed by its two edges, each compacted to its SAID.
    /// </summary>
    public const string ReportsGroupBlock =
        """{"d":"EOObmbCppe1S-7vtLuy766_4-RcfrC7p4ciFtBxdexuz","u":"0ABhY2Rjc3BlY3dvcmtyYXc0","o":"OR","research":"EN9ngstOcFHqsjqf75JZFKtCRmW76NkeRrUSxTLoqqkI","project":"EFwHz5qJ4_8c7IefP7_zugX2eIgtoyY8Up_WZ3osXwkI"}""";

    /// <summary>The <c>accreditation</c> edge in its block-level expanded form, the serialization its SAID is taken over.</summary>
    public const string AccreditationEdgeBlock =
        """{"d":"EAFj8JaNEC3mdFNJKrXW8E03_k9qqb_xM9NjAPVHw-xJ","u":"0ABhY2Rjc3BlY3dvcmtyYXcz","n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi","s":"EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG"}""";

    /// <summary>The <c>research</c> edge in its block-level expanded form, the serialization its SAID is taken over.</summary>
    public const string ResearchEdgeBlock =
        """{"d":"EN9ngstOcFHqsjqf75JZFKtCRmW76NkeRrUSxTLoqqkI","u":"0ABhY2Rjc3BlY3dvcmtyYXc2","n":"EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5","o":"NI2I"}""";

    /// <summary>The <c>project</c> edge in its block-level expanded form, the serialization its SAID is taken over.</summary>
    public const string ProjectEdgeBlock =
        """{"d":"EFwHz5qJ4_8c7IefP7_zugX2eIgtoyY8Up_WZ3osXwkI","u":"0ABhY2Rjc3BlY3dvcmtyYXc1","n":"EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M","o":"NI2I"}""";


    /// <summary>The published top-level SAID of the Transcript ACDC, taken over its most-compact form.</summary>
    public const string TranscriptSaid = "ENeNWgCCNcOf1JbgKxUzREKpyK5kABYFd2QYUzEfwz9H";

    /// <summary>The published Transcript attribute (<c>a</c>) section SAID — a non-leaf block that nests the grades block.</summary>
    public const string TranscriptAttributeSaid = "ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U";

    /// <summary>The version string of the Transcript ACDC's fully expanded form.</summary>
    public const string TranscriptExpandedVersionString = "ACDCCAACAAJSONAAXG.";

    /// <summary>The version string of the Transcript ACDC's most-compact form.</summary>
    public const string TranscriptCompactVersionString = "ACDCCAACAAJSONAAGg.";


    /// <summary>
    /// The Transcript ACDC in fully expanded form: the attribute section nests a SAIDed grades block (so it is not a
    /// leaf), the edge section nests two edges and a nested edge-group, and the rule section is the single-clause
    /// Accreditation rule. The edge and rule blocks reuse the verified section vectors. The attribute's grade values
    /// (<c>3.5</c>, <c>4.0</c>, <c>3.0</c>) exercise canonical number serialization through compaction.
    /// </summary>
    public const string TranscriptExpanded =
        """{"v":"ACDCCAACAAJSONAAXG.","d":"ENeNWgCCNcOf1JbgKxUzREKpyK5kABYFd2QYUzEfwz9H","u":"0ABhY2Rjc3BlY3dvcmtyYXdk","i":"ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz","rd":"EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX","s":"EABGAia_vH_zHCRLOK3Bm2xxujV5A8sYIJbypfSM_2Fh","a":{"d":"ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U","u":"0ABhY2Rjc3BlY3dvcmtyYXcw","i":"ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf","name":"Zoe Doe","gpa":3.5,"grades":{"d":"EFQnBFeKAeS4DAWYoKDwWXOT4h2-XaGk7-w4-2N4ktXy","u":"0ABhY2Rjc3BlY3dvcmtyYXcx","history":3.5,"english":4.0,"math":3.0}},"e":""" + EdgeSectionExpanded + ""","r":""" + RuleSection + """}""";

    /// <summary>
    /// The Transcript ACDC in its most-compact form, the serialization the top-level SAID is taken over: every
    /// section reduced to its SAID and the version string restamped to the compact byte count.
    /// </summary>
    public const string TranscriptCompact =
        """{"v":"ACDCCAACAAJSONAAGg.","d":"ENeNWgCCNcOf1JbgKxUzREKpyK5kABYFd2QYUzEfwz9H","u":"0ABhY2Rjc3BlY3dvcmtyYXdk","i":"ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz","rd":"EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX","s":"EABGAia_vH_zHCRLOK3Bm2xxujV5A8sYIJbypfSM_2Fh","a":"ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U","e":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","r":"EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU"}""";


    /// <summary>The published AGID of the specification's worked JSON aggregate section, over the list of its block SAIDs.</summary>
    public const string AggregateAgid = "EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx";

    /// <summary>The published SAID of the aggregate's Issuee block.</summary>
    public const string AggregateIssueeBlockSaid = "EI2lwi1ZKrs-bDwgEreOhEh-W2O5xrOm5T-QCyMuX5V4";

    /// <summary>The published SAID of the aggregate's Score block.</summary>
    public const string AggregateScoreBlockSaid = "EC-vU19URXX8ztfWdp_j2HHr1lJsqtGa1YHtZrg6-GMR";

    /// <summary>The published SAID of the aggregate's Name block.</summary>
    public const string AggregateNameBlockSaid = "EKYLUIpDXNT0ujSdoNOT5pLp0okOKW3mAbg-M7K5OO_C";

    /// <summary>The Issuee AID carried by the aggregate's Issuee block.</summary>
    public const string AggregateIssueeAid = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf";


    /// <summary>The aggregate's Issuee block in its detail (revealed) form, the serialization its SAID is taken over.</summary>
    public const string AggregateIssueeBlock =
        """{"d":"EI2lwi1ZKrs-bDwgEreOhEh-W2O5xrOm5T-QCyMuX5V4","u":"0ABhY2Rjc3BlY3dvcmtyYXcw","i":"ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"}""";

    /// <summary>The aggregate's Score block in its detail (revealed) form.</summary>
    public const string AggregateScoreBlock =
        """{"d":"EC-vU19URXX8ztfWdp_j2HHr1lJsqtGa1YHtZrg6-GMR","u":"0ABhY2Rjc3BlY3dvcmtyYXcx","score":96}""";

    /// <summary>The aggregate's Name block in its detail (revealed) form.</summary>
    public const string AggregateNameBlock =
        """{"d":"EKYLUIpDXNT0ujSdoNOT5pLp0okOKW3mAbg-M7K5OO_C","u":"0ABhY2Rjc3BlY3dvcmtyYXcy","name":"Zoe Doe"}""";


    /// <summary>The aggregate section fully disclosed: the AGID followed by all three blocks in detail form, wrapped as the <c>A</c> field for decoding.</summary>
    public const string AggregateDisclosed =
        """{"A":["EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx",{"d":"EI2lwi1ZKrs-bDwgEreOhEh-W2O5xrOm5T-QCyMuX5V4","u":"0ABhY2Rjc3BlY3dvcmtyYXcw","i":"ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"},{"d":"EC-vU19URXX8ztfWdp_j2HHr1lJsqtGa1YHtZrg6-GMR","u":"0ABhY2Rjc3BlY3dvcmtyYXcx","score":96},{"d":"EKYLUIpDXNT0ujSdoNOT5pLp0okOKW3mAbg-M7K5OO_C","u":"0ABhY2Rjc3BlY3dvcmtyYXcy","name":"Zoe Doe"}]}""";

    /// <summary>The aggregate section selectively disclosed: the Issuee and Score blocks revealed, the Name block blinded to its SAID, wrapped as the <c>A</c> field.</summary>
    public const string AggregateSelectiveDisclosure =
        """{"A":["EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx",{"d":"EI2lwi1ZKrs-bDwgEreOhEh-W2O5xrOm5T-QCyMuX5V4","u":"0ABhY2Rjc3BlY3dvcmtyYXcw","i":"ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"},{"d":"EC-vU19URXX8ztfWdp_j2HHr1lJsqtGa1YHtZrg6-GMR","u":"0ABhY2Rjc3BlY3dvcmtyYXcx","score":96},"EKYLUIpDXNT0ujSdoNOT5pLp0okOKW3mAbg-M7K5OO_C"]}""";

    /// <summary>The aggregate section in list form: the AGID followed by all block SAIDs blinded, wrapped as the <c>A</c> field.</summary>
    public const string AggregateListForm =
        """{"A":["EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx","EI2lwi1ZKrs-bDwgEreOhEh-W2O5xrOm5T-QCyMuX5V4","EC-vU19URXX8ztfWdp_j2HHr1lJsqtGa1YHtZrg6-GMR","EKYLUIpDXNT0ujSdoNOT5pLp0okOKW3mAbg-M7K5OO_C"]}""";


    /// <summary>The published AGID of the specification's worked CESR-native aggregate section, over the CESR-native serialization of its block SAIDs.</summary>
    public const string CesrAggregateAgid = "EEL7OTDzXjYoaDE8g8064thOpKdxsJWaG8DhRyOB58qW";

    /// <summary>The published SAID of the CESR-native aggregate's Issuee block.</summary>
    public const string CesrAggregateIssueeBlockSaid = "EPss9hsx7P5iYjWXNYJM5NiEu5EtPQHdGZ5K-qXK2p5E";

    /// <summary>The published SAID of the CESR-native aggregate's Score block.</summary>
    public const string CesrAggregateScoreBlockSaid = "EGoIcPap1swfLGRQzTaxf38HsLFuHehBCY5kUSDK8XGs";

    /// <summary>The published SAID of the CESR-native aggregate's Name block.</summary>
    public const string CesrAggregateNameBlockSaid = "ED50KTrvT5n20JFTsyZFvBJfH-bOAVP9xHFhtbI5nCN6";

    /// <summary>
    /// The raw value the CESR-native AGID is digested over, with the AGID slot dummied: the count code <c>-JAs</c>
    /// framing a 44-quadlet group, then the dummied AGID placeholder and the three block SAIDs concatenated. The
    /// BLAKE3-256 digest of this value, CESR-encoded, is <see cref="CesrAggregateAgid"/>.
    /// </summary>
    public const string CesrAggregateDummiedRaw =
        "-JAs############################################EPss9hsx7P5iYjWXNYJM5NiEu5EtPQHdGZ5K-qXK2p5EEGoIcPap1swfLGRQzTaxf38HsLFuHehBCY5kUSDK8XGsED50KTrvT5n20JFTsyZFvBJfH-bOAVP9xHFhtbI5nCN6";


    /// <summary>The published SAID of the specification's worked non-blindable registry inception (the registry SAID).</summary>
    public const string RegistryRipSaid = "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU";

    /// <summary>The Issuer AID of the worked registry.</summary>
    public const string RegistryIssuerAid = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW";

    /// <summary>The published SAID of the registry's first (issued) update event.</summary>
    public const string RegistryIssuedUpdateSaid = "EJFxtbr9WioIkzTfVX4iC6Axxyg8jjKSX0ZrJgoNHiB-";

    /// <summary>The published SAID of the registry's second (revoked) update event.</summary>
    public const string RegistryRevokedUpdateSaid = "EJQ-ezS6h0Oa0BIN_w4KjstdapfOfrwmVluxn1DR5Gja";

    /// <summary>The SAID of the ACDC whose issuance and revocation the registry tracks (the updates' <c>td</c> value).</summary>
    public const string RegistryTargetAcdcSaid = "EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5";


    /// <summary>The worked registry inception (<c>rip</c>) event, the serialization its registry SAID is taken over.</summary>
    public const string RegistryInceptionEventJson =
        """{"v":"ACDCCAACAAJSONAADa.","t":"rip","d":"EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU","u":"0ABhY2Rjc3BlY3dvcmtyYXcz","i":"EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW","n":"0","dt":"2025-07-04T17:53:00.000000+00:00"}""";

    /// <summary>The worked registry update (<c>upd</c>) event that sets the ACDC's state to <c>issued</c>.</summary>
    public const string RegistryIssuedUpdateJson =
        """{"v":"ACDCCAACAAJSONAAEx.","t":"upd","d":"EJFxtbr9WioIkzTfVX4iC6Axxyg8jjKSX0ZrJgoNHiB-","rd":"EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU","n":"1","p":"EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU","dt":"2020-08-03T12:00:20.000000+00:00","td":"EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5","ts":"issued"}""";

    /// <summary>The worked registry update (<c>upd</c>) event that sets the ACDC's state to <c>revoked</c>.</summary>
    public const string RegistryRevokedUpdateJson =
        """{"v":"ACDCCAACAAJSONAAEy.","t":"upd","d":"EJQ-ezS6h0Oa0BIN_w4KjstdapfOfrwmVluxn1DR5Gja","rd":"EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU","n":"2","p":"EJFxtbr9WioIkzTfVX4iC6Axxyg8jjKSX0ZrJgoNHiB-","dt":"2020-08-04T12:00:20.000000+00:00","td":"EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5","ts":"revoked"}""";
}
