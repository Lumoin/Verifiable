# Introducing Claim, Assessor, and Archiving for validation in Verifiable

## Context

The Verifiable library establishes a framework for various socio-economic and technical operations within decentralized, digital signature data architectures. It is designed to enhance trustworthy decision support systems, crucial for transitioning to a regenerative future. Our focus is to integrate traditional validation with artificial intelligence, ensuring valid data usage and trust in automated decision-making.

The integration of AI into the Verifiable library addresses complex data scenarios and decision-making processes. AI's ability to efficiently parse and analyze large datasets, identify patterns, and provide data-driven insights is crucial in decentralized environments characterized by diverse and abundant data. This AI integration aims to automate and improve the accuracy of validation processes, which are essential for establishing the trustworthiness of transactions and decisions.

Artificial intelligence can significantly reduce transaction costs, demystify complex concepts, and facilitate easier collaboration. However, this potential is fully realized only when AI operates on valid data and when there's a verifiable mechanism to trust and, importantly, retrospectively review or appeal automated decisions. This need underscores our library's commitment to recording inputs, outputs, data models, platform details, and versioning—elements critical for post-process evaluation and modification of AI decisions. This means also AI risk management, so the system needs to mitigate risks associated with unintended outcomes, adversarial inputs, and biases, with the goal to build robust and reliable decision-making in decentralized systems or at least allow finding cases when that has not happened.

This decision document centers around structuring the validation, monitoring, and secure operations logic. Our primary objectives are:

1. Facilitate ease of understanding, maintenance, and operation, anticipating the construction of larger, software-intensive systems. Users of Verifiable should have the capability to monitor and refactor its functioning reliably.

2. Accommodate future extensions and evolving sets of claims, such as through refactoring and obsoleting processes.

3. Record claims for checks that either succeed or fail to ensure the execution of checks.

4. Each claim possesses a unique code correlating to a specific code point, enabling "off-Verifiable" utilization. Hence, coding needs to be adaptable to allow others to introduce identifiers.

5. Integrate validation with the runtime environment, distributed tracing, Continuous Integration Environment, version control, monitoring operations, and the secure development lifecycle along with risk and compliance monitoring.

6. Ensure ease of integration with other tools and frameworks when necessary.

7. Facilitate the translation of sector-dependent, regulatory, and other demands into software and enable discussions within the context of Verifiable and its developers.

### Additionally

a. There are plans to introduce remote claim generation and assessments potentially and other system behaviors. This will be subject to a separate ADR and will involve extensive threat modeling.

b. Point `a.` is partially driven by consideration for cross-sector, secure data operations as part of the circular and regenerative economy, and data structures. It appears such dependent data systems are governed in distributed fashion and include socio-economic, system external factors that may influence some operations. There may be need to blend them into operational systems seamlessly.

## Decision

We will introduce a `Claim`, `Assessor`, and `Archiving` model for validation.

- **Claim**: An immutable record containing a unique identifier and a boolean indicating validation result. Since these are immutable records, they can be cached and reused. NOTE: Future refactoring may introduce a chance to capture claim generation context and non-binary result, pursuant to point a. in the previous section.

- **Assessor**: Aggregates multiple Claims to provide an auditable record of a series of validation operations. A function within will interpret the success or failure based on its understanding of the context in which the claims were made. The Assessor has an identifier so it can be tracked.

- **Archiving**: Archiver has an identifier that can be tracked. Its purpose is to archive results by assessors as per user-defined functionality.

## Rationale

1. **Distributed and decentralized systems**: Claim, Assessor, and Archiving model are tailored to operate within distributed and decentralized systems, providing a structured, verifiable, and auditable mechanism to capture, assess, and archive validations and decisions across disparate systems and networks.

2. **Regulatory adherence and contractual obligations**: The immutable and traceable nature of Claims supports adherence to various sector-specific, regulatory, and contractual obligations, ensuring that actions and decisions taken by the system can be audited and verified against predefined legal and contractual frameworks.

3. **Multi-temporal and multi-stakeholder environments**: The model facilitates validations and decision-making processes that span various time scales – from real-time to slower, deliberate processes – and caters to environments where multiple stakeholders (systems, entities, or individuals) with varying obligations and operational cadences are involved.

4. **Demonstrable duty of care**: By capturing and preserving the context and outcome of each validation operation in Claims, the system demonstrates a duty of care, ensuring that actions and decisions are transparent, verifiable, and auditable, fulfilling both immediate and future verification and auditability requirements.

5. **Risk management and trust creation**: The structure facilitates risk management and trust creation in software-intensive data architectures, enabling collaboration and decision support while complying with regulatory frameworks like SSI, eIDAS, and others. This approach supports creating real trust among stakeholders and managing inherent unknowns in dynamic environments.

6. **AI Risk Management**: The Claim and Assessor models are designed to support risk management by recording and contextualizing decisions, enabling the identification and mitigation of unintended outcomes, adversarial influences, and systemic biases in AI-driven processes. This approach aligns with Verifiable's commitment to building trustworthy and reliable decentralized systems.

## Alternatives Considered

- **Single Validation Function**: This approach is hard to maintain and extend due to its monolithic nature which can become complex and hard to manage with growing requirements.

- **Third-Party Libraries**: These do not meet the specific requirements and need for fine-grained control, though they can be utilized by Verifiable users.

## Consequences

1. Maintenance and extensibility will be more straightforward for Verifiable developers also operating it.

2. Security and compliance will be improved for Verifiable developers and allow for domain-bound discussion even between different domains.

3. Initial development may require more time to set up the Claim, Assessor, and Archiving model.

4. *(Potential negative consequences or trade-offs can be listed here)*

## Status

Accepted.

## References

[Explainable Artificial Intelligence (XAI) 2.0: A Manifesto of Open Challenges and Interdisciplinary Research Directions](https://arxiv.org/abs/2310.19775).

## Revision History

None.
