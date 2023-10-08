# Introducing Claim, Assessor, and Archiving for Validation in Verifiable Library

## Context

The Verifiable library seeks to establish a framework for a variety of operations as delineated in the [project README.md](../../README.md). This decision centers around structuring the validation, monitoring, and secure operations logic. The objectives are as follows:

1. Facilitate ease of understanding, maintenance, and operation, anticipating the construction of larger, software intensive systems. Users of Verifiable should have the capability to monitor and refactor its functioning reliably.

2. Accommodate future extensions and evolving sets of claims, such as through refactoring and obsoleting processes.

3. Record claims for checks that either succeed or fail to ensure the execution of checks.

4. Each claim possesses a unique code correlating to a specific code point, enabling "off-Verifiable" utilization. Hence, coding needs to be adaptable to allow others to introduce identifiers.

5. Integrate validation with the runtime environment, distributed tracing, Continuous Integration Environment, version control, monitoring operations, and the secure development lifecycle along with risk and compliance monitoring.

6. Ensure ease of integration with other tools and frameworks when necessary.

7. Facilitate the translation of sector-dependent, regulatory, and other demands into software and enable discussions within the context of Verifiable and its developers.

### Additionally

a. There are plans to introduce for remote claim generation and assessments potentially and other system behaviors. This will be subject to a separate ADR and will involve extensive threat modeling.

b. Point a. is partially driven by consideration for cross-sector, secure data operations as part of the circular and regenerative economy, and data structures. It appears such dependent data systems are governed in distributed fashion and include socio-economic, system external factors that may influence some operations. There may be need to blend them in to operational system seamlessly.

## Decision

We will introduce a Claim, Assessor, and Archiving model for validation.

- **Claim**: An immutable record containing a unique identifier and a boolean indicating validation result. Since these are immutable records, they can be cached and reused. NOTE: Future refactoring may introduce a chance to capture claim generation context and non-binary result, pursuant to **point a.** in previous section.

- **Assessor**: Aggregates multiple Claims to provide an auditable record of a series of validation operations. A function within will interpret the success or failure based on its understanding of the context in which the claims were made. The Assessor has an identifier so it can be tracked.

- **Archiving**: Archiver has an identifier that can be tracked. Its purpose is to archive results by assessors as per user-defined functionality.

## Rationale

1. **Distributed and Decentralized Systems**: Claim, Assessor, and Archiving model are tailored to operate within distributed and decentralized systems, providing a structured, verifiable, and auditable mechanism to capture, assess, and archive validations and decisions across disparate systems and networks.

2. **Regulatory Adherence and Contractual Obligations**: The immutable and traceable nature of Claims supports adherence to various sector-specific, regulatory, and contractual obligations, ensuring that actions and decisions taken by the system can be audited and verified against predefined legal and contractual frameworks.

3. **Multi-Temporal and Multi-Stakeholder Environments**: The model facilitates validations and decision-making processes that span various time scales – from real-time to slower, deliberate processes – and caters to environments where multiple stakeholders (systems, entities, or individuals) with varying obligations and operational cadences are involved.

4. **Demonstrable Duty of Care**: By capturing and preserving the context and outcome of each validation operation in Claims, the system demonstrates a duty of care, ensuring that actions and decisions are transparent, verifiable, and auditable, fulfilling both immediate and future verification and auditability requirements.

## Alternatives Considered

- **Single Validation Function**: This approach is hard to maintain and extend due to its monolithic nature which can become complex and hard to manage with growing requirements.

- **Third-Party Libraries**: These do not meet the specific requirements and need for fine-grained control, though they can be utilized by Verifiable users.

## Consequences

1. Maintenance and extensibility will be more straightforward for Verifiable developers also operating it.

2. Security and compliance will be improved for Verifiable developers and allows for domain-bound discussion even between different domains.

3. Initial development may require more time to set up the Claim, Assessor, and Archiving model.

4. *(Potential negative consequences or trade-offs can be listed here)*

## Status

Accepted.

## References

None.

## Revision History

None.
