# Validation model

CryptoLab validates its educational and library-backed behavior through complementary forms of
evidence:

- unit, integration, round-trip, invalid-input, boundary, and selected property-based tests;
- mathematical identity verification;
- published NIST and RFC vectors;
- strict static analysis and documentation builds;
- release metadata and distribution-content checks;
- optional direct SageMath comparison for selected educational operations.

Passing tests, vectors, or SageMath cross-validation does not constitute:

- certification;
- formal proof;
- an independent audit;
- guaranteed side-channel resistance;
- unconditional production approval.

The mandatory Python validation path is self-contained and does not require SageMath. Optional
cross-validation executes CryptoLab and SageMath independently from the same runtime inputs and
compares their normalized outputs. SageMath remains outside the wheel and normal CLI runtime.
