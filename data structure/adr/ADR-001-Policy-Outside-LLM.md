# ADR-001: Deterministic Policy Outside the LLM
## Decision
The LLM may request actions but cannot authorize them.
## Reason
LLM output is probabilistic and can be influenced by untrusted project content.
## Consequence
Every tool operation must pass through a deterministic policy engine.
