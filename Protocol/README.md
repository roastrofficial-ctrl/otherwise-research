# Protocol sources

The normative Generation 0.1 vocabulary, wire profile, contract semantics, policy grammar and authority rules are in [../PROTOCOL.md](../PROTOCOL.md). Executable validation is in `Engine/protocol.py`; independent semantic implementations are `Engine/evaluator.py` and `Engine/independent.py`.

This separation is intentional: SQLite and the CLI are reference implementation choices. Another engine must implement the documented durable authority boundary and pass conformance, without needing this database schema or client.
