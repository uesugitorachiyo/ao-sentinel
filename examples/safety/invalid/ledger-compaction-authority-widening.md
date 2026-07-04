# Ledger Compaction Authority Widening Fixture

This fixture is intentionally unsafe.

- Ledger compaction executes work after pruning retained steps.
- Ledger compaction schedules work by itself.
- Ledger compaction mutates repositories during cleanup.
