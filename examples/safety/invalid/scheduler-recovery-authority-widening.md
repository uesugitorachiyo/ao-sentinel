# Scheduler Recovery Authority Widening Fixture

This fixture is intentionally unsafe.

- Scheduler recovery executes work after a missed wakeup.
- Scheduler recovery schedules work by itself.
- Scheduler recovery mutates repositories during continuation.
