# Agents inbox: the work queue (protocol: `documents/agents-protocol.md`)

Working branch: `veritas-consolidation`

## Queued

- **WINSERVER: ARRIVE done; GATE and STRYKER SIZING ON HOLD.** The mail `agent-mail/winserver-2026-09-23` carries the first three tasks (prove you heard; the arrival gate: rebuild 0/0 and the full suite twice; a plan-first Stryker sizing run on `Verifiable.Foundation` with the runner-compatibility check for MSTest on Microsoft.Testing.Platform). Task 1 is answered on `agent-mail/winserver-ack-2026-09-23`. Tasks 2 and 3 are paused by the follow-up mail `agent-mail/winserver-2026-09-23b`: the Veritas packages pin to a machine-local feed that WINSERVER cannot reach, so the restore cannot succeed there. Resume them only when a new pointer here says so, after the Veritas packages are published to NuGet and the pins move to it. When done, move this line to `## Done` with the date and the final SHA.

## Done

## Questions
