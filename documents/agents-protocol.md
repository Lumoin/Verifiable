# Agent coordination protocol: the repository is the channel

The repository replaces the owner as the message bus between the development boxes and the WINSERVER worker. The owner reads results and makes calls; agents coordinate through commits on Azure DevOps.

## The channel

- **Work queue:** `documents/agents-inbox.md` is the single file the WINSERVER worker polls. It carries the working branch name at its top, and zero or more brief pointers under `## Queued`, newest last. A development box appends a pointer line when a brief lands; the worker moves the line to `## Done` (with the date and the final commit SHA) when the brief's last order is pushed.
- **Briefs:** `documents/winserver-round<N>-brief.md`, numbered orders, definite deliverables, each committed and pushed on completion. A `## Queued` pointer names either such a brief or a mail branch (below); the pointer line itself states the hold or go state of the orders it points at.
- **Questions upward:** a worker that needs a decision or meets a design question appends it to `## Questions` in the inbox file and continues with the unblocked orders. The development box answers by editing the entry in place (the answer indented under the question), never by owner relay. Owner-level calls are marked `OWNER:` and wait for the owner in the same file.
- **Conflict rule:** the inbox is append-or-move only, one section per writer role (the development boxes own `## Queued`, the worker owns `## Done`, all may append `## Questions`); pull before every edit; a push rejection means pull with rebase and retry.
- **Mail when the loop is not running:** a self-contained `WINSERVER-MAIL.md` on an orphan branch `agent-mail/winserver-<date>`, answered by `WINSERVER-ACK.md` on `agent-mail/winserver-ack-<date>`. Mail branches are never merged.

## The standing worker loop (WINSERVER)

The owner starts this once; thereafter no per-round instructions exist:

> Standing loop for the Verifiable repository: every 30 minutes (or when told to check), `git fetch` and `git pull` on the branch named at the top of `documents/agents-inbox.md`, and read that file. If `## Queued` names a brief whose pointer is not yet under `## Done`: execute it per its own orders (each deliverable committed on the branch the brief names, `winserver/<topic>` unless the brief says otherwise, and pushed on completion), then move its pointer to `## Done` with the date and the final SHA, commit, push. If an order blocks, record the blockage in its deliverable, push, append any question to `## Questions`, continue. If the queue is empty, idle until the next poll. Never modify `src/` or `test/` unless a brief explicitly says so. Never push to `main` or to the working branch itself.

## Rules that bind every box

- Never touch a real TPM; the TPM tests run against a simulator only.
- No AI attribution in commit messages or trailers.
- Binlogs and `.trx` files are transient: read, record, delete in the same act; never committed, never mirrored.
- The owner's OneDrive coordination folder (the notes and records the development boxes share) is not a channel to WINSERVER; it reaches that box only through the owner's own remote-desktop session.

## When the worker goes quiet

The standing loop dies with its session. If a queued brief sits unclaimed across days, the owner re-seeds the worker with a short relay that only points at the inbox (the repository stays the source of truth; never restate orders), in plain prose without lists, code fences or other markup, because it crosses a remote-desktop clipboard that mangles formatting.

## Division of concerns

Development boxes (KARKKI, KONE): design-loaded work, plan records, audits, the specification corpus, anything needing the shared coordination folder or the owner's session notes. WINSERVER: measurement, verification, mutation testing, long runs, heavy files. A deliverable states which box produced it.
