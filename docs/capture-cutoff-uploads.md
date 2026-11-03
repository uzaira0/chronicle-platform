# Capture windows and the hard stop

Rules:

1. One clock. The server never compares a phone timestamp with its own clock, and the phone never compares
   a raw server time with its wall clock.
2. Withdrawal, a declined required module and the dashboard's Mark not enrolled clear everything pending
   upload and stop collection. Data already on the server stays.
3. Pause, completion, archive and the processing block are not withdrawal. Rows captured before them still
   upload; nothing is collected during them.

## Capture windows (pause, completion, archive, processing block)

The server keeps each participant's closed capture windows in `study_participants.closed_capture_windows`
(server instants, `[start, end)`), plus the open window of a current pause, completion, archive or processing
block. Unblocking a processing block closes its window. The status poll
(`ChronicleStudyApi.getDeviceParticipationStatus`, `MobileReminderController.getParticipationStatus`) returns them with the database's `serverTime`:

```json
{"participationStatus": "PAUSED", "serverTime": "2026-10-28T12:00:00.123Z",
 "captureWindows": [{"start": "2026-10-28T11:00:00Z", "end": null}]}
```

The upload routes store every queued row of a paused, completed or archived participant, whatever its phone
timestamp. During a processing block every upload is refused. The server-only checks remain: enrollment,
credentials, consent and the erasure watermark.

The phone measures `ServerClock` on each status poll: the offset between `serverTime` and its wall clock at
the request's midpoint, anchored on `elapsedRealtime`. A later manual clock change is tracked without a new
poll; a reboot keeps the last offset until the poll that boot, `TIME_SET` and the periodic monitor enqueue.
A time zone change moves no instant. With the windows converted to its own clock, the phone:

- collects nothing inside a window and never backfills it (history sources skip suspended intervals);
- before an upload can run again, drops each queued row captured inside a window, and only those rows;
- on learning of a pause or completion, first reads the last usage poll up to the window start.

A phone running 20 s fast keeps a row captured 10 s before the pause: the window start converts to
the pause plus 20 s on the phone's clock.

## Hard stop (withdrawal, required decline, Mark not enrolled)

Each trigger first writes its durable mark: the withdrawal state, `NOT_ENROLLED`, or the declined required
module. The upload gate refuses on the mark alone. Every research stop then clears every upload queue,
held rows, sensor dead letters, row evidence and pending diagnostics, stops collectors, the unlock monitor
and reminders, and cancels collection and upload work. A process death between mark and clear is finished
by the next start. The local quarantine never uploads and stays. The status monitor and the settings sync keep
running, so re-enrollment and re-acceptance resume collection and its work.

The server refuses every upload once a trigger stands (HTTP 403), including rows captured before a required
decline, and `surveyEnrollment` refuses these participants. A phone that receives 403 polls its status at
once, which applies the trigger it missed.

### A hard stop the phone never saw

The researcher can mark a participant not enrolled and enroll them again while the phone is offline. Its next
poll then reads `ENROLLED` and a closed window, never `NOT_ENROLLED`. So the server keeps the hard stop as its
own fact: the `record_capture_cutoff` trigger counts every change to `NOT_ENROLLED`, by any writer
(`study_participants.hard_stop_generation`), and stamps when the latest began (`hard_stopped_at`). No writer
can set either column. The status poll publishes both from the same snapshot as the windows:

```json
{"participationStatus": "ENROLLED", "serverTime": "2026-10-28T14:00:00Z",
 "captureWindows": [{"start": "2026-10-28T12:00:00Z", "end": "2026-10-28T13:00:00Z"}],
 "hardStop": {"generation": 1, "at": "2026-10-28T12:00:00Z"}}
```

Under the stop, before any upload can run again, the phone treats everything captured before `at` as one more
capture window: those queued rows are dropped and the usage source never reads that history again. When the
generation advances past the one this enrollment last saw, it also clears the queues with no capture time
(pending diagnostics and sensor dead letters) and then records the generation. Identity labels selected before
the stop go too, through the same clock mapping. A label selected inside a pause stays: it labels what is
captured after the resume. Rows captured after
the re-enrollment stay and upload. The enrollment response supplies the current generation as a durable
baseline before collection starts, so a stop before the first poll still clears untimed queues. A missing
baseline clears conservatively. Pause, resume and completion move neither column.

Restore carries both hard-stop columns in the existing protected restrictions checkpoint, including for
participants who resumed. The capture-cutoff trigger imports those facts monotonically during containment;
the checkpoint digest and post-restore verification cover both columns. A still-open withdrawal window keeps
its original cutoff, so a later re-enrollment closes the entire stopped interval across the restore. A restore
onto an empty database has no checkpoint and lowers the count. The phone still applies every status, takes the
server's count, and keeps the stop instant it already holds, so the next stop on the restored server clears again.
Status polls run one at a time, so an older response never lands after a newer one.

The server does not also refuse pre-stop rows at upload: that would compare a phone timestamp with a
server instant without the phone's clock mapping (ruling 1). The phone's status step precedes every upload,
as it does for the windows, and maps the hard-stop instant through that same synced clock.

## Removed

- The server filter comparing phone capture time with the server's pause, completion and archive cutoffs
  (TIME-1). It discarded rows captured before the stop when the phone clock ran fast.
- `collectedAt` / `collected_at`, the phone's queue-write ordering value, from the wire, storage and
  export (TIME-2). Capture time is the row's own timestamp.
- The phone and browser checks of the invitation expiry against their own clocks (TIME-4). The server
  refuses an expired invitation and the phone ends the attempt on that refusal.
