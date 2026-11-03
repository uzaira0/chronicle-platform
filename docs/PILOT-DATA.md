# Pilot exports

The seven pilot modules use four export datasets. `UsageEvents` carries app usage,
activity classes, device lifecycle events and user-identification labels together.
`BatteryTelemetry`, `SensorAvailability` and `UploadDiagnostics` carry the other three modules.
A fifth dataset, `AppUsageSurvey`, holds the daily app-usage survey answers of shared devices.

Participant downloads are one dataset per download, streamed straight to the browser:
CSV from the dashboard, CSV or JSON (`responseType=json`) from the API.
There are no server-side export jobs or stored export files. A download takes
explicit participant IDs (`participantId`, one or more; a request with none is refused):
select them on the Participants page. Select all picks the participants shown; the page
shows 100 at a time, and Show more reveals the next 100 before you select all.
The date bounds are independently optional (`startDate`, `endDate`); the dashboard sends
days in the study time zone. Omitting either bound includes retained history in that
direction. Supplied bounds must define a positive range. The download does not limit
the number of rows.
JSON is an array of row objects. CSV renders absent values as blank cells; strings that
could be interpreted as spreadsheet formulas are prefixed with an apostrophe.

JSON preserves SQL `null` for nullable usage-event and app-survey text fields, including
`activity_class`, `application_label` and `username`. Missing usage/survey timestamps
are empty strings. Dedicated collection datasets (including battery and sensor
availability) and upload diagnostics use empty strings for missing scalar values.
PostgreSQL arrays and JSON values are exported as strings in both formats; an empty
sensor array is the PostgreSQL array string `{}`. Test for both `null` and `""` when treating usage text as missing.

`AppUsageSurvey` has one row per answered survey day, app and block. A survey day is a
calendar day in the study time zone; the daily survey has one block, the whole day (the
hourly survey has one per hour). A day the participant confirmed with nothing to review is
one row at the start of the day with an empty `app_package_name`, no `application_label`
and `users` `{}`. "I don't know" is stored in `users` like the other answers.

All datasets include `study_id` (study UUID) and `participant_id` (researcher-assigned ID).

| Dataset | Columns and values |
| --- | --- |
| UsageEvents | `app_package_name`: Android package; `application_label`: app label; `activity_class`: activity class when allowed; `interaction_type`: readable event label; `event_type`: numeric Chronicle/Android usage event code; `event_timestamp`: event time; `timezone`: captured IANA zone; `username`: selected user label on UsageStats events (`Study participant` or `Someone else`; rows from releases before 2026-10-29 say `Target child` or `Other`), empty before a selection, when identification is not consented, and on supplemental Device Lifecycle events; `uploaded_at`: server receipt time; `client_event_id`: phone-assigned retry identity. |
| AppUsageSurvey | `survey_date`: the answered survey day; `app_package_name` and `application_label`: the app asked about; `event_timestamp`: start of the answered block (the start of the day for the daily survey), not a usage event time; `timezone`: study time zone of the survey day; `users`: the selected answers as a PostgreSQL array string, for example `{"Parent alone","I don't know"}`; `submission_date`: server receipt instant shared by the submitted batch, not a calendar date; `answer_lag_seconds`: seconds from the end of the survey day to `submission_date`. |
| BatteryTelemetry | `sample_id`: phone-assigned retry identity; `sample_timestamp`: capture time; `timezone`: phone IANA zone; `level_percent`: 0–100; `charging_state`: UNKNOWN, CHARGING, DISCHARGING, NOT_CHARGING or FULL; `plug_type`: UNPLUGGED, AC, USB, WIRELESS or DOCK; `health`: UNKNOWN, GOOD, OVERHEAT, DEAD, OVER_VOLTAGE, UNSPECIFIED_FAILURE or COLD; `temperature_deci_c`: tenths of a degree Celsius; `voltage_millivolts`: millivolts; `uploaded_at`: server receipt time; `low_power_mode`: empty for Android pilot samples; `random_device_id`: authenticated enrolled app instance; `device_type`: Android or Ios; `producer_version`: collector build recorded with the sample at capture. Historic source metadata and versions that older collectors did not record are empty, never inferred from the current app or enrollment version. |
| SensorAvailability | `random_device_id`: enrolled app instance; `available_sensors`: every modeled sensor type the device has, checked whether or not any sensor module is enabled (a modeled type missing from the list is one the device lacks); `reported_at`: latest server receipt time. The schema also has `screen_width_pixels`, `screen_height_pixels`, `screen_density_dpi`, `display_rotation` and `interaction_pointer_capture_capability`; the pilot app leaves these empty. The `sensor_availability` module toggle decides whether the report is sent. There is one latest snapshot per participant/device, rather than one row per refresh. |
| UploadDiagnostics | `random_device_id`: enrolled app instance; `event_id`: diagnostic retry identity; `diagnostic_day`: phone-local occurrence day; `module_family`: affected collection family; `issue_code`: closed failure category; `occurrence_count`: equivalent failures at one instant; `first_occurred_at` and `last_occurred_at`: that instant (always equal); `http_status`: response code when available; `error_type`: redacted exception class when available; `uploaded_at`: server receipt time. Credentials, URLs, exception messages and stack traces are excluded. |

Usage and battery date ranges include their lower instant and exclude their upper
instant. Availability uses `reported_at` with the same rule. The survey selects the survey
days (`survey_date`) that start inside the range in the study's time zone, also after that
zone is corrected. Usage, battery
and survey timestamps render in each row's `timezone`; compare instants when clocks repeat at
the Santiago daylight-saving transition. Diagnostic ranges select local occurrence
days: a midnight upper bound excludes that day; a later time includes it. Diagnostic
row counts measure stored occurrences, while `occurrence_count` measures failures.

Retries preserve usage `client_event_id`, battery `sample_id` and diagnostic `event_id`.
Resending the same batch does not add duplicate rows. Usage exports read event storage;
acknowledged events appear after the upload-buffer mover stores them. Availability replaces the same
device's latest snapshot. User-identification selections are retained locally to label
subsequent UsageStats events, including available startup/shutdown events collected by App Usage.
Supplemental Device Lifecycle events always have an empty `username`, including charger events.
Selections do not create a standalone uploaded record or a separate Android export dataset.

Executable checks: `PilotE2ETest` covers public enrollment, all pilot upload
surfaces, retries, streamed CSV and JSON downloads of every dataset, date bounds across
Santiago's repeated hour, and 25 devices with 31 days of samples across a 400-day requested range at the default
15-minute collection cadence (224,000 exported rows including daily diagnostic
aggregates and latest availability snapshots). This is a synthetic volume check;
physical collection through reboot, Doze and OEM restrictions needs the Pixel drill.

## iOS Screen Time

For studies using the bare iOS app, select `IOSScreenTime` (dashboard label
**iOS Screen Time**). This is a separate dataset from the Android pilot datasets.
Uploads commit directly to `ios_screen_time_usage`; acknowledged rows are ready to
export without a buffer-drain delay. Webhook data-submission notifications use the
same `IOSScreenTime` data type.

The export is a dictionary of app and web-domain usage, with these columns:

| Columns | Meaning |
| --- | --- |
| `study_id`, `participant_id` | Study UUID and researcher-assigned participant ID. |
| `random_device_id` | Enrolled app instance; windows from different devices stay separate. |
| `record_id` | Phone-assigned capture record UUID. |
| `row_kind` | `application` (app name or bundle ID, no web domain) or `webDomain` (domain present, including an empty label from Apple; no app labels). |
| `captured_at` | Actual capture instant, retained without rounding. |
| `observation_start`, `observation_end` | Absolute bounds of the measured window, normally an hour. |
| `timezone` | Device IANA zone; repeated DST hours remain distinct absolute windows. |
| `app_name`, `bundle_identifier`, `web_domain`, `category_name` | Optional app label, bundle ID, web domain and category label. |
| `duration_seconds` | Cumulative usage in seconds for this app/domain in this window. |
| `notification_count`, `pickup_count` | Optional cumulative counts; missing counts remain absent. |
| `uploaded_at` | Server receipt instant; used for upload compliance. |

The database keeps captures; export keeps exactly the newest capture for each
participant/device/window and app/domain/category identity. A later capture
of the same window replaces its earlier total in the export: do not sum raw
captures as additional minutes. Different apps and web domains have separate rows;
the server refuses a row whose labels contradict its row kind. Date bounds select
`observation_start`, lower inclusive and upper exclusive. Optional scalar values export as empty strings in CSV and JSON,
matching the other dedicated collection datasets. `capture_labels_hash` is an
internal index column and is never exported.
