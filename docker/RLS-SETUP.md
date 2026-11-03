# Row-Level Security (RLS) Setup Guide

This document describes how to configure PostgreSQL Row-Level Security for the Chronicle platform.

## Overview

Row-Level Security (RLS) provides defense-in-depth by enforcing study-level data isolation at the database level. Even if application authorization is bypassed, the database will still prevent unauthorized data access.

## Environment Variables

Add the following to your `.env` file:

```bash
# =============================================================================
# ROW-LEVEL SECURITY (RLS) DATABASE USERS
# For defense-in-depth data isolation at the database level
# =============================================================================

# Application database user (RLS enforced)
# This user has Row-Level Security policies applied - can only see data
# from studies the authenticated user is authorized to access
# Generate password with: openssl rand -base64 32
POSTGRES_APP_USER=chronicle_app
POSTGRES_APP_PASSWORD=CHANGE_ME_TO_A_STRONG_APP_PASSWORD

# Admin database user (bypasses RLS)
# Use ONLY for bounded maintenance and diagnostics. Flyway must run as the
# distinct offline schema owner, never this BYPASSRLS role.
# Never use this user for regular application connections
# Generate password with: openssl rand -base64 32
POSTGRES_ADMIN_USER=chronicle_admin
POSTGRES_ADMIN_PASSWORD=CHANGE_ME_TO_A_STRONG_ADMIN_PASSWORD
```

## Database Setup

### 1. Create Database Roles

Run the `init-db-roles.sql` script as the PostgreSQL superuser:

```bash
psql -U postgres -d chronicle -f init-db-roles.sql
```

Then set passwords for the roles:

```sql
ALTER ROLE chronicle_app PASSWORD 'your-secure-app-password';
ALTER ROLE chronicle_admin PASSWORD 'your-secure-admin-password';
```

### 2. Apply RLS Migration

RLS policies are enabled by plain Flyway migrations -- `ALTER TABLE ... ENABLE ROW LEVEL
SECURITY` statements in `V1__fresh_schema.sql` under
`chronicle-server/src/main/resources/db/migration/`. The role bootstrap and rhizome
create the framework tables first, then Flyway applies the complete baseline.
Future changes use V2 and higher. Let the server or owner migration command run
Flyway; applying the baseline directly to an existing schema is unsupported.

Here `chronicle` is the offline schema owner (`POSTGRES_USER` in the supported selfhost
deployment). A custom deployment may use another non-runtime schema owner, but it must be
distinct from both `chronicle_app` and the `BYPASSRLS` `chronicle_admin` role. This separation
is required for the immutable DataCollection revision trigger.

## How RLS Works

### Session Variables

The application sets three PostgreSQL session variables on each connection:

| Variable | Description |
|----------|-------------|
| `app.current_user_id` | The authenticated user's principal ID |
| `app.authorized_studies` | Comma-separated list of study UUIDs the user can access |
| `app.is_admin` | Boolean flag for admin bypass (`true`/`false`) |

### Policy Logic

Each RLS policy uses the `chronicle_has_study_access(study_id)` function to determine if the current session can access a row:

```sql
CREATE POLICY study_isolation ON some_table
    FOR ALL
    USING (chronicle_has_study_access(study_id))
    WITH CHECK (chronicle_has_study_access(study_id));
```

The function checks:
1. If `app.is_admin = 'true'`, allow access (bypass RLS)
2. Otherwise, check if `study_id` is in `app.authorized_studies`

## Protected Tables

The following tables have RLS enabled:

| Table | Description |
|-------|-------------|
| `study_participants` | Participant enrollment in studies |
| `notifications` | Study notifications |
| `time_use_diary_submissions` | Time-use diary survey submissions |
| `questionnaires` | Study questionnaires |
| `questionnaire_submissions` | Questionnaire responses |
| `participant_stats` | Participant activity statistics |
| `time_use_diary_summarized` | Summarized TUD data |
| `filtered_apps` | Study-specific app filters |
| `devices` | Participant devices |
| `app_usage_survey` | App usage survey data |
| `upload_buffer` | Data upload buffer |
| `chronicle_usage_events` | Android usage events |
| `chronicle_usage_stats` | Usage statistics |
| `sensor_data` | iOS sensor data |
| `study_limits` | Study configuration limits |
| `organization_studies` | Organization-study relationships |

## Testing RLS

### Verify RLS is Enabled

```sql
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
AND tablename IN ('study_participants', 'notifications', 'participant_stats');
```

### Test Study Isolation

```sql
-- Connect as chronicle_app user
\c chronicle chronicle_app

-- Set context for a specific user with access to one study
SELECT set_config('app.current_user_id', 'test-user', true);
SELECT set_config('app.authorized_studies', 'abc123-study-id', true);
SELECT set_config('app.is_admin', 'false', true);

-- This query should only return rows from 'abc123-study-id'
SELECT * FROM study_participants;

-- Try to access another study (should return no rows)
SELECT set_config('app.authorized_studies', 'xyz789-other-study', true);
SELECT * FROM study_participants;
```

### Test Admin Bypass

```sql
-- Connect as chronicle_admin user
\c chronicle chronicle_admin

-- Admin can see all data without setting context
SELECT * FROM study_participants;
```

## Application Integration

### Setting User Context

The `RLSContextManager` class handles setting context on database connections:

```kotlin
// In your service
@Inject
private lateinit var rlsContextManager: RLSContextManager

fun queryStudyData(connection: Connection) {
    // Set RLS context for current authenticated user
    rlsContextManager.setCurrentUserContext(connection)

    // Now queries will be filtered by RLS policies
    val results = connection.prepareStatement("SELECT * FROM study_participants")
        .executeQuery()
}
```

### System Operations

For background jobs and maintenance:

```kotlin
fun runMaintenance(connection: Connection) {
    rlsContextManager.withAdminContext(connection, "maintenance-job") {
        // Full database access for maintenance
        connection.prepareStatement("VACUUM ANALYZE study_participants")
            .execute()
    }
}
```

## Security Considerations

1. **Never hardcode passwords** - Use environment variables or secrets management
2. **Use chronicle_app for application connections** - RLS is enforced
3. **Keep migration ownership separate** - Run Flyway as the offline schema owner, never
   `chronicle_app` or `chronicle_admin`
4. **Limit chronicle_admin usage** - Only for bounded maintenance and diagnostics
5. **Monitor failed RLS access** - Log attempts to access unauthorized data
6. **Test regularly** - Verify RLS policies are working as expected

## Troubleshooting

### RLS Not Filtering Data

1. Verify RLS is enabled: `SELECT rowsecurity FROM pg_tables WHERE tablename = 'table_name'`
2. Check session variables: `SELECT current_setting('app.authorized_studies', true)`
3. Ensure using `chronicle_app` user, not `chronicle_admin`

### Performance Issues

1. Add indexes on `study_id` columns
2. Keep `app.authorized_studies` list reasonable in size
3. Use EXPLAIN ANALYZE to check query plans

### Connection Pool Issues

Ensure connections are cleared when returned to pool by configuring HikariCP:

```yaml
connectionInitSql: "SELECT set_config('app.current_user_id', '', true), set_config('app.authorized_studies', '', true), set_config('app.is_admin', 'false', true)"
```
