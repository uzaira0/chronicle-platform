// Fixtures for `semgrep --test --config sql-injection.yaml sql-injection.kt`.
import java.sql.Connection
import java.sql.Statement

class StatementExecuteFixtures(private val connection: Connection) {
    fun built(statement: Statement, table: String, id: String) {
        // ruleid: chronicle-statement-execute
        statement.execute("DELETE FROM " + table)
        // ruleid: chronicle-statement-execute
        statement.executeQuery("SELECT * FROM $table")
        // ruleid: chronicle-statement-execute, chronicle-sql-format
        statement.executeUpdate(String.format("DELETE FROM %s", table))
        val sql = "DELETE FROM items WHERE id = '" + id + "'"
        // ruleid: chronicle-statement-execute
        statement.executeUpdate(sql)
        val templated = "DELETE FROM ${table}"
        // ruleid: chronicle-statement-execute
        statement.execute(templated)
    }

    fun notBuilt(statement: Statement, callerSql: String) {
        // ok: chronicle-statement-execute
        statement.execute("SET LOCAL statement_timeout = 0")
        // ok: chronicle-statement-execute
        statement.execute(callerSql)
        val constant = "SELECT 1"
        // ok: chronicle-statement-execute
        statement.executeQuery(constant)
        // ok: chronicle-statement-execute
        statement.execute("SELECT '\$literal'")
    }
}
