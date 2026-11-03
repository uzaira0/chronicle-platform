// Fixtures for `semgrep --test --config sql-injection.yaml sql-injection.java`.
import java.sql.SQLException;
import java.sql.Statement;

class StatementExecuteFixtures {
    void built( Statement statement, String table ) throws SQLException {
        // ruleid: chronicle-statement-execute
        statement.execute( "DROP TABLE " + table );
        String sql = "DELETE FROM " + table;
        // ruleid: chronicle-statement-execute
        statement.executeUpdate( sql );
        // ruleid: chronicle-statement-execute, chronicle-sql-format
        statement.executeQuery( String.format( "SELECT * FROM %s", table ) );
    }

    void notBuilt( Statement statement, String callerSql ) throws SQLException {
        // ok: chronicle-statement-execute
        statement.execute( "SELECT 1" );
        // ok: chronicle-statement-execute
        statement.execute( callerSql );
    }
}
