import com.openlattice.chronicle.contract.ChronicleContractTestSchema;
import java.sql.DriverManager;

// Reuse the production-shaped bootstrap and the real production Flyway configuration.
class RestoreDeployment {
    public static void main(String[] args) throws Exception {
        var schema = ChronicleContractTestSchema.INSTANCE;
        try (var connection = DriverManager.getConnection(args[0], args[1], args[2])) {
            schema.applyFrameworkSchema(connection);
        }
        var result = schema.flywayFor(args[0], args[1], args[2]).migrate();
        if (!result.success) throw new IllegalStateException("Flyway corpus failed");
        System.out.println(result.migrationsExecuted);
    }
}
