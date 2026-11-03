import com.openlattice.chronicle.upgrades.FlywayMigrationService;

// A filesystem copy permits a throwaway V2 without touching the server's migrations.
class ForwardMigration {
    public static void main(String[] args) {
        var flyway = FlywayMigrationService.Companion.baseConfiguration()
            .dataSource(args[0], args[1], args[2])
            .locations("filesystem:" + args[3]).load();
        var result = flyway.migrate();
        if (!result.success) throw new IllegalStateException("fixture migration failed");
        System.out.println(result.migrationsExecuted);
    }
}
