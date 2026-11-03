import com.fasterxml.jackson.databind.ObjectMapper;
import com.geekbeast.configuration.postgres.PostgresFlavor;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.openlattice.chronicle.authorization.JwtBlocklist;
import com.openlattice.chronicle.storage.ResolvedStorage;
import com.openlattice.chronicle.storage.StorageResolver;
import com.zaxxer.hikari.HikariDataSource;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.mockito.Mockito;

/** Exercise the production durable session gate on both sides of a real logout. */
class ResearcherSessionProbe {
    record Request(String jdbcUrl, String username, String password, String tokenValue, long issuedAtEpoch) {}
    record Result(boolean beforeLogout, boolean afterLogout) {}

    public static void main(String[] args) throws Exception {
        var mapper = new ObjectMapper();
        var request = mapper.readValue(System.in, Request.class);
        var config = new Config();
        config.setClusterName("restore-session-" + UUID.randomUUID());
        config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
        var hazelcast = Hazelcast.newHazelcastInstance(config);
        Result result;
        try (var dataSource = new HikariDataSource()) {
            dataSource.setJdbcUrl(request.jdbcUrl());
            dataSource.setUsername(request.username());
            dataSource.setPassword(request.password());
            var storage = Mockito.mock(StorageResolver.class);
            Mockito.when(storage.getDefaultPlatformStorage()).thenReturn(new ResolvedStorage(PostgresFlavor.VANILLA, dataSource));
            var sessions = new JwtBlocklist(hazelcast, storage);
            var issued = Instant.ofEpochSecond(request.issuedAtEpoch());
            var window = Duration.ofHours(1);
            var expiry = issued.plus(window);
            boolean before = sessions.isSessionActive(request.tokenValue(), issued, expiry, window, Instant.now());
            sessions.blockTokenByValue(request.tokenValue(), expiry);
            result = new Result(before, sessions.isSessionActive(request.tokenValue(), issued, expiry, window, Instant.now()));
        } finally {
            hazelcast.shutdown();
        }
        System.out.println(mapper.writeValueAsString(result));
    }
}
