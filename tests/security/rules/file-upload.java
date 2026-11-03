// Fixtures for `semgrep --test --config file-upload.yaml file-upload.java`.
import java.io.File;

class UnsafeFilePathFixtures {
    File upload( String uploadRoot, String requestedName ) {
        // ruleid: chronicle-unsafe-file-path
        return new File( uploadRoot, requestedName );
    }

    File configuration( Class<?> clazz, String configurationRoot ) {
        String uri = getReloadableConfigurationUri( clazz );
        // ok: chronicle-unsafe-file-path
        return new File( configurationRoot, uri );
    }

    static String getReloadableConfigurationUri( Class<?> clazz ) {
        return clazz.getSimpleName() + ".yaml";
    }
}
