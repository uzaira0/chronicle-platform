"""Published POMs carry the GPL license declared by the Chronicle projects."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]


class MavenLicenseTests(unittest.TestCase):
    def test_generated_pom_licenses_match_the_declared_gpl(self):
        projects = ('chronicle-server', 'chronicle-api', 'chronicle-models', 'rhizome-client')
        with tempfile.TemporaryDirectory(prefix='pom-licenses-') as folder:
            work = Path(folder)
            init = work / 'pom-output.gradle'
            init.write_text('''allprojects {
    tasks.withType(org.gradle.api.publish.maven.tasks.GenerateMavenPom).configureEach {
        destination = new File(System.getenv('CHRONICLE_POM_TEST_DIR'), project.name + '.pom')
    }
}
''')
            for branch in ('develop', 'main'):
                subprocess.run([str(ROOT / 'gradlew'), '--no-daemon', '-q', '-I', str(init),
                                *[':' + project + ':generatePomFileForMavenJavaPublication' for project in projects]],
                               cwd=ROOT, env=dict(os.environ, CHRONICLE_POM_TEST_DIR=folder, SIGNING_KEY_PASSPHRASE='synthetic-test-only',
                                        GITHUB_REF='refs/heads/' + branch),
                               check=True, capture_output=True, text=True, timeout=180)
                for project in projects:
                    with self.subTest(project=project, branch=branch):
                        license_text = (ROOT / project / 'LICENSE').read_text()
                        pom = ET.parse(work / (project + '.pom'))
                        license_url = pom.findtext('{*}licenses/{*}license/{*}url')
                        if 'GNU GENERAL PUBLIC LICENSE' in license_text:
                            self.assertEqual('https://www.gnu.org/licenses/gpl-3.0.html', license_url)
                        else:
                            self.assertIn('Apache License', license_text)
                            self.assertEqual('http://www.apache.org/licenses/LICENSE-2.0.txt', license_url)
