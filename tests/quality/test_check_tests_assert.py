#!/usr/bin/env python3
"""scripts/check-tests-assert.py: a JVM @Test that checks nothing fails the engineering job."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('check_tests_assert', ROOT / 'scripts/check-tests-assert.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

KOTLIN = 'chronicle-server/src/test/kotlin/x/'
JAVA = 'rhizome/src/test/java/x/'


class CheckTestsAssertTests(unittest.TestCase):
    def offenders(self, files):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, text in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text)
            return [line.split(': @Test ')[1].split(' asserts')[0] for line in
                    checker.offenders(checker.declarations(root, checker.TEST_TREES))]

    def test_a_call_with_no_check_is_reported_and_a_comment_is_not_a_check(self):
        self.assertEqual(self.offenders({KOTLIN + 'A.kt': '''
class A {
    @Test
    fun reloads() {
        client.admin.reloadCache() // assertEquals would go here; "assertTrue" in a string neither
    }
    @Test fun checked() { assertEquals(1, client.count()) }
}'''}), ['reloads'])

    def test_a_helper_in_another_test_file_that_asserts_counts_but_an_api_method_of_that_name_does_not(self):
        self.assertEqual(self.offenders({
            KOTLIN + 'Fixture.kt': 'abstract class Fixture {\n    protected fun createStudy(): Int { assertTrue(true); return 1 }\n'
                                   '    protected fun race(flag: Boolean) = assertFalse(flag)\n}',
            KOTLIN + 'B.kt': '''
class B : Fixture() {
    @Test fun viaHelper() { createStudy() }
    @Test fun viaReference() = listOf(true).forEach(::race)
    @Test fun viaApiMethodWithTheSameName() { client.studyApi.createStudy() }
}'''}), ['viaApiMethodWithTheSameName'])

    def test_mock_verify_property_checks_and_expected_exceptions_count(self):
        self.assertEqual(self.offenders({KOTLIN + 'C.kt': '''
class C {
    @Test fun verified() { service.run(); Mockito.verify(store).write(1) }
    @Test fun property() = runBlocking { forAll(Arb.int()) { it == it } }
    @Test(expected = IllegalStateException::class) fun throws() { service.run() }
}'''}), [])

    def test_java_tests_are_checked_too(self):
        self.assertEqual(self.offenders({JAVA + 'D.java': '''
public class D {
    @Test
    public void served() { TestConfiguration actual = api.getTestConfigurationSecuredAdmin(); }
    @Test
    public void compared() { Assert.assertEquals( expected, api.get() ); }
}'''}), ['served'])

    def test_assertion_named_values_are_not_assertion_calls(self):
        self.assertEqual(self.offenders({KOTLIN + 'A.kt': '''
class A {
    fun prepare() { assertTrue(true) }
    @Test fun namedValue() { val expected = api.get(); val assertion = 0 }
    @Test fun helperNamedValue() {
        val prepare = api.get()
        val actual = prepare
    }
}'''}), ['helperNamedValue', 'namedValue'])

    def test_an_unrelated_class_helper_cannot_supply_an_assertion(self):
        self.assertEqual(self.offenders({KOTLIN + 'A.kt': '''
class A { fun prepare() { assertTrue(true) } }
class B { fun prepare() { api.get() }; @Test fun unchecked() { prepare() } }
'''}), ['unchecked'])

    def test_android_flavor_tests_are_checked(self):
        self.assertEqual(self.offenders({
            'chronicle/app/src/testOpen/java/x/A.kt': 'class A { @Test fun uncheckedFlavor() { api.get() } }',
        }), ['uncheckedFlavor'])

    def test_class_annotation_array_braces_do_not_hide_the_class_name(self):
        self.assertEqual(self.offenders({JAVA + 'A.java': '''
@Fixture({String.class}) public class A { @Test public void unchecked() { api.get(); } }
'''}), ['unchecked'])

    def test_generic_assertions_and_helpers_count_but_other_generic_calls_do_not(self):
        self.assertEqual(self.offenders({KOTLIN + 'A.kt': '''
class A {
    fun <T> prepare(value: T) { assertNotNull(value) }
    @Test fun property() { forAll<List<String>>(Arb.list(Arb.string())) { it == it } }
    @Test fun throws() { assertThrows<IllegalArgumentException> { api.get() } }
    @Test fun helper() { prepare<List<String>>(emptyList()) }
    @Test fun unchecked() { api.get<List<String>>() }
    @Test fun assertionNamedValue() { val assertThrows = api.get<String>() }
}'''}), ['assertionNamedValue', 'unchecked'])

    def test_top_level_helpers_follow_packages_imports_and_aliases(self):
        self.assertEqual(self.offenders({
            KOTLIN + 'Fixture.kt': '''package fixture
fun awaitValue() { assertTrue(true) }
fun quietValue() { api.get() }
private fun hiddenValue() { assertTrue(true) }
''',
            KOTLIN + 'Same.kt': '''package fixture
class Same { @Test fun samePackage() { awaitValue() } }
''',
            KOTLIN + 'A.kt': '''package checks
import fixture.awaitValue as awaitResult
import fixture.quietValue
import fixture.hiddenValue
class A {
    @Test fun imported() { awaitResult() }
    @Test fun quiet() { quietValue() }
    @Test fun hidden() { hiddenValue() }
    @Test fun missingImport() { awaitValue() }
}''',
            KOTLIN + 'Wildcard.kt': '''package wildcard
import fixture.*
class Wildcard { @Test fun wildcardImport() { awaitValue() } }
''',
        }), ['hidden', 'missingImport', 'quiet'])

    def test_kotlin_annotation_class_arrays_preserve_helper_class_boundaries(self):
        self.assertEqual(self.offenders({
            KOTLIN + 'Fixture.kt': '''
@RunWith(Runner::class)
@Label("é")
@Config(shadows = [Fixture.Fake::class, Fixture.Other::class])
abstract class Fixture {
    @Implements(Cipher::class) class Fake { fun encrypt() = Unit }
    @Implements(Keys::class) class Other { fun key() = Unit }
    protected fun prepare() { assertTrue(true) }
}
''',
            KOTLIN + 'A.kt': '''
class A : Fixture() { @Test fun inherited() { prepare() } }
class B { @Test fun unrelated() { prepare() } }
''',
        }), ['unrelated'])

    def test_every_jvm_test_in_the_repository_asserts_something(self):
        self.assertEqual(checker.offenders(checker.declarations(ROOT, checker.TEST_TREES)), [])


if __name__ == '__main__':
    unittest.main()
