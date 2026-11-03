import { expect, test } from 'bun:test';
import { resolve } from 'node:path';

const extractor = resolve(import.meta.dir, 'endpoint-consumers.ts');
const fixture = (name: string) =>
  resolve(import.meta.dir, 'fixtures/endpoint-consumers', name, 'chronicle-web/src/modern/api.ts');

test('requests follow imported URL builders and their module constants', () => {
  const result = Bun.spawnSync([process.execPath, extractor, fixture('imported')]);
  expect(result.exitCode).toBe(0);
  expect(JSON.parse(result.stdout.toString())).toContainEqual({
    method: 'POST',
    path: '/chronicle/v3/study/{}/participant/{}/form-access-codes',
    callee: 'fetch',
  });
});

test('an unresolved executable request fails extraction', () => {
  const result = Bun.spawnSync([process.execPath, extractor, fixture('unresolved')]);
  expect(result.exitCode).not.toBe(0);
  expect(result.stderr.toString()).toContain('Unresolved request');
});

test('an entirely dynamic template cannot hide a request', () => {
  const result = Bun.spawnSync([process.execPath, extractor, fixture('unresolved-template')]);
  expect(result.exitCode).not.toBe(0);
  expect(result.stderr.toString()).toContain('Unresolved request');
});

test('the extractor keeps the selected test runtime when PATH cannot launch bun', () => {
  const result = Bun.spawnSync([process.execPath, extractor, fixture('imported')], {
    env: { ...process.env, PATH: '' },
  });
  expect(result.exitCode).toBe(0);
  expect(JSON.parse(result.stdout.toString())).toContainEqual({
    method: 'POST',
    path: '/chronicle/v3/study/{}/participant/{}/form-access-codes',
    callee: 'fetch',
  });
});

test('nested page wrappers resolve both fetcher and URL without counting an unrelated fetcher', () => {
  const result = Bun.spawnSync([process.execPath, extractor, fixture('forwarded-pagination')]);
  expect(result.exitCode).toBe(0);
  const requests = JSON.parse(result.stdout.toString()) as { method: string; path: string }[];
  expect(requests).toHaveLength(2);
  expect(requests.map(({ method, path }) => ({ method, path }))).toEqual(
    expect.arrayContaining([
      { method: 'GET', path: '/study/{}/participants/stats' },
      { method: 'GET', path: '/study/{}/participants/ios/upload-status' },
    ]),
  );
});

test('a network fetcher with an unresolved URL cannot disappear inside a wrapper', () => {
  const result = Bun.spawnSync([process.execPath, extractor, fixture('forwarded-unresolved')]);
  expect(result.exitCode).not.toBe(0);
  expect(result.stderr.toString()).toContain('Unresolved request');
});
