import { expect, test } from 'vitest';
import { groupPathRegexes } from '../src/scripts/lib/path-regex';

test('required path literals never suppress a matching regex for optional and alternative forms', () => {
  const sources = ['/foo?', '/bar*', '/baz{0,2}', '/left|/right', '(?i)/mixed', '/escaped\\|literal',
    '^/start/[a-z]+$', '/prefix(?=end)', '/x\\d+', '/block-0/[a-z]+$', '/block-1/[a-z]+$'];
  const groups = groupPathRegexes(sources);
  expect(groups.flatMap(group => group.sources)).toEqual(sources);
  for (const group of groups) for (const source of group.sources) {
    const regex = new RegExp(source.replace(/^\(\?i\)/, ''), source.startsWith('(?i)') ? 'i' : '');
    const paths = ['', '/', '/fo', '/foo', '/bar', '/ba', '/baz', '/right', '/MIXED', '/escaped|literal',
      '/start/item', '/prefixend', '/x12', '/block-0/item', '/block-1/item', '/public/' + 'segment/'.repeat(1000)];
    for (const pathname of paths) if (regex.test(pathname)) expect(!group.required || pathname.includes(group.required), source).toBe(true);
  }
});

test('large contiguous literal regex sets have one shared necessary condition', () => {
  const sources = Array.from({ length: 256 }, (_, i) => '/blocked-' + i + '/[a-z]+$');
  const groups = groupPathRegexes(sources);
  expect(groups).toEqual([{ required: '/blocked-', sources }]);
});
