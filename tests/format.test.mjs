// Tests for src/static/js/app/format.js
//
// Dates are built with local-time constructors, so the expectations hold in any
// time zone. Run with: node tests/format.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'format.js');
const f = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const at = (...a) => new Date(...a).getTime();
const NOW = at(2026, 10, 20, 15, 0, 0);

console.log('\n--- toMs ---');
check('epoch seconds become ms', () => assert.equal(f.toMs(1790000000), 1790000000000));
check('epoch ms pass through', () => assert.equal(f.toMs(1790000000123), 1790000000123));
check('toMs accepts Python isoformat with microseconds', () =>
  assert.equal(f.toMs('2026-11-20T14:24:10.123456'), at(2026, 10, 20, 14, 24, 10, 123)));
check('a Date is accepted', () => assert.equal(f.toMs(new Date(NOW)), NOW));
check('garbage is NaN', () => { assert.ok(Number.isNaN(f.toMs('soon'))); assert.ok(Number.isNaN(f.toMs(null))); });

console.log('\n--- relativeTime ---');
check('under a minute', () => assert.equal(f.relativeTime(NOW - 30000, NOW), 'just now'));
check('minutes', () => assert.equal(f.relativeTime(NOW - 16 * 60000, NOW), '16 min ago'));
check('hours and minutes under 6h', () => assert.equal(f.relativeTime(NOW - 100 * 60000, NOW), '1h 40m ago'));
check('whole hours drop the minutes', () => assert.equal(f.relativeTime(NOW - 3 * 3600000, NOW), '3h ago'));
check('hours only past 6h', () => assert.equal(f.relativeTime(NOW - (8 * 60 + 20) * 60000, NOW), '8h ago'));
check('yesterday', () => assert.equal(f.relativeTime(NOW - 30 * 3600000, NOW), 'yesterday'));
check('days', () => assert.equal(f.relativeTime(NOW - 3 * 86400000, NOW), '3 days ago'));
check('older shows the date', () => assert.equal(f.relativeTime(at(2026, 10, 10, 9, 0), NOW), '10 Nov'));
check('a clock slightly ahead reads as just now', () => assert.equal(f.relativeTime(NOW + 5000, NOW), 'just now'));
check('relativeTime of garbage is empty', () => { assert.equal(f.relativeTime('soon', NOW), ''); assert.equal(f.relativeTime(undefined, NOW), ''); });
check('seconds input works too', () => assert.equal(f.relativeTime(NOW / 1000 - 120, NOW), '2 min ago'));

console.log('\n--- absolute, clock and day labels ---');
check('absoluteTime', () => assert.equal(f.absoluteTime(at(2026, 10, 20, 14, 24, 10)), '2026-11-20 14:24:10'));
check('absoluteTime of garbage is empty', () => assert.equal(f.absoluteTime('x'), ''));
check('clockTime today', () => assert.equal(f.clockTime(at(2026, 10, 20, 14, 31) / 1000, NOW), '14:31'));
check('clockTime another day', () => assert.equal(f.clockTime(at(2026, 10, 19, 8, 10), NOW), '19 Nov, 08:10'));
check('dayLabel today / yesterday / earlier / other year', () => {
  assert.equal(f.dayLabel(at(2026, 10, 20, 14, 24), NOW), 'Today, 14:24');
  assert.equal(f.dayLabel(at(2026, 10, 19, 18, 12), NOW), 'Yesterday, 18:12');
  assert.equal(f.dayLabel(at(2026, 10, 18, 9, 41), NOW), '18 Nov, 09:41');
  assert.equal(f.dayLabel(at(2025, 10, 12, 22, 3), NOW), '12 Nov 2025, 22:03');
});

console.log('\n--- backup names ---');
check('backupDate parses the name, with or without a counter', () => {
  assert.equal(f.backupDate('Caddyfile.20261120-142410').getTime(), at(2026, 10, 20, 14, 24, 10));
  assert.equal(f.backupDate('Caddyfile.20261120-142410-3').getTime(), at(2026, 10, 20, 14, 24, 10));
  assert.equal(f.backupDate('Caddyfile.weird'), null);
});
check('backupLabel', () => {
  assert.equal(f.backupLabel('Caddyfile.20261120-142410', NOW), 'Today, 14:24');
  assert.equal(f.backupLabel('Caddyfile.weird', NOW), 'weird');
});

console.log('\n--- countries and status text ---');
check('country names via Intl.DisplayNames', () => {
  assert.equal(f.countryName('GB'), 'United Kingdom');
  assert.equal(f.countryName('de'), 'Germany');
});
check('Cloudflare specials and fallbacks', () => {
  assert.equal(f.countryName('T1'), 'Tor network');
  assert.equal(f.countryName('XX'), 'Unknown country');
  assert.equal(f.countryName(''), '');
  assert.equal(f.countryName('1'), '1');
});
check('statusText', () => {
  assert.equal(f.statusText(504), 'Gateway timeout');
  assert.equal(f.statusText('404'), 'Not found');
  assert.equal(f.statusText(599), '');
});
check('durationNote only for 504', () => { assert.equal(f.durationNote(504), 'upstream timeout'); assert.equal(f.durationNote(502), ''); });

console.log('\n--- numbers ---');
check('formatBytes', () => {
  assert.equal(f.formatBytes(0), '0 B'); assert.equal(f.formatBytes(512), '512 B');
  assert.equal(f.formatBytes(1536), '1.5 KB'); assert.equal(f.formatBytes(31457280), '30.0 MB');
});
check('formatMs', () => {
  assert.equal(f.formatMs(141), '141 ms'); assert.equal(f.formatMs(2.5), '2.5 ms');
  assert.equal(f.formatMs(12400), '12.4 s'); assert.equal(f.formatMs(125000), '125 s');
  assert.equal(f.formatMs(null), '—');
});
check('formatCount', () => { assert.equal(f.formatCount(857), '857'); assert.equal(f.formatCount(1319), '1,319'); assert.equal(f.formatCount(48211), '48.2k'); });
check('formatPercent', () => { assert.equal(f.formatPercent(3.3333), '3.3%'); assert.equal(f.formatPercent(32.31, 0), '32%'); });
check('percentChange', () => {
  assert.equal(f.percentChange(112, 100), 12); assert.equal(f.percentChange(88, 100), -12);
  assert.equal(f.percentChange(5, 0), null); assert.equal(f.percentChange(5, null), null);
});
check('shortHost', () => assert.equal(f.shortHost('torrent.example.com'), 'torrent'));
check('shortDateTime is never relative', () => {
  assert.equal(f.shortDateTime(at(2026, 10, 20, 14, 24)), '20 Nov, 14:24');
  assert.equal(f.shortDateTime('nope'), '');
});

console.log(`\n${passed} passed`);
