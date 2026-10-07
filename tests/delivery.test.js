import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FailoverProvider,
  MemoryProvider,
  TwilioProvider,
  SendGridProvider,
  TelegramProvider,
  localizedSms,
  supportedLanguages,
} from '../src/index.js';

const okFetch = (log, body = {}) => async (url, init) => { log.push({ url, init }); return { ok: true, status: 200, json: async () => body, headers: new Map([['x-message-id', 'm1']]) }; };
const failFetch = async () => ({ ok: false, status: 500 });

test('twilio request shape', async () => {
  const log = [];
  const p = new TwilioProvider({
    accountSid: 'AC1',
    authToken: 'tok',
    from: '+15550001111',
    fetchImpl: okFetch(log, { sid: 'SM9' }),
  });
  assert.deepEqual(
    await p.send({ channel: 'sms', to: '+919876543210', message: { text: 'hi 123456' } }),
    { id: 'SM9' },
  );
  assert.equal(log[0].url, 'https://api.twilio.com/2010-04-01/Accounts/AC1/Messages.json');
  assert.equal(log[0].init.headers.authorization, `Basic ${Buffer.from('AC1:tok').toString('base64')}`);
  assert.equal(log[0].init.body.get('To'), '+919876543210');
  assert.equal(log[0].init.body.get('Body'), 'hi 123456');
  await assert.rejects(
    new TwilioProvider({ accountSid: 'a', authToken: 'b', from: 'c', fetchImpl: failFetch }).send({ channel: 'sms', to: 'x', message: { text: 't' } }),
    /Twilio error 500/,
  );
  await assert.rejects(p.send({ channel: 'email', to: 'x', message: {} }), /only sends sms/);
});
test('sendgrid request shape', async () => {
  const log = [];
  const p = new SendGridProvider({ apiKey: 'SG.x', from: 'no-reply@acme.io', fetchImpl: okFetch(log) });
  await p.send({ channel: 'email', to: 'a@b.com', message: { subject: 'S', text: 'T' } });
  const body = JSON.parse(log[0].init.body);
  assert.equal(body.personalizations[0].to[0].email, 'a@b.com');
  assert.equal(body.subject, 'S');
  assert.equal(log[0].init.headers.authorization, 'Bearer SG.x');
});
test('telegram request shape', async () => {
  const log = [];
  const p = new TelegramProvider({ botToken: 'B0T', fetchImpl: okFetch(log, { result: { message_id: 7 } }) });
  assert.deepEqual(await p.send({ to: '12345', message: { text: 'code 1' } }), { id: '7' });
  assert.equal(log[0].url, 'https://api.telegram.org/botB0T/sendMessage');
  assert.equal(JSON.parse(log[0].init.body).chat_id, '12345');
});

test('failover: falls through, circuit-breaks a dead provider, recovers after cooldown', async () => {
  const c = { t: 0 };
  const calls = { bad: 0 };
  class Bad { async send() { calls.bad++; throw new Error('down'); } }
  const good = new MemoryProvider();
  const f = new FailoverProvider([new Bad(), good], { maxFailures: 2, cooldownMs: 1000, clock: () => c.t });
  for (let i = 0; i < 5; i++) assert.equal((await f.send({ to: 'x' })).via, 'MemoryProvider');
  assert.equal(calls.bad, 2, 'bad provider skipped once its breaker opened');
  c.t = 1500;
  await f.send({ to: 'x' });
  assert.equal(calls.bad, 3);
  const allBad = new FailoverProvider([new Bad(), new Bad()]);
  await assert.rejects(allBad.send({}), /All providers failed/);
});

test('i18n messages', () => {
  assert.deepEqual(supportedLanguages(), ['en', 'hi', 'te', 'es', 'fr', 'de']);
  for (const lang of supportedLanguages()) { const m = localizedSms({ lang, brand: 'Acme', code: '482913', domain: 'acme.io' }); assert.ok(m.includes('482913') && m.includes('Acme')); assert.ok(m.endsWith('@acme.io #482913')); }
  assert.ok(localizedSms({ lang: 'te', brand: 'B', code: '111111' }).includes('ధృవీకరణ'));
  assert.equal(
    localizedSms({ lang: 'xx', brand: 'B', code: '111111' }),
    localizedSms({ lang: 'en', brand: 'B', code: '111111' }),
  );
  assert.equal(
    localizedSms({ lang: 'hi-IN', brand: 'B', code: '1' }),
    localizedSms({ lang: 'hi', brand: 'B', code: '1' }),
  );
});
