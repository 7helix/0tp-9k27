// A provider is any object with: async send({ channel, to, message }) -> { id }
// Plug in Twilio, SES, SendGrid, ... by wrapping their SDK in this shape.

/** Captures messages in memory - perfect for tests. */
export class MemoryProvider {
  constructor() { this.sent = []; }
  async send(msg) { this.sent.push(msg); return { id: `mem-${this.sent.length}` }; }
  last() { return this.sent[this.sent.length - 1]; }
}

/** Prints to the terminal - development only (it prints the code!). */
export class ConsoleProvider {
  async send({ channel, to, message }) {
    console.log(`\n[DEV ${channel.toUpperCase()} -> ${to}]\n${message.text ?? message}\n`);
    return { id: 'console' };
  }
}

/** POSTs JSON to your own gateway. */
export class WebhookProvider {
  constructor({ url, headers = {}, fetchImpl = fetch }) { Object.assign(this, { url, headers, fetchImpl }); }
  async send(msg) {
    const r = await this.fetchImpl(this.url, { method: 'POST', headers: { 'content-type': 'application/json', ...this.headers }, body: JSON.stringify(msg) });
    if (!r.ok) throw new Error(`Delivery failed: ${r.status}`);
    return { id: r.headers.get('x-message-id') ?? 'webhook' };
  }
}

/** Mask destinations in logs/API responses: a***@example.com, +91******21 */
export function maskDestination(to) {
  if (to.includes('@')) { const [u, d] = to.split('@'); return `${u[0]}***@${d}`; }
  return to.length <= 4 ? '****' : `${to.slice(0, 3)}${'*'.repeat(to.length - 5)}${to.slice(-2)}`;
}
