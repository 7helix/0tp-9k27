// A provider is anything with `async send({ channel, to, message })` that returns `{ id }`.
// To use Twilio, SES, SendGrid and so on, wrap their SDK in that shape.

// Keeps messages in memory. Handy in tests.
export class MemoryProvider {
  constructor() {
    this.sent = [];
  }

  async send(message) {
    this.sent.push(message);
    return { id: `mem-${this.sent.length}` };
  }

  last() {
    return this.sent[this.sent.length - 1];
  }
}

// Prints to the terminal. Development only, since it prints the code.
export class ConsoleProvider {
  async send({ channel, to, message }) {
    console.log(`\n[DEV ${channel.toUpperCase()} -> ${to}]\n${message.text ?? message}\n`);
    return { id: 'console' };
  }
}

// Posts the message as JSON to a gateway of your own.
export class WebhookProvider {
  constructor({ url, headers = {}, fetchImpl = fetch }) {
    this.url = url;
    this.headers = headers;
    this.fetchImpl = fetchImpl;
  }

  async send(message) {
    const response = await this.fetchImpl(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...this.headers },
      body: JSON.stringify(message),
    });
    if (!response.ok) throw new Error(`Delivery failed: ${response.status}`);
    return { id: response.headers.get('x-message-id') ?? 'webhook' };
  }
}

// a***@example.com, +91********10. Use it for logs and API responses.
export function maskDestination(to) {
  if (to.includes('@')) {
    const [user, domain] = to.split('@');
    return `${user[0]}***@${domain}`;
  }
  if (to.length <= 4) return '****';
  return `${to.slice(0, 3)}${'*'.repeat(to.length - 5)}${to.slice(-2)}`;
}
