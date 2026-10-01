// SendGrid v3 mail/send via REST.
export class SendGridProvider {
  constructor({ apiKey, from, fetchImpl = fetch }) { Object.assign(this, { apiKey, from, fetchImpl }); }
  async send({ channel, to, message }) {
    if (channel !== 'email') throw new Error('SendGridProvider only sends email');
    const r = await this.fetchImpl('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: { authorization: `Bearer ${this.apiKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }], from: { email: this.from },
        subject: message.subject, content: [{ type: 'text/plain', value: message.text }],
      }),
    });
    if (!r.ok) throw new Error(`SendGrid error ${r.status}`);
    return { id: r.headers.get('x-message-id') ?? 'sendgrid' };
  }
}
