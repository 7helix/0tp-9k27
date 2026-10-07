// SendGrid v3 "mail/send" through the REST API.
export class SendGridProvider {
  constructor({ apiKey, from, fetchImpl = fetch }) {
    this.apiKey = apiKey;
    this.from = from;
    this.fetchImpl = fetchImpl;
  }

  async send({ channel, to, message }) {
    if (channel !== 'email') throw new Error('SendGridProvider only sends email');

    const response = await this.fetchImpl('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.apiKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: this.from },
        subject: message.subject,
        content: [{ type: 'text/plain', value: message.text }],
      }),
    });

    if (!response.ok) throw new Error(`SendGrid error ${response.status}`);
    return { id: response.headers.get('x-message-id') ?? 'sendgrid' };
  }
}
