// Twilio Programmable SMS via REST (no SDK). Inject fetchImpl to test without network.
export class TwilioProvider {
  constructor({ accountSid, authToken, from, fetchImpl = fetch }) { Object.assign(this, { accountSid, authToken, from, fetchImpl }); }
  async send({ channel, to, message }) {
    if (channel !== 'sms') throw new Error('TwilioProvider only sends sms');
    const auth = Buffer.from(`${this.accountSid}:${this.authToken}`).toString('base64');
    const r = await this.fetchImpl(`https://api.twilio.com/2010-04-01/Accounts/${this.accountSid}/Messages.json`, {
      method: 'POST',
      headers: { authorization: `Basic ${auth}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ To: to, From: this.from, Body: message.text }),
    });
    if (!r.ok) throw new Error(`Twilio error ${r.status}`);
    return { id: (await r.json()).sid };
  }
}
