// Twilio SMS through the REST API, no SDK. Pass fetchImpl to test without a network.
export class TwilioProvider {
  constructor({ accountSid, authToken, from, fetchImpl = fetch }) {
    this.accountSid = accountSid;
    this.authToken = authToken;
    this.from = from;
    this.fetchImpl = fetchImpl;
  }

  async send({ channel, to, message }) {
    if (channel !== 'sms') throw new Error('TwilioProvider only sends sms');

    const credentials = Buffer.from(`${this.accountSid}:${this.authToken}`).toString('base64');
    const response = await this.fetchImpl(
      `https://api.twilio.com/2010-04-01/Accounts/${this.accountSid}/Messages.json`,
      {
        method: 'POST',
        headers: {
          authorization: `Basic ${credentials}`,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ To: to, From: this.from, Body: message.text }),
      },
    );

    if (!response.ok) throw new Error(`Twilio error ${response.status}`);
    return { id: (await response.json()).sid };
  }
}
