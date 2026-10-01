// Telegram bot delivery (`to` = chat_id the user linked earlier). Free channel, good SMS fallback.
export class TelegramProvider {
  constructor({ botToken, fetchImpl = fetch }) { Object.assign(this, { botToken, fetchImpl }); }
  async send({ to, message }) {
    const r = await this.fetchImpl(`https://api.telegram.org/bot${this.botToken}/sendMessage`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: to, text: message.text ?? String(message) }),
    });
    if (!r.ok) throw new Error(`Telegram error ${r.status}`);
    return { id: String((await r.json()).result?.message_id ?? '') };
  }
}
