// Sends the code through a Telegram bot. `to` is the chat id the user linked earlier. It's free,
// which makes it a decent fallback when SMS is down or too expensive.
export class TelegramProvider {
  constructor({ botToken, fetchImpl = fetch }) {
    this.botToken = botToken;
    this.fetchImpl = fetchImpl;
  }

  async send({ to, message }) {
    const response = await this.fetchImpl(`https://api.telegram.org/bot${this.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: to, text: message.text ?? String(message) }),
    });

    if (!response.ok) throw new Error(`Telegram error ${response.status}`);
    const body = await response.json();
    return { id: String(body.result?.message_id ?? '') };
  }
}
