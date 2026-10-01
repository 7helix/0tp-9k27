// Prometheus text-format counters (no dependency). Labels are escaped per the exposition format.
export class Metrics {
  constructor() { this.values = new Map(); this.help = new Map(); }
  inc(name, labels = {}, by = 1, help = '') {
    const key = `${name}\u0000${JSON.stringify(Object.entries(labels).sort())}`;
    this.values.set(key, (this.values.get(key) || 0) + by);
    if (help && !this.help.has(name)) this.help.set(name, help);
  }
  render() {
    const byName = new Map();
    for (const [key, v] of this.values) {
      const [name, l] = key.split('\u0000'); const labels = JSON.parse(l);
      const lbl = labels.length ? `{${labels.map(([k, val]) => `${k}="${String(val).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`).join(',')}}` : '';
      (byName.get(name) || byName.set(name, []).get(name)).push(`${name}${lbl} ${v}`);
    }
    return [...byName].map(([n, lines]) => `# HELP ${n} ${this.help.get(n) || n}\n# TYPE ${n} counter\n${lines.join('\n')}`).join('\n') + '\n';
  }
}
