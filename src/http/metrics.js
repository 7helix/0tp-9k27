// Counters in the Prometheus text format, without a library.
export class Metrics {
  constructor() {
    this.values = new Map();
    this.help = new Map();
  }

  inc(name, labels = {}, by = 1, help = '') {
    const sortedLabels = Object.entries(labels).sort();
    const key = `${name}\u0000${JSON.stringify(sortedLabels)}`;
    this.values.set(key, (this.values.get(key) || 0) + by);
    if (help && !this.help.has(name)) this.help.set(name, help);
  }

  render() {
    const byName = new Map();

    for (const [key, value] of this.values) {
      const [name, labelJson] = key.split('\u0000');
      const labels = JSON.parse(labelJson);
      const text = labels.map(([k, v]) => `${k}="${escapeLabel(v)}"`).join(',');

      if (!byName.has(name)) byName.set(name, []);
      byName.get(name).push(`${name}${labels.length ? `{${text}}` : ''} ${value}`);
    }

    const blocks = [...byName].map(([name, lines]) => {
      const help = this.help.get(name) || name;
      return `# HELP ${name} ${help}\n# TYPE ${name} counter\n${lines.join('\n')}`;
    });
    return blocks.join('\n') + '\n';
  }
}

function escapeLabel(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}
