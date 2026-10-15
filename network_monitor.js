
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { performance } = require('node:perf_hooks');

const VERSION = '2.1.0';

const FIELDS = Object.freeze({
    rxBytes: 'rx_bytes',
    txBytes: 'tx_bytes',
    rxPackets: 'rx_packets',
    txPackets: 'tx_packets',
    rxErrors: 'rx_errors',
    txErrors: 'tx_errors',
    rxDropped: 'rx_dropped',
    txDropped: 'tx_dropped'
});

const FIELD_NAMES = Object.keys(FIELDS);

function validateInterface(name) {
    if (
        typeof name !== 'string' ||
        Buffer.byteLength(name) < 1 ||
        Buffer.byteLength(name) > 15 ||
        !/^[A-Za-z0-9_.:-]+$/.test(name) ||
        name === '.' ||
        name === '..'
    ) {
        throw new Error(`Invalid network interface: ${name}`);
    }

    return name;
}

function integer(value, name, minimum = 0) {
    const text = String(value);

    if (!/^\d+$/.test(text)) {
        throw new Error(`${name} must be an integer`);
    }

    const result = Number(text);

    if (!Number.isSafeInteger(result) || result < minimum) {
        throw new Error(`${name} must be at least ${minimum}`);
    }

    return result;
}

function decimal(value, name, minimum = 0) {
    const text = String(value);

    if (!/^(?:\d+)(?:\.\d+)?$/.test(text)) {
        throw new Error(`${name} must be a nonnegative number`);
    }

    const result = Number(text);

    if (!Number.isFinite(result) || result < minimum) {
        throw new Error(`${name} must be at least ${minimum}`);
    }

    return result;
}

function zeros() {
    return Object.fromEntries(FIELD_NAMES.map(key => [key, 0n]));
}

function serialize(value) {
    return JSON.stringify(value, (_, item) => {
        return typeof item === 'bigint' ? item.toString() : item;
    });
}

function formatBytes(value) {
    let number = Number(value);

    if (!Number.isFinite(number) || number < 0) {
        return 'N/A';
    }

    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
    let index = 0;

    while (number >= 1024 && index < units.length - 1) {
        number /= 1024;
        index++;
    }

    return `${number.toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

function formatRate(value) {
    return `${formatBytes(value)}/s`;
}

function calculateDelta(previous, current) {
    const delta = zeros();
    const resets = [];

    for (const key of FIELD_NAMES) {
        if (current[key] < previous[key]) {
            resets.push(key);
        } else {
            delta[key] = current[key] - previous[key];
        }
    }

    return { delta, resets };
}

function mean(values) {
    if (!values.length) {
        return 0;
    }

    return values.reduce((total, value) => total + value, 0) / values.length;
}

function finiteNumber(value) {
    return Number.isFinite(value) ? value : null;
}

class InterfaceMonitor {
    constructor(name, options) {
        this.name = validateInterface(name);
        this.options = options;
        this.base = path.join('/sys/class/net', this.name);
        this.previous = null;
        this.previousTime = null;
        this.lastCounters = null;
        this.totals = zeros();
        this.sampleCount = 0;
        this.resetCount = 0;
        this.errorCount = 0;
        this.consecutiveFailures = 0;
        this.history = [];
        this.lastRates = null;
        this.peaks = {
            rxBytesPerSecond: 0,
            txBytesPerSecond: 0,
            rxPacketsPerSecond: 0,
            txPacketsPerSecond: 0
        };
        this.measuredSeconds = 0;
        this.lastAlertTime = new Map();
        this.alertCount = 0;
    }

    async exists() {
        try {
            const result = await fs.stat(this.base);
            return result.isDirectory();
        } catch {
            return false;
        }
    }

    async readCounters() {
        const values = await Promise.all(
            FIELD_NAMES.map(async key => {
                const filename = path.join(
                    this.base,
                    'statistics',
                    FIELDS[key]
                );

                const content = (
                    await fs.readFile(filename, 'utf8')
                ).trim();

                if (!/^\d+$/.test(content)) {
                    throw new Error(
                        `Invalid ${FIELDS[key]} counter on ${this.name}`
                    );
                }

                return BigInt(content);
            })
        );

        const result = {};

        FIELD_NAMES.forEach((key, index) => {
            result[key] = values[index];
        });

        return result;
    }

    async readMetadata() {
        const result = { interface: this.name };

        for (const field of ['operstate', 'mtu', 'speed', 'address']) {
            try {
                result[field] = (
                    await fs.readFile(path.join(this.base, field), 'utf8')
                ).trim();
            } catch {
                result[field] = null;
            }
        }

        return result;
    }

    async establishBaseline() {
        const counters = await this.readCounters();

        this.previous = counters;
        this.previousTime = performance.now();
        this.lastCounters = counters;
        this.consecutiveFailures = 0;
    }

    rollingRates() {
        const keys = Object.keys(this.peaks);
        const result = {};

        for (const key of keys) {
            result[key] = mean(this.history.map(item => item[key]));
        }

        return result;
    }

    createAlert(type, value, threshold) {
        const now = Date.now();
        const last = this.lastAlertTime.get(type) ?? -Infinity;

        if (now - last < this.options.cooldown) {
            return null;
        }

        this.lastAlertTime.set(type, now);
        this.alertCount++;

        return {
            timestamp: new Date(now).toISOString(),
            interface: this.name,
            type,
            value: typeof value === 'bigint' ? value.toString() : value,
            threshold: typeof threshold === 'bigint'
                ? threshold.toString()
                : threshold
        };
    }

    checkAlerts(rates, delta, elapsed) {
        const alerts = [];

        const checks = [
            [
                'HIGH_RX_TRAFFIC',
                rates.rxBytesPerSecond,
                this.options.thresholdBytes
            ],
            [
                'HIGH_TX_TRAFFIC',
                rates.txBytesPerSecond,
                this.options.thresholdBytes
            ],
            [
                'HIGH_RX_ERRORS',
                Number(delta.rxErrors) / elapsed,
                this.options.errorThreshold
            ],
            [
                'HIGH_TX_ERRORS',
                Number(delta.txErrors) / elapsed,
                this.options.errorThreshold
            ],
            [
                'HIGH_RX_DROPPED',
                Number(delta.rxDropped) / elapsed,
                this.options.dropThreshold
            ],
            [
                'HIGH_TX_DROPPED',
                Number(delta.txDropped) / elapsed,
                this.options.dropThreshold
            ]
        ];

        for (const [type, value, threshold] of checks) {
            if (value > threshold) {
                const alert = this.createAlert(type, value, threshold);

                if (alert) {
                    alerts.push(alert);
                }
            }
        }

        return alerts;
    }

    async sample() {
        const counters = await this.readCounters();
        const now = performance.now();

        if (!this.previous || this.previousTime === null) {
            this.previous = counters;
            this.previousTime = now;
            this.lastCounters = counters;
            return null;
        }

        const elapsed = (now - this.previousTime) / 1000;
        const result = calculateDelta(this.previous, counters);

        this.previous = counters;
        this.previousTime = now;
        this.lastCounters = counters;
        this.consecutiveFailures = 0;

        if (result.resets.length > 0) {
            this.resetCount++;

            return {
                type: 'reset',
                timestamp: new Date().toISOString(),
                interface: this.name,
                counters: result.resets
            };
        }

        if (elapsed <= 0) {
            return null;
        }

        for (const key of FIELD_NAMES) {
            this.totals[key] += result.delta[key];
        }

        this.measuredSeconds += elapsed;
        this.sampleCount++;

        const rates = {
            rxBytesPerSecond: Number(result.delta.rxBytes) / elapsed,
            txBytesPerSecond: Number(result.delta.txBytes) / elapsed,
            rxPacketsPerSecond: Number(result.delta.rxPackets) / elapsed,
            txPacketsPerSecond: Number(result.delta.txPackets) / elapsed
        };

        for (const key of Object.keys(this.peaks)) {
            this.peaks[key] = Math.max(this.peaks[key], rates[key]);
        }

        this.lastRates = rates;
        this.history.push(rates);

        if (this.history.length > this.options.historySize) {
            this.history.shift();
        }

        return {
            type: 'sample',
            timestamp: new Date().toISOString(),
            interface: this.name,
            elapsedSeconds: elapsed,
            delta: result.delta,
            rates,
            rollingRates: this.rollingRates(),
            alerts: this.checkAlerts(rates, result.delta, elapsed)
        };
    }

    summary() {
        const totals = this.totals;
        const totalBytes = totals.rxBytes + totals.txBytes;
        const totalPackets = totals.rxPackets + totals.txPackets;
        const totalErrors = totals.rxErrors + totals.txErrors;

        return {
            interface: this.name,
            samples: this.sampleCount,
            resets: this.resetCount,
            errors: this.errorCount,
            alerts: this.alertCount,
            measuredSeconds: this.measuredSeconds,
            totals,
            lastCounters: this.lastCounters,
            averageRates: {
                rxBytesPerSecond: this.measuredSeconds > 0
                    ? finiteNumber(Number(totals.rxBytes) / this.measuredSeconds)
                    : 0,
                txBytesPerSecond: this.measuredSeconds > 0
                    ? finiteNumber(Number(totals.txBytes) / this.measuredSeconds)
                    : 0
            },
            lastRates: this.lastRates,
            rollingRates: this.rollingRates(),
            peakRates: this.peaks,
            averagePacketSize: totalPackets > 0n
                ? finiteNumber(Number(totalBytes) / Number(totalPackets))
                : null,
            errorRatePercent: totalPackets > 0n
                ? finiteNumber(Number(totalErrors) / Number(totalPackets) * 100)
                : null
        };
    }
}

class NetworkMonitor extends EventEmitter {
    constructor(interfaceNames, options = {}) {
        super();

        this.options = {
            duration: options.duration ?? 0,
            interval: options.interval ?? 1000,
            thresholdBytes: options.thresholdBytes ?? 50 * 1024 * 1024,
            errorThreshold: options.errorThreshold ?? 1000,
            dropThreshold: options.dropThreshold ?? 100,
            cooldown: options.cooldown ?? 5000,
            historySize: options.historySize ?? 60,
            maxFailures: options.maxFailures ?? 5
        };

        if (!Array.isArray(interfaceNames) || !interfaceNames.length) {
            throw new Error('At least one interface is required');
        }

        this.interfaces = [...new Set(interfaceNames)].map(
            name => new InterfaceMonitor(name, this.options)
        );

        this.state = 'stopped';
        this.startedAt = null;
        this.stoppedAt = null;
        this.activeSince = null;
        this.activeMilliseconds = 0;
        this.timer = null;
        this.durationTimer = null;
        this.pending = null;
        this.stopPromise = null;
        this.alertCount = 0;
        this.errorCount = 0;
    }

    async start() {
        if (this.state !== 'stopped' || this.startedAt !== null) {
            throw new Error('Monitor has already been started');
        }

        for (const iface of this.interfaces) {
            if (!await iface.exists()) {
                throw new Error(`Interface does not exist: ${iface.name}`);
            }

            await iface.establishBaseline();
        }

        this.startedAt = new Date().toISOString();
        this.activeSince = performance.now();
        this.state = 'running';

        this.emit('started', {
            interfaces: this.interfaces.map(item => item.name),
            options: this.options
        });

        this.schedule();

        if (this.options.duration > 0) {
            this.durationTimer = setTimeout(() => {
                this.stop().catch(error => this.emit('monitorError', error));
            }, this.options.duration * 1000);
        }
    }

    schedule() {
        if (this.state !== 'running') {
            return;
        }

        this.timer = setTimeout(() => {
            this.timer = null;

            if (this.state !== 'running') {
                return;
            }

            const pending = this.sampleAll();
            this.pending = pending;

            pending
                .catch(error => this.emit('monitorError', error))
                .finally(() => {
                    if (this.pending === pending) {
                        this.pending = null;
                    }

                    if (this.state === 'running') {
                        this.schedule();
                    }
                });
        }, this.options.interval);
    }

    async sampleAll() {
        const results = await Promise.allSettled(
            this.interfaces.map(iface => iface.sample())
        );

        for (let i = 0; i < results.length; i++) {
            const iface = this.interfaces[i];
            const result = results[i];

            if (result.status === 'rejected') {
                iface.errorCount++;
                iface.consecutiveFailures++;
                this.errorCount++;

                this.emit('monitorError', {
                    interface: iface.name,
                    message: result.reason?.message ?? String(result.reason),
                    failures: iface.consecutiveFailures
                });

                if (iface.consecutiveFailures >= this.options.maxFailures) {
                    this.emit('monitorError', {
                        interface: iface.name,
                        message: 'Maximum consecutive failures reached'
                    });

                    queueMicrotask(() => {
                        this.stop().catch(error => {
                            this.emit('monitorError', error);
                        });
                    });
                } else {
                    try {
                        await iface.establishBaseline();
                    } catch {
                        iface.previous = null;
                        iface.previousTime = null;
                    }
                }

                continue;
            }

            const data = result.value;

            if (!data) {
                continue;
            }

            if (data.type === 'reset') {
                this.emit('reset', data);
                continue;
            }

            this.emit('sample', data);

            for (const alert of data.alerts) {
                this.alertCount++;
                this.emit('alert', alert);
            }
        }
    }

    pause() {
        if (this.state !== 'running') {
            return;
        }

        this.activeMilliseconds += performance.now() - this.activeSince;
        this.activeSince = null;
        this.state = 'paused';

        if (this.timer !== null) {
            clearTimeout(this.timer);
            this.timer = null;
        }

        this.emit('paused');
    }

    async resume() {
        if (this.state !== 'paused') {
            return;
        }

        if (this.pending) {
            await this.pending;
        }

        for (const iface of this.interfaces) {
            await iface.establishBaseline();
        }

        this.activeSince = performance.now();
        this.state = 'running';
        this.emit('resumed');
        this.schedule();
    }

    elapsedSeconds() {
        let milliseconds = this.activeMilliseconds;

        if (this.activeSince !== null) {
            milliseconds += performance.now() - this.activeSince;
        }

        return milliseconds / 1000;
    }

    async stop() {
        if (this.stopPromise) {
            return this.stopPromise;
        }

        if (this.state === 'stopped') {
            return this.summary();
        }

        this.stopPromise = this.finishStop();
        return this.stopPromise;
    }

    async finishStop() {
        if (this.activeSince !== null) {
            this.activeMilliseconds += performance.now() - this.activeSince;
            this.activeSince = null;
        }

        this.state = 'stopped';

        if (this.timer !== null) {
            clearTimeout(this.timer);
            this.timer = null;
        }

        if (this.durationTimer !== null) {
            clearTimeout(this.durationTimer);
            this.durationTimer = null;
        }

        if (this.pending) {
            await this.pending;
        }

        this.stoppedAt = new Date().toISOString();

        const result = this.summary();
        this.emit('stopped', result);

        return result;
    }

    summary() {
        return {
            version: VERSION,
            state: this.state,
            startedAt: this.startedAt,
            stoppedAt: this.stoppedAt,
            activeSeconds: this.elapsedSeconds(),
            alerts: this.alertCount,
            errors: this.errorCount,
            interfaces: this.interfaces.map(iface => iface.summary())
        };
    }
}

class ConsoleRenderer {
    started(data) {
        console.log(`RXTX Monitor v${VERSION}`);
        console.log(`Interfaces: ${data.interfaces.join(', ')}`);
        console.log(`Sampling interval: ${data.options.interval} ms`);
        console.log(
            `Traffic threshold: ${formatRate(data.options.thresholdBytes)}`
        );
        console.log('Press Ctrl+C to stop');
        console.log('');
    }

    sample(data) {
        const time = data.timestamp.replace('T', ' ').slice(0, 19);

        console.log(`[${time}] ${data.interface}`);
        console.log(
            `  RX  ${formatRate(data.rates.rxBytesPerSecond).padStart(15)}  ` +
            `${data.rates.rxPacketsPerSecond.toFixed(1)} packets/s`
        );
        console.log(
            `  TX  ${formatRate(data.rates.txBytesPerSecond).padStart(15)}  ` +
            `${data.rates.txPacketsPerSecond.toFixed(1)} packets/s`
        );
        console.log(
            `  Rolling RX: ${formatRate(data.rollingRates.rxBytesPerSecond)}`
        );
        console.log(
            `  Rolling TX: ${formatRate(data.rollingRates.txBytesPerSecond)}`
        );

        if (data.delta.rxErrors > 0n || data.delta.txErrors > 0n) {
            console.log(
                `  Errors: RX=${data.delta.rxErrors} TX=${data.delta.txErrors}`
            );
        }

        if (data.delta.rxDropped > 0n || data.delta.txDropped > 0n) {
            console.log(
                `  Dropped: RX=${data.delta.rxDropped} TX=${data.delta.txDropped}`
            );
        }

        console.log('');
    }

    alert(data) {
        console.log(
            `ALERT ${data.interface}: ${data.type} ` +
            `value=${data.value} threshold=${data.threshold}`
        );
    }

    reset(data) {
        console.log(
            `Counter reset on ${data.interface}: ${data.counters.join(', ')}`
        );
    }

    error(data) {
        console.error(
            `Monitor error: ${data.interface ?? 'general'}: ` +
            `${data.message ?? String(data)}`
        );
    }

    summary(data) {
        console.log('');
        console.log('='.repeat(64));
        console.log('RXTX MONITOR SUMMARY');
        console.log('='.repeat(64));
        console.log(`Active duration: ${data.activeSeconds.toFixed(2)} seconds`);
        console.log(`Alerts: ${data.alerts}`);
        console.log(`Errors: ${data.errors}`);

        for (const iface of data.interfaces) {
            console.log('');
            console.log(`Interface: ${iface.interface}`);
            console.log(`Samples: ${iface.samples}`);
            console.log(`Counter resets: ${iface.resets}`);
            console.log(`RX total: ${formatBytes(iface.totals.rxBytes)}`);
            console.log(`TX total: ${formatBytes(iface.totals.txBytes)}`);
            console.log(
                `RX average: ${formatRate(iface.averageRates.rxBytesPerSecond)}`
            );
            console.log(
                `TX average: ${formatRate(iface.averageRates.txBytesPerSecond)}`
            );
            console.log(
                `RX peak: ${formatRate(iface.peakRates.rxBytesPerSecond)}`
            );
            console.log(
                `TX peak: ${formatRate(iface.peakRates.txBytesPerSecond)}`
            );
            console.log(`RX packets: ${iface.totals.rxPackets}`);
            console.log(`TX packets: ${iface.totals.txPackets}`);
            console.log(
                `Errors: RX=${iface.totals.rxErrors} TX=${iface.totals.txErrors}`
            );
            console.log(
                `Dropped: RX=${iface.totals.rxDropped} TX=${iface.totals.txDropped}`
            );

            if (iface.averagePacketSize !== null) {
                console.log(
                    `Average packet size: ${iface.averagePacketSize.toFixed(1)} B`
                );
            }
        }

        console.log('='.repeat(64));
    }
}

async function listInterfaces() {
    const names = await fs.readdir('/sys/class/net');
    const results = [];

    for (const name of names.sort()) {
        const iface = new InterfaceMonitor(name, {});
        results.push(await iface.readMetadata());
    }

    return results;
}

function parseArgs(argv) {
    const options = {
        interfaces: [],
        duration: 0,
        interval: 1000,
        thresholdBytes: 50 * 1024 * 1024,
        errorThreshold: 1000,
        dropThreshold: 100,
        cooldown: 5000,
        historySize: 60,
        maxFailures: 5,
        json: false,
        ndjson: false,
        list: false,
        help: false,
        version: false
    };

    const numericOptions = {
        '--interval': ['interval', 100],
        '--errors': ['errorThreshold', 0],
        '--drops': ['dropThreshold', 0],
        '--cooldown': ['cooldown', 0],
        '--history': ['historySize', 1],
        '--max-failures': ['maxFailures', 1]
    };

    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];

        if (arg === '--help' || arg === '-h') {
            options.help = true;
        } else if (arg === '--version') {
            options.version = true;
        } else if (arg === '--list' || arg === '-l') {
            options.list = true;
        } else if (arg === '--json') {
            options.json = true;
        } else if (arg === '--ndjson') {
            options.ndjson = true;
        } else if (arg === '--threshold') {
            if (++i >= argv.length) {
                throw new Error('Missing threshold value');
            }

            options.thresholdBytes = decimal(
                argv[i],
                'Traffic threshold'
            ) * 1024 * 1024;
        } else if (Object.hasOwn(numericOptions, arg)) {
            if (++i >= argv.length) {
                throw new Error(`Missing value for ${arg}`);
            }

            const [key, minimum] = numericOptions[arg];
            options[key] = integer(argv[i], arg, minimum);
        } else if (arg.startsWith('-')) {
            throw new Error(`Unknown option: ${arg}`);
        } else if (options.interfaces.length === 0) {
            options.interfaces = arg.split(',').map(validateInterface);
        } else if (/^\d+$/.test(arg) && options.duration === 0) {
            options.duration = integer(arg, 'Duration');
        } else {
            throw new Error(`Unexpected argument: ${arg}`);
        }
    }

    if (options.json && options.ndjson) {
        throw new Error('Choose either --json or --ndjson');
    }

    if (
        !options.help &&
        !options.version &&
        !options.list &&
        options.interfaces.length === 0
    ) {
        throw new Error('No network interfaces specified');
    }

    options.interfaces = [...new Set(options.interfaces)];

    return options;
}

function printHelp() {
    console.log(`RXTX Monitor v${VERSION}`);
    console.log('');
    console.log('Usage: node main.js <interface[,interface...]> [seconds] [options]');
    console.log('');
    console.log('Options:');
    console.log('  --list               List network interfaces');
    console.log('  --interval N         Sampling interval in milliseconds');
    console.log('  --threshold N        Traffic threshold in MiB/s');
    console.log('  --errors N           Error threshold per second');
    console.log('  --drops N            Drop threshold per second');
    console.log('  --cooldown N         Alert cooldown in milliseconds');
    console.log('  --history N          Rolling average sample count');
    console.log('  --max-failures N     Maximum consecutive read failures');
    console.log('  --json               Final JSON summary');
    console.log('  --ndjson             Streaming NDJSON events');
    console.log('  --version            Show version');
    console.log('  --help               Show help');
    console.log('');
    console.log('Examples:');
    console.log('  node main.js --list');
    console.log('  node main.js lo 10');
    console.log('  node main.js eth0 60 --interval 500');
    console.log('  node main.js eth0,lo 30 --threshold 10');
    console.log('  node main.js lo 10 --json');
}

async function main() {
    const options = parseArgs(process.argv.slice(2));

    if (options.help) {
        printHelp();
        return;
    }

    if (options.version) {
        console.log(VERSION);
        return;
    }

    if (options.list) {
        const interfaces = await listInterfaces();

        for (const iface of interfaces) {
            console.log(
                `${iface.interface.padEnd(16)} ` +
                `state=${iface.operstate ?? 'unknown'} ` +
                `mtu=${iface.mtu ?? 'unknown'} ` +
                `speed=${iface.speed ?? 'unknown'}`
            );
        }

        return;
    }

    const monitor = new NetworkMonitor(options.interfaces, options);
    const renderer = new ConsoleRenderer();

    function output(type, data) {
        if (options.ndjson) {
            process.stdout.write(serialize({ type, data }) + '\n');
            return;
        }

        if (options.json) {
            return;
        }

        if (type === 'started') {
            renderer.started(data);
        } else if (type === 'sample') {
            renderer.sample(data);
        } else if (type === 'alert') {
            renderer.alert(data);
        } else if (type === 'reset') {
            renderer.reset(data);
        } else if (type === 'error') {
            renderer.error(data);
        } else if (type === 'stopped') {
            renderer.summary(data);
        }
    }

    monitor.on('started', data => output('started', data));
    monitor.on('sample', data => output('sample', data));
    monitor.on('alert', data => output('alert', data));
    monitor.on('reset', data => output('reset', data));
    monitor.on('monitorError', data => output('error', data));

    monitor.on('stopped', data => {
        if (options.json) {
            console.log(serialize(data));
        } else {
            output('stopped', data);
        }
    });

    let shuttingDown = false;

    async function shutdown() {
        if (shuttingDown) {
            return;
        }

        shuttingDown = true;

        try {
            await monitor.stop();
        } catch (error) {
            console.error(error.message);
            process.exitCode = 1;
        }
    }

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    await monitor.start();
}

if (require.main === module) {
    main().catch(error => {
        console.error(`Error: ${error.message}`);
        process.exitCode = 1;
    });
}

module.exports = {
    InterfaceMonitor,
    NetworkMonitor,
    ConsoleRenderer,
    parseArgs,
    calculateDelta,
    formatBytes
};
