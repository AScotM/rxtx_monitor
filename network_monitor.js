const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

class NetworkMonitor extends EventEmitter {
    constructor(interfaceName, options = {}) {
        super();
        this.interface = this.sanitizeInterfaceName(interfaceName);
        this.duration = Math.max(0, Number(options.duration || 0));
        this.highTrafficThreshold = BigInt(options.highTrafficThreshold ?? 50 * 1024 * 1024);
        this.errorThreshold = BigInt(options.errorThreshold ?? 1000);
        this.dropThreshold = BigInt(options.dropThreshold ?? 100);
        this.sampleInterval = Math.max(100, Number(options.sampleInterval || 1000));
        this.alertCooldown = Math.max(100, Number(options.alertCooldown || 5000));
        this.alertHistorySize = Math.max(1, Number(options.alertHistorySize || 100));
        this.maxFileSize = Math.max(1024, Number(options.maxFileSize || 16384));
        this.state = 'stopped';
        this.startTime = 0;
        this.endTime = 0;
        this.prevStats = null;
        this.initialStats = null;
        this.lastStats = null;
        this.alerts = [];
        this.sampleCount = 0;
        this.monitorInterval = null;
        this.durationTimeout = null;
        this.currentSamplePromise = null;
        this.lastAlertTimestamps = new Map();
    }

    sanitizeInterfaceName(name) {
        if (!name || typeof name !== 'string') {
            throw new Error('Interface name must be a non-empty string');
        }

        const cleanName = name.trim();
        if (cleanName.length === 0 || cleanName.length > 64) {
            throw new Error('Interface name must be between 1 and 64 characters');
        }

        if (cleanName.includes('/') || cleanName.includes('..')) {
            throw new Error('Interface name cannot contain path characters');
        }

        if (!/^[a-z0-9]+[a-z0-9\-_:.]*$/i.test(cleanName)) {
            throw new Error('Interface name must start with alphanumeric and contain only letters, numbers, hyphens, underscores, colons, or dots');
        }

        return cleanName;
    }

    getInterfaceBasePath() {
        return path.posix.join('/sys/class/net', this.interface);
    }

    getStatisticsBasePath() {
        return path.posix.join(this.getInterfaceBasePath(), 'statistics');
    }

    validateInterfacePath(filePath) {
        try {
            const normalizedPath = path.posix.normalize(filePath).replace(/\/+/g, '/');
            const expectedPath = this.getInterfaceBasePath();

            if (normalizedPath !== expectedPath) {
                return { valid: false, reason: 'Invalid interface path' };
            }

            const rel = path.posix.relative('/sys/class/net', normalizedPath);
            if (!rel || rel.startsWith('..') || path.posix.isAbsolute(rel)) {
                return { valid: false, reason: 'Path escapes /sys/class/net' };
            }

            const parts = rel.split('/').filter(Boolean);
            if (parts.length !== 1) {
                return { valid: false, reason: 'Interface path depth invalid' };
            }

            try {
                this.sanitizeInterfaceName(parts[0]);
            } catch (error) {
                return { valid: false, reason: error.message };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, reason: `Validation error: ${error.message}` };
        }
    }

    validateStatisticsPath(filePath) {
        try {
            const normalizedPath = path.posix.normalize(filePath).replace(/\/+/g, '/');
            const expectedBase = this.getStatisticsBasePath();

            if (!normalizedPath.startsWith(expectedBase + '/')) {
                return { valid: false, reason: 'Path must be within interface statistics directory' };
            }

            const rel = path.posix.relative(expectedBase, normalizedPath);
            if (!rel || rel.startsWith('..') || path.posix.isAbsolute(rel)) {
                return { valid: false, reason: 'Path escapes statistics directory' };
            }

            const parts = rel.split('/').filter(Boolean);
            if (parts.length !== 1) {
                return { valid: false, reason: 'Statistics path depth invalid' };
            }

            const allowedFiles = new Set([
                'tx_bytes',
                'rx_bytes',
                'tx_packets',
                'rx_packets',
                'tx_errors',
                'rx_errors',
                'tx_dropped',
                'rx_dropped'
            ]);

            if (!allowedFiles.has(parts[0])) {
                return { valid: false, reason: `File ${parts[0]} not allowed in statistics directory` };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, reason: `Validation error: ${error.message}` };
        }
    }

    resetRuntimeState() {
        this.startTime = Date.now();
        this.endTime = 0;
        this.prevStats = null;
        this.initialStats = null;
        this.lastStats = null;
        this.alerts = [];
        this.sampleCount = 0;
        this.currentSamplePromise = null;
        this.lastAlertTimestamps.clear();
    }

    startTicker() {
        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
        }

        this.monitorInterval = setInterval(() => {
            if (this.state !== 'running') {
                return;
            }

            if (this.currentSamplePromise) {
                return;
            }

            this.currentSamplePromise = this.sample()
                .catch(error => {
                    this.emit('error', error);
                })
                .finally(() => {
                    this.currentSamplePromise = null;
                });
        }, this.sampleInterval);
    }

    stopTicker() {
        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
            this.monitorInterval = null;
        }
    }

    startDurationTimer() {
        if (this.durationTimeout) {
            clearTimeout(this.durationTimeout);
        }

        if (this.duration > 0) {
            this.durationTimeout = setTimeout(() => {
                this.stop().catch(error => {
                    this.emit('error', error);
                });
            }, this.duration * 1000);
        }
    }

    stopDurationTimer() {
        if (this.durationTimeout) {
            clearTimeout(this.durationTimeout);
            this.durationTimeout = null;
        }
    }

    async start() {
        if (this.state === 'running') {
            throw new Error('Monitor is already running');
        }

        if (this.state === 'paused') {
            throw new Error('Monitor is paused; use resume()');
        }

        const exists = await this.interfaceExists();
        if (!exists) {
            throw new Error(`Interface ${this.interface} not found or not accessible`);
        }

        this.resetRuntimeState();

        const stats = await this.getNetworkStats();
        this.prevStats = stats;
        this.initialStats = this.cloneStats(stats);
        this.lastStats = this.cloneStats(stats);
        this.state = 'running';
        this.startTicker();
        this.startDurationTimer();
        this.emit('started', {
            interface: this.interface,
            duration: this.duration,
            sampleInterval: this.sampleInterval
        });
    }

    async stop() {
        if (this.state === 'stopped') {
            return;
        }

        this.state = 'stopped';
        this.stopTicker();
        this.stopDurationTimer();

        const pending = this.currentSamplePromise;
        if (pending) {
            try {
                await pending;
            } catch (_) {
            }
        }

        this.endTime = Date.now();
        this.emit('stopped', this.getSummary());
    }

    pause() {
        if (this.state !== 'running') {
            return;
        }

        this.state = 'paused';
        this.stopTicker();
        this.stopDurationTimer();
        this.emit('paused', {
            interface: this.interface,
            timestamp: new Date()
        });
    }

    resume() {
        if (this.state !== 'paused') {
            return;
        }

        if (!this.prevStats) {
            throw new Error('Cannot resume without previous statistics');
        }

        this.state = 'running';
        this.startTicker();
        this.startDurationTimer();
        this.emit('resumed', {
            interface: this.interface,
            timestamp: new Date()
        });
    }

    cloneStats(stats) {
        if (!stats) {
            return null;
        }

        return {
            interface: stats.interface,
            timestamp: stats.timestamp,
            txBytes: BigInt(stats.txBytes),
            rxBytes: BigInt(stats.rxBytes),
            txPackets: BigInt(stats.txPackets),
            rxPackets: BigInt(stats.rxPackets),
            txErrors: BigInt(stats.txErrors),
            rxErrors: BigInt(stats.rxErrors),
            txDropped: BigInt(stats.txDropped),
            rxDropped: BigInt(stats.rxDropped)
        };
    }

    async sample() {
        if (this.state !== 'running') {
            return;
        }

        const currentStats = await this.getNetworkStats();

        if (!this.prevStats) {
            this.prevStats = this.cloneStats(currentStats);
            this.lastStats = this.cloneStats(currentStats);
            return;
        }

        const txRate = this.calculateCounterDelta(this.prevStats.txBytes, currentStats.txBytes);
        const rxRate = this.calculateCounterDelta(this.prevStats.rxBytes, currentStats.rxBytes);
        const txPacketRate = this.calculateCounterDelta(this.prevStats.txPackets, currentStats.txPackets);
        const rxPacketRate = this.calculateCounterDelta(this.prevStats.rxPackets, currentStats.rxPackets);
        const txErrorsDelta = this.calculateCounterDelta(this.prevStats.txErrors, currentStats.txErrors);
        const rxErrorsDelta = this.calculateCounterDelta(this.prevStats.rxErrors, currentStats.rxErrors);
        const txDroppedDelta = this.calculateCounterDelta(this.prevStats.txDropped, currentStats.txDropped);
        const rxDroppedDelta = this.calculateCounterDelta(this.prevStats.rxDropped, currentStats.rxDropped);

        const sampleData = {
            timestamp: new Date(),
            interface: this.interface,
            txRate,
            rxRate,
            txPacketRate,
            rxPacketRate,
            txErrorsDelta,
            rxErrorsDelta,
            txDroppedDelta,
            rxDroppedDelta,
            currentStats: this.cloneStats(currentStats)
        };

        const alerts = this.checkAlerts(
            txRate,
            rxRate,
            txErrorsDelta,
            rxErrorsDelta,
            txDroppedDelta,
            rxDroppedDelta
        );

        sampleData.alerts = alerts;

        this.prevStats = this.cloneStats(currentStats);
        this.lastStats = this.cloneStats(currentStats);
        this.sampleCount++;
        this.emit('sample', sampleData);
    }

    calculateCounterDelta(prev, curr) {
        const prevBig = BigInt(prev);
        const currBig = BigInt(curr);

        if (currBig >= prevBig) {
            return currBig - prevBig;
        }

        const maxUint64 = (1n << 64n) - 1n;
        return (maxUint64 - prevBig) + currBig + 1n;
    }

    checkAlerts(txRate, rxRate, txErrors, rxErrors, txDropped, rxDropped) {
        const now = Date.now();
        const emitted = [];

        const checkAndAddAlert = (type, condition, details) => {
            if (!condition) {
                return;
            }

            const lastAlert = this.lastAlertTimestamps.get(type) || 0;
            if (now - lastAlert < this.alertCooldown) {
                return;
            }

            const alert = {
                timestamp: new Date(now),
                type,
                interface: this.interface,
                ...details
            };

            this.addAlert(alert);
            this.lastAlertTimestamps.set(type, now);
            this.emit('alert', alert);
            emitted.push(alert);
        };

        checkAndAddAlert('HIGH_TX_TRAFFIC', txRate > this.highTrafficThreshold, { rate: txRate });
        checkAndAddAlert('HIGH_RX_TRAFFIC', rxRate > this.highTrafficThreshold, { rate: rxRate });
        checkAndAddAlert('HIGH_TX_ERRORS', txErrors > this.errorThreshold, { count: txErrors });
        checkAndAddAlert('HIGH_RX_ERRORS', rxErrors > this.errorThreshold, { count: rxErrors });
        checkAndAddAlert('HIGH_TX_DROPPED', txDropped > this.dropThreshold, { count: txDropped });
        checkAndAddAlert('HIGH_RX_DROPPED', rxDropped > this.dropThreshold, { count: rxDropped });

        return emitted;
    }

    addAlert(alert) {
        this.alerts.push(alert);
        while (this.alerts.length > this.alertHistorySize) {
            this.alerts.shift();
        }
    }

    async getNetworkStats() {
        const basePath = this.getStatisticsBasePath();
        const statsFiles = {
            txBytes: 'tx_bytes',
            rxBytes: 'rx_bytes',
            txPackets: 'tx_packets',
            rxPackets: 'rx_packets',
            txErrors: 'tx_errors',
            rxErrors: 'rx_errors',
            txDropped: 'tx_dropped',
            rxDropped: 'rx_dropped'
        };

        const stats = {
            interface: this.interface,
            timestamp: Date.now()
        };

        const fileEntries = Object.entries(statsFiles).map(([key, fileName]) => ({
            key,
            filePath: path.posix.join(basePath, fileName)
        }));

        const values = await Promise.all(
            fileEntries.map(entry => this.readSysFile(entry.filePath))
        );

        values.forEach((value, index) => {
            stats[fileEntries[index].key] = value;
        });

        return stats;
    }

    async readSysFile(filePath) {
        const validation = this.validateStatisticsPath(filePath);
        if (!validation.valid) {
            throw new Error(validation.reason);
        }

        try {
            const stats = await fs.promises.stat(filePath);
            if (stats.size > this.maxFileSize) {
                throw new Error(`File too large: ${stats.size} bytes`);
            }

            const data = await fs.promises.readFile(filePath, 'utf8');
            const trimmed = data.trim();

            if (!trimmed) {
                return 0n;
            }

            if (!/^\d+$/.test(trimmed)) {
                throw new Error(`Invalid numeric content in ${filePath}`);
            }

            return BigInt(trimmed);
        } catch (error) {
            if (error.code === 'ENOENT') {
                throw new Error(`Network statistics not available for interface ${this.interface}`);
            }
            if (error.code === 'EACCES') {
                throw new Error(`Permission denied reading statistics for ${this.interface}`);
            }
            throw error;
        }
    }

    async interfaceExists() {
        try {
            const interfacePath = this.getInterfaceBasePath();
            const validation = this.validateInterfacePath(interfacePath);

            if (!validation.valid) {
                return false;
            }

            await fs.promises.access(interfacePath, fs.constants.R_OK);
            const stats = await fs.promises.stat(interfacePath);
            return stats.isDirectory();
        } catch (_) {
            return false;
        }
    }

    getElapsedSeconds() {
        const end = this.endTime || Date.now();
        return Math.max(0, (end - this.startTime) / 1000);
    }

    getSessionTotals() {
        if (!this.initialStats || !this.lastStats) {
            return null;
        }

        return {
            txBytes: this.calculateCounterDelta(this.initialStats.txBytes, this.lastStats.txBytes),
            rxBytes: this.calculateCounterDelta(this.initialStats.rxBytes, this.lastStats.rxBytes),
            txPackets: this.calculateCounterDelta(this.initialStats.txPackets, this.lastStats.txPackets),
            rxPackets: this.calculateCounterDelta(this.initialStats.rxPackets, this.lastStats.rxPackets),
            txErrors: this.calculateCounterDelta(this.initialStats.txErrors, this.lastStats.txErrors),
            rxErrors: this.calculateCounterDelta(this.initialStats.rxErrors, this.lastStats.rxErrors),
            txDropped: this.calculateCounterDelta(this.initialStats.txDropped, this.lastStats.txDropped),
            rxDropped: this.calculateCounterDelta(this.initialStats.rxDropped, this.lastStats.rxDropped)
        };
    }

    getSummary() {
        const elapsed = this.getElapsedSeconds();
        const sessionTotals = this.getSessionTotals();

        const interfaceTotals = this.lastStats ? {
            txBytes: this.lastStats.txBytes,
            rxBytes: this.lastStats.rxBytes,
            txPackets: this.lastStats.txPackets,
            rxPackets: this.lastStats.rxPackets,
            txErrors: this.lastStats.txErrors,
            rxErrors: this.lastStats.rxErrors,
            txDropped: this.lastStats.txDropped,
            rxDropped: this.lastStats.rxDropped
        } : null;

        const combinedSession = sessionTotals ? {
            totalBytes: sessionTotals.txBytes + sessionTotals.rxBytes,
            totalPackets: sessionTotals.txPackets + sessionTotals.rxPackets,
            totalErrors: sessionTotals.txErrors + sessionTotals.rxErrors,
            totalDropped: sessionTotals.txDropped + sessionTotals.rxDropped
        } : null;

        const averageRates = sessionTotals && elapsed > 0 ? {
            txBytesPerSecond: Number(sessionTotals.txBytes) / elapsed,
            rxBytesPerSecond: Number(sessionTotals.rxBytes) / elapsed
        } : null;

        const avgPacketSize = combinedSession && combinedSession.totalPackets > 0n
            ? Number(combinedSession.totalBytes) / Number(combinedSession.totalPackets)
            : null;

        const errorRate = combinedSession && combinedSession.totalPackets > 0n
            ? (Number(combinedSession.totalErrors) / Number(combinedSession.totalPackets)) * 100
            : null;

        return {
            interface: this.interface,
            state: this.state,
            startTime: this.startTime ? new Date(this.startTime).toISOString() : null,
            endTime: this.endTime ? new Date(this.endTime).toISOString() : new Date().toISOString(),
            durationSeconds: elapsed,
            sampleCount: this.sampleCount,
            alerts: this.alerts.map(alert => ({
                type: alert.type,
                timestamp: alert.timestamp.toISOString(),
                rate: alert.rate !== undefined ? alert.rate.toString() : undefined,
                count: alert.count !== undefined ? alert.count.toString() : undefined,
                interface: alert.interface
            })),
            sessionTotals: sessionTotals ? {
                txBytes: sessionTotals.txBytes.toString(),
                rxBytes: sessionTotals.rxBytes.toString(),
                txPackets: sessionTotals.txPackets.toString(),
                rxPackets: sessionTotals.rxPackets.toString(),
                txErrors: sessionTotals.txErrors.toString(),
                rxErrors: sessionTotals.rxErrors.toString(),
                txDropped: sessionTotals.txDropped.toString(),
                rxDropped: sessionTotals.rxDropped.toString()
            } : null,
            interfaceTotals: interfaceTotals ? {
                txBytes: interfaceTotals.txBytes.toString(),
                rxBytes: interfaceTotals.rxBytes.toString(),
                txPackets: interfaceTotals.txPackets.toString(),
                rxPackets: interfaceTotals.rxPackets.toString(),
                txErrors: interfaceTotals.txErrors.toString(),
                rxErrors: interfaceTotals.rxErrors.toString(),
                txDropped: interfaceTotals.txDropped.toString(),
                rxDropped: interfaceTotals.rxDropped.toString()
            } : null,
            combinedSession: combinedSession ? {
                totalBytes: combinedSession.totalBytes.toString(),
                totalPackets: combinedSession.totalPackets.toString(),
                totalErrors: combinedSession.totalErrors.toString(),
                totalDropped: combinedSession.totalDropped.toString()
            } : null,
            averageRates: averageRates ? {
                txBytesPerSecond: averageRates.txBytesPerSecond,
                rxBytesPerSecond: averageRates.rxBytesPerSecond
            } : null,
            averagePacketSize: avgPacketSize,
            errorRatePercent: errorRate,
            settings: {
                highTrafficThreshold: this.highTrafficThreshold.toString(),
                errorThreshold: this.errorThreshold.toString(),
                dropThreshold: this.dropThreshold.toString(),
                sampleInterval: this.sampleInterval,
                alertCooldown: this.alertCooldown
            }
        };
    }

    exportToJson() {
        return this.getSummary();
    }

    formatBytes(value) {
        let bytes;

        if (typeof value === 'bigint') {
            bytes = Number(value);
        } else if (typeof value === 'number') {
            bytes = value;
        } else {
            bytes = Number(value || 0);
        }

        if (!Number.isFinite(bytes) || bytes < 0) {
            return '0 B';
        }

        const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        let unitIndex = 0;

        while (bytes >= 1024 && unitIndex < units.length - 1) {
            bytes /= 1024;
            unitIndex++;
        }

        return bytes.toFixed(unitIndex === 0 ? 0 : 2) + ' ' + units[unitIndex];
    }
}

class ConsoleRenderer {
    constructor(output = console) {
        this.output = output;
    }

    renderStarted(info, monitor) {
        this.output.log(`Checking interface ${monitor.interface}...`);
        this.output.log(`Network Traffic Monitor - ${monitor.interface}`);
        this.output.log(`Duration: ${info.duration > 0 ? info.duration + ' seconds' : 'unlimited'}`);
        this.output.log(`Sample interval: ${info.sampleInterval}ms`);
        this.output.log(`High traffic threshold: ${monitor.formatBytes(monitor.highTrafficThreshold)}/s`);
        this.output.log('Press Ctrl+C to stop');
        this.output.log('');
    }

    renderPaused(interfaceName) {
        this.output.log(`Monitoring paused for ${interfaceName}`);
    }

    renderResumed(interfaceName) {
        this.output.log(`Monitoring resumed for ${interfaceName}`);
    }

    renderError(error) {
        this.output.error(`Monitor error: ${error.message}`);
    }

    renderSample(sample, monitor) {
        const timestamp = sample.timestamp.toISOString().replace('T', ' ').substring(0, 19);

        this.output.log(`[${timestamp}] ${sample.interface}`);
        this.output.log(
            `  TX: ${monitor.formatBytes(sample.txRate).padStart(8)}/s (${sample.txPacketRate.toString().padStart(5)} pkt/s) | Total: ${monitor.formatBytes(sample.currentStats.txBytes)}`
        );
        this.output.log(
            `  RX: ${monitor.formatBytes(sample.rxRate).padStart(8)}/s (${sample.rxPacketRate.toString().padStart(5)} pkt/s) | Total: ${monitor.formatBytes(sample.currentStats.rxBytes)}`
        );

        if (sample.txErrorsDelta > 0n || sample.rxErrorsDelta > 0n) {
            this.output.log(`  ERRORS: TX=${sample.txErrorsDelta.toString()}, RX=${sample.rxErrorsDelta.toString()}`);
        }

        if (sample.txDroppedDelta > 0n || sample.rxDroppedDelta > 0n) {
            this.output.log(`  DROPPED: TX=${sample.txDroppedDelta.toString()}, RX=${sample.rxDroppedDelta.toString()}`);
        }

        for (const alert of sample.alerts || []) {
            const value = alert.rate !== undefined
                ? `${monitor.formatBytes(alert.rate)}/s`
                : `${alert.count.toString()} packets`;
            this.output.log(`  ALERT: ${alert.type} DETECTED (${value})`);
        }

        if (sample.txRate === 0n && sample.rxRate === 0n) {
            this.output.log('  No network activity');
        }

        if ((sample.txRate > 0n || sample.rxRate > 0n) && (sample.txPacketRate + sample.rxPacketRate) > 0n) {
            const totalBytes = Number(sample.txRate + sample.rxRate);
            const totalPackets = Number(sample.txPacketRate + sample.rxPacketRate);
            const efficiency = totalPackets > 0 ? Math.round(totalBytes / totalPackets) : 0;
            this.output.log(`  Avg packet size: ${efficiency} bytes`);
        }

        this.output.log('');
    }

    renderSummary(summary, monitor) {
        this.output.log('');
        this.output.log('='.repeat(50));
        this.output.log('MONITORING SUMMARY');
        this.output.log('='.repeat(50));
        this.output.log(`Interface: ${summary.interface}`);
        this.output.log(`Duration: ${summary.durationSeconds.toFixed(1)} seconds`);
        this.output.log(`Samples: ${summary.sampleCount}`);

        if (summary.alerts.length > 0) {
            this.output.log('');
            this.output.log(`Alerts triggered: ${summary.alerts.length}`);

            const alertTypes = {};
            for (const alert of summary.alerts) {
                const timeStr = alert.timestamp.substring(11, 19);
                alertTypes[alert.type] = (alertTypes[alert.type] || 0) + 1;
                const value = alert.rate !== undefined
                    ? `${monitor.formatBytes(BigInt(alert.rate))}/s`
                    : `${BigInt(alert.count).toString()} packets`;
                this.output.log(`  [${timeStr}] ${alert.type}: ${value}`);
            }

            this.output.log('');
            this.output.log('Alert summary:');
            for (const [type, count] of Object.entries(alertTypes)) {
                this.output.log(`  ${type}: ${count} times`);
            }
        } else {
            this.output.log('');
            this.output.log('No alerts triggered');
        }

        if (summary.sessionTotals) {
            this.output.log('');
            this.output.log('SESSION TOTALS:');
            this.output.log(`  TX: ${monitor.formatBytes(BigInt(summary.sessionTotals.txBytes))}`);
            this.output.log(`     Packets: ${BigInt(summary.sessionTotals.txPackets).toLocaleString()}`);
            this.output.log(`     Errors: ${BigInt(summary.sessionTotals.txErrors).toLocaleString()}`);
            this.output.log(`     Dropped: ${BigInt(summary.sessionTotals.txDropped).toLocaleString()}`);
            this.output.log(`  RX: ${monitor.formatBytes(BigInt(summary.sessionTotals.rxBytes))}`);
            this.output.log(`     Packets: ${BigInt(summary.sessionTotals.rxPackets).toLocaleString()}`);
            this.output.log(`     Errors: ${BigInt(summary.sessionTotals.rxErrors).toLocaleString()}`);
            this.output.log(`     Dropped: ${BigInt(summary.sessionTotals.rxDropped).toLocaleString()}`);
        }

        if (summary.interfaceTotals) {
            this.output.log('');
            this.output.log(`CURRENT INTERFACE COUNTERS FOR ${summary.interface}:`);
            this.output.log(`  TX: ${monitor.formatBytes(BigInt(summary.interfaceTotals.txBytes))}`);
            this.output.log(`     Packets: ${BigInt(summary.interfaceTotals.txPackets).toLocaleString()}`);
            this.output.log(`     Errors: ${BigInt(summary.interfaceTotals.txErrors).toLocaleString()}`);
            this.output.log(`     Dropped: ${BigInt(summary.interfaceTotals.txDropped).toLocaleString()}`);
            this.output.log(`  RX: ${monitor.formatBytes(BigInt(summary.interfaceTotals.rxBytes))}`);
            this.output.log(`     Packets: ${BigInt(summary.interfaceTotals.rxPackets).toLocaleString()}`);
            this.output.log(`     Errors: ${BigInt(summary.interfaceTotals.rxErrors).toLocaleString()}`);
            this.output.log(`     Dropped: ${BigInt(summary.interfaceTotals.rxDropped).toLocaleString()}`);
        }

        if (summary.combinedSession) {
            this.output.log('');
            this.output.log('SESSION AGGREGATES:');
            this.output.log(`  Data: ${monitor.formatBytes(BigInt(summary.combinedSession.totalBytes))}`);
            this.output.log(`  Packets: ${BigInt(summary.combinedSession.totalPackets).toLocaleString()}`);
            this.output.log(`  Errors: ${BigInt(summary.combinedSession.totalErrors).toLocaleString()}`);
            this.output.log(`  Dropped: ${BigInt(summary.combinedSession.totalDropped).toLocaleString()}`);
        }

        if (summary.averageRates) {
            this.output.log('');
            this.output.log('AVERAGE SESSION RATES:');
            this.output.log(`  TX: ${monitor.formatBytes(summary.averageRates.txBytesPerSecond)}/s`);
            this.output.log(`  RX: ${monitor.formatBytes(summary.averageRates.rxBytesPerSecond)}/s`);
        }

        if (summary.averagePacketSize !== null) {
            this.output.log(`  Avg packet size: ${Math.round(summary.averagePacketSize)} bytes`);
        }

        if (summary.errorRatePercent !== null) {
            this.output.log(`  Error rate: ${summary.errorRatePercent.toFixed(4)}%`);
        }
    }
}

async function listInterfaces() {
    try {
        const interfacesPath = '/sys/class/net';
        await fs.promises.access(interfacesPath);

        const interfaces = await fs.promises.readdir(interfacesPath);
        const validInterfaces = [];

        for (const iface of interfaces) {
            try {
                const ifacePath = path.posix.join(interfacesPath, iface);
                const stats = await fs.promises.stat(ifacePath);
                if (stats.isDirectory()) {
                    validInterfaces.push(iface);
                }
            } catch (_) {
            }
        }

        console.log(`Available interfaces (${validInterfaces.length}):`);
        validInterfaces.forEach(iface => console.log(`  - ${iface}`));
        return validInterfaces;
    } catch (error) {
        console.log('Cannot list interfaces:', error.message);
        return [];
    }
}

async function validateInterface(interfaceName) {
    try {
        const monitor = new NetworkMonitor(interfaceName);
        return await monitor.interfaceExists();
    } catch (_) {
        return false;
    }
}

function validatePositiveNumber(value, name, min = 0) {
    const num = parseInt(value, 10);
    if (Number.isNaN(num) || num < min) {
        throw new Error(`${name} must be a number >= ${min}`);
    }
    return num;
}

function parseArgs(args) {
    if (args.length < 1 || args.includes('--help') || args.includes('-h')) {
        return { help: true };
    }

    if (args.includes('--list') || args.includes('-l')) {
        return { list: true };
    }

    const interfaceName = args[0];
    let duration = 0;
    let highTrafficThresholdMb = 50;
    let errorThreshold = 1000;
    let dropThreshold = 100;
    let sampleInterval = 1000;
    let alertCooldown = 5000;
    let outputJson = false;

    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--threshold' && args[i + 1]) {
            highTrafficThresholdMb = validatePositiveNumber(args[i + 1], 'Threshold', 1);
            i++;
        } else if (args[i] === '--errors' && args[i + 1]) {
            errorThreshold = validatePositiveNumber(args[i + 1], 'Error threshold', 0);
            i++;
        } else if (args[i] === '--drops' && args[i + 1]) {
            dropThreshold = validatePositiveNumber(args[i + 1], 'Drop threshold', 0);
            i++;
        } else if (args[i] === '--interval' && args[i + 1]) {
            sampleInterval = validatePositiveNumber(args[i + 1], 'Sample interval', 100);
            i++;
        } else if (args[i] === '--cooldown' && args[i + 1]) {
            alertCooldown = validatePositiveNumber(args[i + 1], 'Alert cooldown', 100);
            i++;
        } else if (args[i] === '--json') {
            outputJson = true;
        } else if (/^\d+$/.test(args[i])) {
            duration = validatePositiveNumber(args[i], 'Duration', 0);
        }
    }

    return {
        help: false,
        list: false,
        interfaceName,
        duration,
        highTrafficThresholdMb,
        errorThreshold,
        dropThreshold,
        sampleInterval,
        alertCooldown,
        outputJson
    };
}

function printHelp() {
    console.log('Network Traffic Monitor');
    console.log('Usage: node network_monitor.js <interface> [duration_seconds]');
    console.log('');
    console.log('Options:');
    console.log('  --help, -h       Show this help message');
    console.log('  --list, -l       List available interfaces');
    console.log('  --threshold N    Set high traffic threshold in MB (default: 50)');
    console.log('  --errors N       Set error threshold (default: 1000)');
    console.log('  --drops N        Set dropped packet threshold (default: 100)');
    console.log('  --interval N     Set sample interval in ms (default: 1000)');
    console.log('  --cooldown N     Set alert cooldown in ms (default: 5000)');
    console.log('  --json           Output summary in JSON format');
    console.log('');
    console.log('Examples:');
    console.log('  node network_monitor.js eth0 60');
    console.log('  node network_monitor.js wlan0 --threshold 100 --errors 500');
    console.log('  node network_monitor.js --list');
}

async function main() {
    const parsed = parseArgs(process.argv.slice(2));

    if (parsed.help) {
        printHelp();
        return;
    }

    if (parsed.list) {
        await listInterfaces();
        return;
    }

    if (!await validateInterface(parsed.interfaceName)) {
        console.error(`Error: Interface '${parsed.interfaceName}' not found or not accessible`);
        console.log('Use --list to see available interfaces');
        process.exit(1);
    }

    const monitor = new NetworkMonitor(parsed.interfaceName, {
        duration: parsed.duration,
        highTrafficThreshold: BigInt(parsed.highTrafficThresholdMb) * 1024n * 1024n,
        errorThreshold: BigInt(parsed.errorThreshold),
        dropThreshold: BigInt(parsed.dropThreshold),
        sampleInterval: parsed.sampleInterval,
        alertCooldown: parsed.alertCooldown
    });

    const renderer = new ConsoleRenderer();

    monitor.on('started', info => renderer.renderStarted(info, monitor));
    monitor.on('sample', sample => renderer.renderSample(sample, monitor));
    monitor.on('paused', () => renderer.renderPaused(monitor.interface));
    monitor.on('resumed', () => renderer.renderResumed(monitor.interface));
    monitor.on('error', error => renderer.renderError(error));

    let summaryPrinted = false;
    monitor.on('stopped', summary => {
        if (summaryPrinted) {
            return;
        }
        summaryPrinted = true;
        renderer.renderSummary(summary, monitor);
        if (parsed.outputJson) {
            console.log(JSON.stringify(monitor.exportToJson(), null, 2));
        }
    });

    const shutdown = async () => {
        try {
            await monitor.stop();
        } finally {
            process.exit(0);
        }
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    try {
        await monitor.start();
    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    main().catch(error => {
        console.error('Fatal error:', error.message);
        process.exit(1);
    });
}

module.exports = {
    NetworkMonitor,
    ConsoleRenderer
};
