const fs = require('fs');
const path = require('path');

class NetworkMonitor {
    constructor(interfaceName, duration = 0) {
        this.interface = this.sanitizeInterfaceName(interfaceName);
        this.duration = Math.max(0, duration);
        this.startTime = Date.now();
        this.prevStats = null;
        this.alerts = [];
        this.sampleCount = 0;
        this.monitorInterval = null;
        this.isRunning = false;
        this.maxFileSize = 16384;
        this.highTrafficThreshold = 50 * 1024 * 1024;
        this.errorThreshold = 1000;
        this.dropThreshold = 100;
        this.sampleInterval = 1000;
        this.alertHistorySize = 100;
        this.durationTimeout = null;
        this.currentSamplePromise = null;
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

    validateSysfsPath(filePath) {
        try {
            const normalizedPath = path.normalize(filePath).replace(/\/+/g, '/');
            
            if (!normalizedPath.startsWith('/sys/class/net/')) {
                return { valid: false, reason: 'Path must start with /sys/class/net/' };
            }
            
            const pathAfterBase = normalizedPath.substring('/sys/class/net/'.length);
            const parts = pathAfterBase.split('/').filter(part => part.length > 0);
            
            if (parts.length === 0) {
                return { valid: false, reason: 'No interface specified' };
            }
            
            const ifaceName = parts[0];
            try {
                this.sanitizeInterfaceName(ifaceName);
            } catch (error) {
                return { valid: false, reason: `Invalid interface name: ${error.message}` };
            }
            
            const allowedFiles = new Set([
                'tx_bytes', 'rx_bytes', 'tx_packets', 'rx_packets',
                'tx_errors', 'rx_errors', 'tx_dropped', 'rx_dropped',
                'operstate', 'carrier', 'speed', 'mtu', 'statistics'
            ]);
            
            if (parts.length > 1) {
                const filename = parts[1];
                if (!allowedFiles.has(filename)) {
                    return { valid: false, reason: `File ${filename} not allowed in sysfs` };
                }
            }
            
            if (parts.length > 2) {
                const subfile = parts[2];
                const allowedSubfiles = new Set([
                    'tx_bytes', 'rx_bytes', 'tx_packets', 'rx_packets',
                    'tx_errors', 'rx_errors', 'tx_dropped', 'rx_dropped'
                ]);
                if (!allowedSubfiles.has(subfile)) {
                    return { valid: false, reason: `Subfile ${subfile} not allowed` };
                }
            }
            
            if (parts.length > 3) {
                return { valid: false, reason: 'Path too deep' };
            }
            
            return { valid: true };
        } catch (error) {
            return { valid: false, reason: `Validation error: ${error.message}` };
        }
    }

    async start() {
        if (this.isRunning) {
            throw new Error('Monitor is already running');
        }

        console.log(`Checking interface ${this.interface}...`);
        const exists = await this.interfaceExists();
        if (!exists) {
            throw new Error(`Interface ${this.interface} not found or not accessible`);
        }

        console.log(`Network Traffic Monitor - ${this.interface}`);
        console.log(`Duration: ${this.duration > 0 ? this.duration + ' seconds' : 'unlimited'}`);
        console.log(`Sample interval: ${this.sampleInterval}ms`);
        console.log(`High traffic threshold: ${this.formatBytes(this.highTrafficThreshold)}/s`);
        console.log('Press Ctrl+C to stop\n');

        try {
            this.prevStats = await this.getNetworkStats();
            console.log('Initial statistics loaded successfully');
        } catch (error) {
            throw new Error(`Failed to get initial stats: ${error.message}`);
        }

        this.isRunning = true;
        this.startTime = Date.now();
        this.sampleCount = 0;
        this.alerts = [];
        
        this.monitorInterval = setInterval(async () => {
            if (!this.isRunning || this.currentSamplePromise) {
                return;
            }
            
            this.currentSamplePromise = this.sample().catch(error => {
                console.error(`Sampling error: ${error.message}`);
            }).finally(() => {
                this.currentSamplePromise = null;
            });
        }, this.sampleInterval);

        if (this.duration > 0) {
            this.durationTimeout = setTimeout(() => {
                this.stop();
            }, this.duration * 1000);
        }
    }

    stop() {
        this.isRunning = false;
        
        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
            this.monitorInterval = null;
        }
        
        if (this.durationTimeout) {
            clearTimeout(this.durationTimeout);
            this.durationTimeout = null;
        }
        
        this.printSummary();
        
        this.prevStats = null;
        this.sampleCount = 0;
    }

    pause() {
        this.isRunning = false;
        console.log('Monitoring paused');
    }

    resume() {
        if (!this.prevStats) {
            throw new Error('Cannot resume - no previous statistics');
        }
        this.isRunning = true;
        console.log('Monitoring resumed');
    }

    async sample() {
        if (!this.isRunning) return;

        let currentStats;
        try {
            currentStats = await this.getNetworkStats();
        } catch (error) {
            console.error(`Failed to get network stats: ${error.message}`);
            return;
        }

        if (!this.prevStats) {
            this.prevStats = currentStats;
            return;
        }

        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        const txRate = this.calculateCounterDelta(this.prevStats.txBytes, currentStats.txBytes);
        const rxRate = this.calculateCounterDelta(this.prevStats.rxBytes, currentStats.rxBytes);
        const txPacketRate = this.calculateCounterDelta(this.prevStats.txPackets, currentStats.txPackets);
        const rxPacketRate = this.calculateCounterDelta(this.prevStats.rxPackets, currentStats.rxPackets);
        const txErrorsDelta = this.calculateCounterDelta(this.prevStats.txErrors, currentStats.txErrors);
        const rxErrorsDelta = this.calculateCounterDelta(this.prevStats.rxErrors, currentStats.rxErrors);
        const txDroppedDelta = this.calculateCounterDelta(this.prevStats.txDropped, currentStats.txDropped);
        const rxDroppedDelta = this.calculateCounterDelta(this.prevStats.rxDropped, currentStats.rxDropped);
        
        console.log(`[${timestamp}] ${this.interface}`);
        console.log(`  TX: ${this.formatBytes(txRate).padStart(8)}/s (${txPacketRate.toString().padStart(5)} pkt/s) | Total: ${this.formatBytes(currentStats.txBytes)}`);
        console.log(`  RX: ${this.formatBytes(rxRate).padStart(8)}/s (${rxPacketRate.toString().padStart(5)} pkt/s) | Total: ${this.formatBytes(currentStats.rxBytes)}`);
        
        if (txErrorsDelta > 0 || rxErrorsDelta > 0) {
            console.log(`  ERRORS: TX=${txErrorsDelta}, RX=${rxErrorsDelta}`);
        }
        
        if (txDroppedDelta > 0 || rxDroppedDelta > 0) {
            console.log(`  DROPPED: TX=${txDroppedDelta}, RX=${rxDroppedDelta}`);
        }

        this.checkAlerts(txRate, rxRate, txErrorsDelta, rxErrorsDelta, txDroppedDelta, rxDroppedDelta);
        
        if (txRate === 0 && rxRate === 0) {
            console.log('  No network activity');
        }
        
        if ((txRate > 0 || rxRate > 0) && (txPacketRate + rxPacketRate) > 0) {
            const efficiency = (txRate + rxRate) / (txPacketRate + rxPacketRate);
            console.log(`  Avg packet size: ${Math.round(efficiency)} bytes`);
        }

        console.log();

        this.prevStats = currentStats;
        this.sampleCount++;
    }

    calculateCounterDelta(prev, curr) {
        const MAX_UINT64 = 0xFFFFFFFFFFFFFFFFn;
        
        const prevBig = BigInt(prev);
        const currBig = BigInt(curr);
        
        if (currBig >= prevBig) {
            return Number(currBig - prevBig);
        } else {
            return Number((MAX_UINT64 - prevBig) + currBig + 1n);
        }
    }

    checkAlerts(txRate, rxRate, txErrors, rxErrors, txDropped, rxDropped) {
        const timestamp = new Date();
        
        if (txRate > this.highTrafficThreshold) {
            this.addAlert({
                timestamp,
                type: 'HIGH_TX_TRAFFIC',
                rate: txRate,
                interface: this.interface
            });
            console.log(`  ALERT: HIGH TX TRAFFIC DETECTED (${this.formatBytes(txRate)}/s)`);
        }
        
        if (rxRate > this.highTrafficThreshold) {
            this.addAlert({
                timestamp,
                type: 'HIGH_RX_TRAFFIC',
                rate: rxRate,
                interface: this.interface
            });
            console.log(`  ALERT: HIGH RX TRAFFIC DETECTED (${this.formatBytes(rxRate)}/s)`);
        }

        if (txErrors > this.errorThreshold) {
            this.addAlert({
                timestamp,
                type: 'HIGH_TX_ERRORS',
                count: txErrors,
                interface: this.interface
            });
            console.log(`  ALERT: HIGH TX ERRORS DETECTED (${txErrors} errors)`);
        }

        if (rxErrors > this.errorThreshold) {
            this.addAlert({
                timestamp,
                type: 'HIGH_RX_ERRORS',
                count: rxErrors,
                interface: this.interface
            });
            console.log(`  ALERT: HIGH RX ERRORS DETECTED (${rxErrors} errors)`);
        }

        if (txDropped > this.dropThreshold) {
            this.addAlert({
                timestamp,
                type: 'HIGH_TX_DROPPED',
                count: txDropped,
                interface: this.interface
            });
            console.log(`  ALERT: HIGH TX DROPPED PACKETS (${txDropped} dropped)`);
        }

        if (rxDropped > this.dropThreshold) {
            this.addAlert({
                timestamp,
                type: 'HIGH_RX_DROPPED',
                count: rxDropped,
                interface: this.interface
            });
            console.log(`  ALERT: HIGH RX DROPPED PACKETS (${rxDropped} dropped)`);
        }
    }

    addAlert(alert) {
        this.alerts.push(alert);
        if (this.alerts.length > this.alertHistorySize) {
            this.alerts.shift();
        }
    }

    async getNetworkStats() {
        const basePath = `/sys/class/net/${this.interface}/statistics`;
        
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

        const readPromises = [];
        const filePaths = [];

        for (const [statName, fileName] of Object.entries(statsFiles)) {
            const filePath = path.join(basePath, fileName);
            filePaths.push({ statName, filePath });
            readPromises.push(this.readSysFile(filePath).catch(() => 0));
        }

        const results = await Promise.all(readPromises);
        
        results.forEach((value, index) => {
            const { statName } = filePaths[index];
            stats[statName] = value;
        });
        
        return stats;
    }

    async readSysFile(filePath) {
        try {
            const validation = this.validateSysfsPath(filePath);
            if (!validation.valid) {
                throw new Error(validation.reason);
            }

            const stats = await fs.promises.stat(filePath);
            if (stats.size > this.maxFileSize) {
                throw new Error(`File too large: ${stats.size} bytes`);
            }

            const data = await fs.promises.readFile(filePath, 'utf8');
            const value = parseInt(data.trim(), 10);
            
            if (isNaN(value) || value < 0) {
                return 0;
            }
            
            return value;
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
            const interfacePath = `/sys/class/net/${this.interface}`;
            
            const validation = this.validateSysfsPath(interfacePath);
            if (!validation.valid) {
                console.error(`Invalid interface path: ${validation.reason}`);
                return false;
            }

            await fs.promises.access(interfacePath);
            const stats = await fs.promises.stat(interfacePath);
            
            if (!stats.isDirectory()) {
                console.error(`Interface path is not a directory: ${interfacePath}`);
                return false;
            }
            
            return true;
        } catch (error) {
            console.error(`Interface check failed: ${error.message}`);
            return false;
        }
    }

    formatBytes(bytes) {
        if (typeof bytes !== 'number' || bytes < 0) {
            return '0 B';
        }

        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let value = bytes;
        let unitIndex = 0;

        while (value >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex++;
        }

        return value.toFixed(unitIndex === 0 ? 0 : 2) + ' ' + units[unitIndex];
    }

    printSummary() {
        if (!this.prevStats) {
            console.log('No statistics collected');
            return;
        }

        const elapsed = (Date.now() - this.startTime) / 1000;
        console.log('\n' + '='.repeat(50));
        console.log('MONITORING SUMMARY');
        console.log('='.repeat(50));
        console.log(`Interface: ${this.interface}`);
        console.log(`Duration: ${elapsed.toFixed(1)} seconds`);
        console.log(`Samples: ${this.sampleCount}`);
        
        if (this.alerts.length > 0) {
            console.log(`\nAlerts triggered: ${this.alerts.length}`);
            const alertTypes = {};
            this.alerts.forEach(alert => {
                const timeStr = alert.timestamp.toISOString().substring(11, 19);
                alertTypes[alert.type] = (alertTypes[alert.type] || 0) + 1;
                const value = alert.rate ? `${this.formatBytes(alert.rate)}/s` : `${alert.count} packets`;
                console.log(`  [${timeStr}] ${alert.type}: ${value}`);
            });
            
            console.log('\nAlert summary:');
            Object.entries(alertTypes).forEach(([type, count]) => {
                console.log(`  ${type}: ${count} times`);
            });
        } else {
            console.log('\nNo alerts triggered');
        }
        
        console.log(`\nFinal totals for ${this.interface}:`);
        console.log(`  TX: ${this.formatBytes(this.prevStats.txBytes)}`);
        console.log(`     Packets: ${this.prevStats.txPackets.toLocaleString()}`);
        console.log(`     Errors: ${this.prevStats.txErrors.toLocaleString()}`);
        console.log(`     Dropped: ${this.prevStats.txDropped.toLocaleString()}`);
        
        console.log(`  RX: ${this.formatBytes(this.prevStats.rxBytes)}`);
        console.log(`     Packets: ${this.prevStats.rxPackets.toLocaleString()}`);
        console.log(`     Errors: ${this.prevStats.rxErrors.toLocaleString()}`);
        console.log(`     Dropped: ${this.prevStats.rxDropped.toLocaleString()}`);
        
        const totalBytes = this.prevStats.txBytes + this.prevStats.rxBytes;
        const totalPackets = this.prevStats.txPackets + this.prevStats.rxPackets;
        const totalErrors = this.prevStats.txErrors + this.prevStats.rxErrors;
        const totalDropped = this.prevStats.txDropped + this.prevStats.rxDropped;
        
        console.log(`\nTOTALS:`);
        console.log(`  Data: ${this.formatBytes(totalBytes)}`);
        console.log(`  Packets: ${totalPackets.toLocaleString()}`);
        console.log(`  Errors: ${totalErrors.toLocaleString()}`);
        console.log(`  Dropped: ${totalDropped.toLocaleString()}`);
        
        if (elapsed > 0) {
            const avgTxRate = this.prevStats.txBytes / elapsed;
            const avgRxRate = this.prevStats.rxBytes / elapsed;
            console.log(`\nAVERAGE RATES:`);
            console.log(`  TX: ${this.formatBytes(avgTxRate)}/s`);
            console.log(`  RX: ${this.formatBytes(avgRxRate)}/s`);
            
            if (totalPackets > 0) {
                const avgPacketSize = totalBytes / totalPackets;
                console.log(`  Avg packet size: ${Math.round(avgPacketSize)} bytes`);
            }
            
            if (totalErrors > 0 && totalPackets > 0) {
                const errorRate = (totalErrors / totalPackets) * 100;
                console.log(`  Error rate: ${errorRate.toFixed(4)}%`);
            }
        }
    }

    exportToJson() {
        return {
            interface: this.interface,
            startTime: new Date(this.startTime).toISOString(),
            sampleCount: this.sampleCount,
            alerts: this.alerts.map(alert => ({
                ...alert,
                timestamp: alert.timestamp.toISOString()
            })),
            finalStats: this.prevStats,
            settings: {
                highTrafficThreshold: this.highTrafficThreshold,
                errorThreshold: this.errorThreshold,
                dropThreshold: this.dropThreshold,
                sampleInterval: this.sampleInterval
            }
        };
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
                const ifacePath = path.join(interfacesPath, iface);
                const stats = await fs.promises.stat(ifacePath);
                if (stats.isDirectory()) {
                    validInterfaces.push(iface);
                }
            } catch {
                continue;
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
    } catch (error) {
        return false;
    }
}

function validatePositiveNumber(value, name, min = 1) {
    const num = parseInt(value, 10);
    if (isNaN(num) || num < min) {
        throw new Error(`${name} must be a number >= ${min}`);
    }
    return num;
}

async function main() {
    const args = process.argv.slice(2);
    
    if (args.length < 1 || args.includes('--help') || args.includes('-h')) {
        console.log('Network Traffic Monitor');
        console.log('Usage: node network_monitor.js <interface> [duration_seconds]');
        console.log('\nOptions:');
        console.log('  --help, -h       Show this help message');
        console.log('  --list, -l       List available interfaces');
        console.log('  --threshold N    Set high traffic threshold in MB (default: 50)');
        console.log('  --errors N       Set error threshold (default: 1000)');
        console.log('  --drops N        Set dropped packet threshold (default: 100)');
        console.log('  --interval N     Set sample interval in ms (default: 1000)');
        console.log('  --json           Output summary in JSON format');
        console.log('\nExamples:');
        console.log('  node network_monitor.js eth0 60');
        console.log('  node network_monitor.js wlan0 --threshold 100 --errors 500');
        console.log('  node network_monitor.js --list');
        return;
    }

    if (args.includes('--list') || args.includes('-l')) {
        await listInterfaces();
        return;
    }

    const interfaceName = args[0];
    let duration = 0;
    let highTrafficThreshold = 50;
    let errorThreshold = 1000;
    let dropThreshold = 100;
    let sampleInterval = 1000;
    let outputJson = false;

    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--threshold' && args[i + 1]) {
            highTrafficThreshold = validatePositiveNumber(args[i + 1], 'Threshold', 1);
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
        } else if (args[i] === '--json') {
            outputJson = true;
        } else if (!isNaN(parseInt(args[i], 10))) {
            duration = validatePositiveNumber(args[i], 'Duration', 0);
        }
    }

    if (!await validateInterface(interfaceName)) {
        console.error(`Error: Interface '${interfaceName}' not found or not accessible`);
        console.log('Use --list to see available interfaces');
        process.exit(1);
    }

    const monitor = new NetworkMonitor(interfaceName, duration);
    monitor.highTrafficThreshold = highTrafficThreshold * 1024 * 1024;
    monitor.errorThreshold = errorThreshold;
    monitor.dropThreshold = dropThreshold;
    monitor.sampleInterval = sampleInterval;
    
    const sigintHandler = () => {
        console.log('\nStopping monitor...');
        monitor.stop();
        if (outputJson) {
            console.log(JSON.stringify(monitor.exportToJson(), null, 2));
        }
        process.exit(0);
    };

    process.on('SIGINT', sigintHandler);
    process.on('SIGTERM', sigintHandler);

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

module.exports = NetworkMonitor;
