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
    }

    sanitizeInterfaceName(name) {
        if (!name || typeof name !== 'string') {
            throw new Error('Interface name must be a non-empty string');
        }
        
        if (name.includes('/') || name.includes('..') || name.length > 64) {
            throw new Error('Invalid interface name');
        }
        
        if (!/^[a-zA-Z0-9\-_:.]+$/.test(name)) {
            throw new Error('Interface name contains invalid characters');
        }
        
        return name;
    }

    async start() {
        if (this.isRunning) {
            throw new Error('Monitor is already running');
        }

        if (!await this.interfaceExists()) {
            throw new Error(`Interface ${this.interface} not found`);
        }

        console.log(`Network Traffic Monitor - ${this.interface}`);
        console.log(`Duration: ${this.duration > 0 ? this.duration + ' seconds' : 'unlimited'}`);
        console.log('Press Ctrl+C to stop\n');

        try {
            this.prevStats = await this.getNetworkStats();
        } catch (error) {
            throw new Error(`Failed to get initial stats: ${error.message}`);
        }

        this.isRunning = true;
        this.startTime = Date.now();
        
        this.monitorInterval = setInterval(async () => {
            try {
                await this.sample();
            } catch (error) {
                console.error(`Sampling error: ${error.message}`);
            }
        }, 1000);

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

        const txRate = Math.max(0, currentStats.txBytes - this.prevStats.txBytes);
        const rxRate = Math.max(0, currentStats.rxBytes - this.prevStats.rxBytes);
        const txPacketRate = Math.max(0, currentStats.txPackets - this.prevStats.txPackets);
        const rxPacketRate = Math.max(0, currentStats.rxPackets - this.prevStats.rxPackets);
        
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        
        console.log(`[${timestamp}] ${this.interface}`);
        console.log(`  TX: ${this.formatBytes(txRate).padStart(8)}/s (${txPacketRate.toString().padStart(5)} pkt/s) | Total: ${this.formatBytes(currentStats.txBytes)}`);
        console.log(`  RX: ${this.formatBytes(rxRate).padStart(8)}/s (${rxPacketRate.toString().padStart(5)} pkt/s) | Total: ${this.formatBytes(currentStats.rxBytes)}`);
        
        const txErrorsDelta = Math.max(0, currentStats.txErrors - this.prevStats.txErrors);
        const rxErrorsDelta = Math.max(0, currentStats.rxErrors - this.prevStats.rxErrors);
        
        if (txErrorsDelta > 0 || rxErrorsDelta > 0) {
            console.log(`  ERRORS: TX=${txErrorsDelta}, RX=${rxErrorsDelta}`);
        }
        
        const txDroppedDelta = Math.max(0, currentStats.txDropped - this.prevStats.txDropped);
        const rxDroppedDelta = Math.max(0, currentStats.rxDropped - this.prevStats.rxDropped);
        
        if (txDroppedDelta > 0 || rxDroppedDelta > 0) {
            console.log(`  DROPPED: TX=${txDroppedDelta}, RX=${rxDroppedDelta}`);
        }

        const highTrafficThreshold = 50 * 1024 * 1024;
        if (txRate > highTrafficThreshold) {
            this.alerts.push({
                timestamp: new Date(),
                type: 'HIGH_TX',
                rate: txRate,
                interface: this.interface
            });
            console.log('  ⚠️  HIGH TX TRAFFIC DETECTED');
        }
        
        if (rxRate > highTrafficThreshold) {
            this.alerts.push({
                timestamp: new Date(),
                type: 'HIGH_RX',
                rate: rxRate,
                interface: this.interface
            });
            console.log('  ⚠️  HIGH RX TRAFFIC DETECTED');
        }
        
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

        for (const [statName, fileName] of Object.entries(statsFiles)) {
            const filePath = path.join(basePath, fileName);
            stats[statName] = await this.readSysFile(filePath);
        }
        
        return stats;
    }

    async readSysFile(filePath) {
        try {
            const resolvedPath = path.resolve(filePath);
            if (!resolvedPath.startsWith('/sys/class/net/')) {
                throw new Error('Invalid file path');
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
            return 0;
        }
    }

    async interfaceExists() {
        try {
            const interfacePath = `/sys/class/net/${this.interface}`;
            await fs.promises.access(interfacePath);
            
            const stats = await fs.promises.stat(interfacePath);
            return stats.isDirectory();
        } catch {
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
        console.log('\n=== Monitoring Summary ===');
        console.log(`Interface: ${this.interface}`);
        console.log(`Duration: ${elapsed.toFixed(1)} seconds`);
        console.log(`Samples: ${this.sampleCount}`);
        
        if (this.alerts.length > 0) {
            console.log(`\nAlerts triggered: ${this.alerts.length}`);
            this.alerts.forEach(alert => {
                const timeStr = alert.timestamp.toISOString().substring(11, 19);
                console.log(`  [${timeStr}] ${alert.type}: ${this.formatBytes(alert.rate)}/s`);
            });
        }
        
        console.log(`\nFinal totals for ${this.interface}:`);
        console.log(`  TX: ${this.formatBytes(this.prevStats.txBytes)} (${this.prevStats.txPackets} packets, ${this.prevStats.txErrors} errors, ${this.prevStats.txDropped} dropped)`);
        console.log(`  RX: ${this.formatBytes(this.prevStats.rxBytes)} (${this.prevStats.rxPackets} packets, ${this.prevStats.rxErrors} errors, ${this.prevStats.rxDropped} dropped)`);
        
        const totalBytes = this.prevStats.txBytes + this.prevStats.rxBytes;
        const totalPackets = this.prevStats.txPackets + this.prevStats.rxPackets;
        console.log(`  TOTAL: ${this.formatBytes(totalBytes)} (${totalPackets} packets)`);
    }
}

async function listInterfaces() {
    try {
        const interfacesPath = '/sys/class/net';
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
        
        console.log('Available interfaces:');
        validInterfaces.forEach(iface => console.log(`  - ${iface}`));
        return validInterfaces;
    } catch (error) {
        console.log('Cannot list interfaces:', error.message);
        return [];
    }
}

async function main() {
    const args = process.argv.slice(2);
    
    if (args.length < 1 || args.includes('--help') || args.includes('-h')) {
        console.log('Usage: node network_monitor.js <interface> [duration_seconds]');
        console.log('Options:');
        console.log('  --help, -h    Show this help message');
        console.log('  --list, -l    List available interfaces');
        await listInterfaces();
        return;
    }

    if (args.includes('--list') || args.includes('-l')) {
        await listInterfaces();
        return;
    }

    const interfaceName = args[0];
    const duration = args[1] ? parseInt(args[1], 10) : 0;

    if (isNaN(duration) || duration < 0) {
        console.error('Error: Duration must be a non-negative number');
        process.exit(1);
    }

    const monitor = new NetworkMonitor(interfaceName, duration);
    
    let sigintHandler;
    process.on('SIGINT', sigintHandler = () => {
        console.log('\nStopping monitor...');
        monitor.stop();
        process.exit(0);
    });

    process.on('SIGTERM', () => {
        console.log('\nReceived SIGTERM, stopping monitor...');
        monitor.stop();
        process.exit(0);
    });

    try {
        await monitor.start();
    } catch (error) {
        console.error('Error:', error.message);
        process.removeListener('SIGINT', sigintHandler);
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
