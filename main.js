const fs = require('fs');
const path = require('path');

class NetworkMonitor {
    constructor(interfaceName, duration = 0) {
        this.interface = interfaceName;
        this.duration = duration;
        this.startTime = Date.now();
        this.prevStats = null;
        this.alerts = [];
        this.sampleCount = 0;
    }

    async start() {
        if (!await this.interfaceExists()) {
            throw new Error(`Interface ${this.interface} not found`);
        }

        console.log(`Network Traffic Monitor - ${this.interface}`);
        console.log(`Duration: ${this.duration > 0 ? this.duration + ' seconds' : 'unlimited'}`);
        console.log('Press Ctrl+C to stop\n');

        this.prevStats = await this.getNetworkStats();
        
        this.monitorInterval = setInterval(async () => {
            await this.sample();
        }, 1000);

        if (this.duration > 0) {
            setTimeout(() => {
                this.stop();
            }, this.duration * 1000);
        }
    }

    stop() {
        clearInterval(this.monitorInterval);
        this.printSummary();
    }

    async sample() {
        const currentStats = await this.getNetworkStats();
        
        const txRate = currentStats.txBytes - this.prevStats.txBytes;
        const rxRate = currentStats.rxBytes - this.prevStats.rxBytes;
        const txPacketRate = currentStats.txPackets - this.prevStats.txPackets;
        const rxPacketRate = currentStats.rxPackets - this.prevStats.rxPackets;
        
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        
        console.log(`[${timestamp}] ${this.interface}`);
        console.log(`  TX: ${this.formatBytes(txRate).padStart(8)}/s (${txPacketRate.toString().padStart(5)} pkt/s) | Total: ${this.formatBytes(currentStats.txBytes)}`);
        console.log(`  RX: ${this.formatBytes(rxRate).padStart(8)}/s (${rxPacketRate.toString().padStart(5)} pkt/s) | Total: ${this.formatBytes(currentStats.rxBytes)}`);
        
        if (currentStats.txErrors > this.prevStats.txErrors || currentStats.rxErrors > this.prevStats.rxErrors) {
            console.log(`  ERRORS: TX=${currentStats.txErrors - this.prevStats.txErrors}, RX=${currentStats.rxErrors - this.prevStats.rxErrors}`);
        }
        
        if (currentStats.txDropped > this.prevStats.txDropped || currentStats.rxDropped > this.prevStats.rxDropped) {
            console.log(`  DROPPED: TX=${currentStats.txDropped - this.prevStats.txDropped}, RX=${currentStats.rxDropped - this.prevStats.rxDropped}`);
        }

        if (txRate > 50 * 1024 * 1024) {
            this.alerts.push({
                timestamp: new Date(),
                type: 'HIGH_TX',
                rate: txRate,
                interface: this.interface
            });
            console.log('  HIGH TX TRAFFIC DETECTED');
        }
        
        if (rxRate > 50 * 1024 * 1024) {
            this.alerts.push({
                timestamp: new Date(),
                type: 'HIGH_RX',
                rate: rxRate,
                interface: this.interface
            });
            console.log('  HIGH RX TRAFFIC DETECTED');
        }
        
        if (txRate === 0 && rxRate === 0) {
            console.log('  No network activity');
        }
        
        if (txRate > 0 || rxRate > 0) {
            const efficiency = (txRate + rxRate) / (txPacketRate + rxPacketRate + 1);
            if (efficiency > 0) {
                console.log(`  Avg packet size: ${Math.round(efficiency)} bytes`);
            }
        }

        console.log();

        this.prevStats = currentStats;
        this.sampleCount++;
    }

    async getNetworkStats() {
        const basePath = `/sys/class/net/${this.interface}/statistics`;
        
        const stats = {
            interface: this.interface,
            txBytes: await this.readSysFile(path.join(basePath, 'tx_bytes')),
            rxBytes: await this.readSysFile(path.join(basePath, 'rx_bytes')),
            txPackets: await this.readSysFile(path.join(basePath, 'tx_packets')),
            rxPackets: await this.readSysFile(path.join(basePath, 'rx_packets')),
            txErrors: await this.readSysFile(path.join(basePath, 'tx_errors')),
            rxErrors: await this.readSysFile(path.join(basePath, 'rx_errors')),
            txDropped: await this.readSysFile(path.join(basePath, 'tx_dropped')),
            rxDropped: await this.readSysFile(path.join(basePath, 'rx_dropped'))
        };
        
        return stats;
    }

    async readSysFile(filePath) {
        try {
            const data = await fs.promises.readFile(filePath, 'utf8');
            return parseInt(data.trim(), 10) || 0;
        } catch {
            return 0;
        }
    }

    async interfaceExists() {
        try {
            await fs.promises.access(`/sys/class/net/${this.interface}`);
            return true;
        } catch {
            return false;
        }
    }

    formatBytes(bytes) {
        const KB = 1024;
        const MB = KB * 1024;
        const GB = MB * 1024;
        const TB = GB * 1024;

        if (bytes >= TB) return (bytes / TB).toFixed(2) + ' TB';
        if (bytes >= GB) return (bytes / GB).toFixed(2) + ' GB';
        if (bytes >= MB) return (bytes / MB).toFixed(2) + ' MB';
        if (bytes >= KB) return (bytes / KB).toFixed(2) + ' KB';
        return bytes + ' B';
    }

    printSummary() {
        const elapsed = (Date.now() - this.startTime) / 1000;
        console.log('\n=== Monitoring Summary ===');
        console.log(`Duration: ${elapsed.toFixed(1)} seconds`);
        console.log(`Samples: ${this.sampleCount}`);
        
        if (this.alerts.length > 0) {
            console.log(`\nAlerts triggered: ${this.alerts.length}`);
            this.alerts.forEach(alert => {
                console.log(`  [${alert.timestamp.toISOString().substring(11, 19)}] ${alert.type}: ${this.formatBytes(alert.rate)}/s`);
            });
        }
        
        console.log(`\nFinal totals for ${this.interface}:`);
        console.log(`  TX: ${this.formatBytes(this.prevStats.txBytes)} (${this.prevStats.txPackets} packets, ${this.prevStats.txErrors} errors, ${this.prevStats.txDropped} dropped)`);
        console.log(`  RX: ${this.formatBytes(this.prevStats.rxBytes)} (${this.prevStats.rxPackets} packets, ${this.prevStats.rxErrors} errors, ${this.prevStats.rxDropped} dropped)`);
    }
}

async function listInterfaces() {
    try {
        const interfaces = await fs.promises.readdir('/sys/class/net');
        console.log('Available interfaces:');
        interfaces.forEach(iface => console.log(`  - ${iface}`));
        return interfaces;
    } catch (error) {
        console.log('Cannot list interfaces');
        return [];
    }
}

async function main() {
    const args = process.argv.slice(2);
    
    if (args.length < 1) {
        console.log('Usage: node network_monitor.js <interface> [duration_seconds]');
        await listInterfaces();
        return;
    }

    const interfaceName = args[0];
    const duration = args[1] ? parseInt(args[1], 10) : 0;

    const monitor = new NetworkMonitor(interfaceName, duration);
    
    process.on('SIGINT', () => {
        console.log('\nStopping monitor...');
        monitor.stop();
        process.exit(0);
    });

    try {
        await monitor.start();
    } catch (error) {
        console.error(error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = NetworkMonitor;
