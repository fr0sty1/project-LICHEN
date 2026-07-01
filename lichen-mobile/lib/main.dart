import 'package:flutter/material.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:provider/provider.dart';

import 'services/ble_connection.dart';
import 'services/message_store.dart';
import 'pages/chat_page.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final messageStore = MessageStore();
  await messageStore.init();
  runApp(LichenApp(messageStore: messageStore));
}

class LichenApp extends StatelessWidget {
  final MessageStore messageStore;

  const LichenApp({super.key, required this.messageStore});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => BleConnection()),
        ChangeNotifierProvider.value(value: messageStore),
      ],
      child: MaterialApp(
        title: 'LICHEN',
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(seedColor: Colors.green),
          useMaterial3: true,
        ),
        home: const ConnectionPage(),
      ),
    );
  }
}

class ConnectionPage extends StatefulWidget {
  const ConnectionPage({super.key});

  @override
  State<ConnectionPage> createState() => _ConnectionPageState();
}

class _ConnectionPageState extends State<ConnectionPage> {
  List<ScanResult> _scanResults = [];
  bool _isScanning = false;

  @override
  Widget build(BuildContext context) {
    final ble = context.watch<BleConnection>();

    return Scaffold(
      appBar: AppBar(
        title: const Text('LICHEN'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Column(
        children: [
          _buildConnectionStatus(ble),
          const Divider(),
          Expanded(child: _buildDeviceList(ble)),
        ],
      ),
      floatingActionButton: _buildActionButton(ble),
    );
  }

  Widget _buildConnectionStatus(BleConnection ble) {
    final (icon, color, text) = switch (ble.state) {
      ConnectionState.disconnected => (Icons.bluetooth_disabled, Colors.grey, 'Disconnected'),
      ConnectionState.scanning => (Icons.bluetooth_searching, Colors.blue, 'Scanning...'),
      ConnectionState.connecting => (Icons.bluetooth_connected, Colors.orange, 'Connecting...'),
      ConnectionState.connected => (Icons.bluetooth_connected, Colors.green, 'Connected'),
    };

    return Container(
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          Icon(icon, color: color, size: 32),
          const SizedBox(width: 16),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                text,
                style: Theme.of(context).textTheme.titleMedium?.copyWith(color: color),
              ),
              if (ble.device != null)
                Text(
                  ble.device!.platformName.isNotEmpty
                      ? ble.device!.platformName
                      : ble.device!.remoteId.str,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildDeviceList(BleConnection ble) {
    if (ble.state == ConnectionState.connected) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.check_circle, color: Colors.green, size: 64),
            const SizedBox(height: 16),
            Text(
              'Connected to LICHEN node',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 32),
            FilledButton.tonal(
              onPressed: () => ble.ping().then((ok) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text(ok ? 'Ping OK' : 'Ping failed')),
                );
              }),
              child: const Text('Ping'),
            ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => const ChatPage(contact: 'TEST-NODE'),
                ),
              ),
              child: const Text('Open Chat'),
            ),
          ],
        ),
      );
    }

    if (_scanResults.isEmpty && !_isScanning) {
      return const Center(
        child: Text('Tap scan to find LICHEN nodes'),
      );
    }

    return ListView.builder(
      itemCount: _scanResults.length,
      itemBuilder: (context, index) {
        final result = _scanResults[index];
        final name = result.device.platformName.isNotEmpty
            ? result.device.platformName
            : 'Unknown Device';

        return ListTile(
          leading: const Icon(Icons.bluetooth),
          title: Text(name),
          subtitle: Text(result.device.remoteId.str),
          trailing: Text('${result.rssi} dBm'),
          onTap: ble.state == ConnectionState.disconnected
              ? () => ble.connect(result.device)
              : null,
        );
      },
    );
  }

  Widget _buildActionButton(BleConnection ble) {
    if (ble.state == ConnectionState.connected) {
      return FloatingActionButton.extended(
        onPressed: () => ble.disconnect(),
        icon: const Icon(Icons.bluetooth_disabled),
        label: const Text('Disconnect'),
        backgroundColor: Colors.red.shade100,
      );
    }

    if (ble.state == ConnectionState.scanning) {
      return FloatingActionButton.extended(
        onPressed: () {
          ble.stopScan();
          setState(() => _isScanning = false);
        },
        icon: const Icon(Icons.stop),
        label: const Text('Stop'),
      );
    }

    if (ble.state == ConnectionState.connecting) {
      return const FloatingActionButton.extended(
        onPressed: null,
        icon: SizedBox(
          width: 24,
          height: 24,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
        label: Text('Connecting...'),
      );
    }

    return FloatingActionButton.extended(
      onPressed: () {
        setState(() {
          _scanResults = [];
          _isScanning = true;
        });
        ble.scan().listen((result) {
          setState(() {
            final idx = _scanResults.indexWhere(
              (r) => r.device.remoteId == result.device.remoteId,
            );
            if (idx >= 0) {
              _scanResults[idx] = result;
            } else {
              _scanResults.add(result);
            }
          });
        }).onDone(() {
          setState(() => _isScanning = false);
        });
      },
      icon: const Icon(Icons.bluetooth_searching),
      label: const Text('Scan'),
    );
  }
}
