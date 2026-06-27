import 'package:flutter_test/flutter_test.dart';
import 'package:lichen_mobile/models/message.dart';

void main() {
  group('Message', () {
    test('serializes to map', () {
      final msg = Message(
        id: 'test-123',
        contact: 'NODE-A',
        text: 'Hello',
        timestamp: DateTime.fromMillisecondsSinceEpoch(1700000000000),
        isOutgoing: true,
        state: MessageState.sent,
      );

      final map = msg.toMap();
      expect(map['id'], 'test-123');
      expect(map['contact'], 'NODE-A');
      expect(map['text'], 'Hello');
      expect(map['timestamp'], 1700000000000);
      expect(map['is_outgoing'], 1);
      expect(map['state'], MessageState.sent.index);
    });

    test('deserializes from map', () {
      final map = {
        'id': 'test-456',
        'contact': 'NODE-B',
        'text': 'World',
        'timestamp': 1700000001000,
        'is_outgoing': 0,
        'state': MessageState.delivered.index,
      };

      final msg = Message.fromMap(map);
      expect(msg.id, 'test-456');
      expect(msg.contact, 'NODE-B');
      expect(msg.text, 'World');
      expect(msg.isOutgoing, false);
      expect(msg.state, MessageState.delivered);
    });

    test('round-trips through serialization', () {
      final original = Message(
        id: 'round-trip',
        contact: 'NODE-X',
        text: 'Test message',
        timestamp: DateTime.now(),
        isOutgoing: false,
        state: MessageState.read,
      );

      final restored = Message.fromMap(original.toMap());
      expect(restored.id, original.id);
      expect(restored.contact, original.contact);
      expect(restored.text, original.text);
      expect(restored.isOutgoing, original.isOutgoing);
      expect(restored.state, original.state);
    });
  });
}
