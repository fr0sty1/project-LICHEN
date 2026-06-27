/// Message delivery states
enum MessageState {
  sending,   // spinner
  sent,      // single check
  delivered, // double check
  read,      // blue double check
  failed,    // red X, tap to retry
}

/// A chat message
class Message {
  final String id;
  final String contact;
  final String text;
  final DateTime timestamp;
  final bool isOutgoing;
  MessageState state;

  Message({
    required this.id,
    required this.contact,
    required this.text,
    required this.timestamp,
    required this.isOutgoing,
    this.state = MessageState.sending,
  });

  Map<String, dynamic> toMap() => {
    'id': id,
    'contact': contact,
    'text': text,
    'timestamp': timestamp.millisecondsSinceEpoch,
    'is_outgoing': isOutgoing ? 1 : 0,
    'state': state.index,
  };

  factory Message.fromMap(Map<String, dynamic> map) => Message(
    id: map['id'] as String,
    contact: map['contact'] as String,
    text: map['text'] as String,
    timestamp: DateTime.fromMillisecondsSinceEpoch(map['timestamp'] as int),
    isOutgoing: (map['is_outgoing'] as int) == 1,
    state: MessageState.values[map['state'] as int],
  );
}
