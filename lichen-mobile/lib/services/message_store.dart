import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart';

import '../models/message.dart';

/// Local message storage using SQLite
class MessageStore extends ChangeNotifier {
  Database? _db;
  final _messagesController = StreamController<Message>.broadcast();

  /// Stream of incoming messages
  Stream<Message> get incoming => _messagesController.stream;

  Future<void> init() async {
    final path = join(await getDatabasesPath(), 'lichen_messages.db');
    _db = await openDatabase(
      path,
      version: 1,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE messages (
            id TEXT PRIMARY KEY,
            contact TEXT NOT NULL,
            text TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            is_outgoing INTEGER NOT NULL,
            state INTEGER NOT NULL
          )
        ''');
        await db.execute('CREATE INDEX idx_contact ON messages(contact)');
      },
    );
  }

  /// Save a message
  Future<void> save(Message msg) async {
    await _db?.insert(
      'messages',
      msg.toMap(),
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
    notifyListeners();
  }

  /// Update message state
  Future<void> updateState(String id, MessageState state) async {
    await _db?.update(
      'messages',
      {'state': state.index},
      where: 'id = ?',
      whereArgs: [id],
    );
    notifyListeners();
  }

  /// Get messages for a contact, newest first
  Future<List<Message>> getMessages(String contact) async {
    final rows = await _db?.query(
      'messages',
      where: 'contact = ?',
      whereArgs: [contact],
      orderBy: 'timestamp DESC',
    );
    return rows?.map((m) => Message.fromMap(m)).toList() ?? [];
  }

  /// Get most recent message per contact for list view
  Future<List<Message>> getConversations() async {
    final rows = await _db?.rawQuery('''
      SELECT * FROM messages
      WHERE id IN (
        SELECT id FROM messages m1
        WHERE timestamp = (
          SELECT MAX(timestamp) FROM messages m2
          WHERE m1.contact = m2.contact
        )
      )
      ORDER BY timestamp DESC
    ''');
    return rows?.map((m) => Message.fromMap(m)).toList() ?? [];
  }

  /// Add an incoming message
  void receiveMessage(Message msg) {
    save(msg);
    _messagesController.add(msg);
  }

  @override
  void dispose() {
    _messagesController.close();
    _db?.close();
    super.dispose();
  }
}
