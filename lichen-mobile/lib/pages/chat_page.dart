import 'dart:math';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/message.dart';
import '../services/message_store.dart';

/// Chat page with a contact
class ChatPage extends StatefulWidget {
  final String contact;

  const ChatPage({super.key, required this.contact});

  @override
  State<ChatPage> createState() => _ChatPageState();
}

class _ChatPageState extends State<ChatPage> {
  final _controller = TextEditingController();
  final _scrollController = ScrollController();
  List<Message> _messages = [];

  @override
  void initState() {
    super.initState();
    _loadMessages();
  }

  Future<void> _loadMessages() async {
    final store = context.read<MessageStore>();
    final msgs = await store.getMessages(widget.contact);
    setState(() => _messages = msgs.reversed.toList());
  }

  Future<void> _sendMessage() async {
    final text = _controller.text.trim();
    if (text.isEmpty) return;

    final store = context.read<MessageStore>();
    final msg = Message(
      id: '${DateTime.now().millisecondsSinceEpoch}-${Random().nextInt(10000)}',
      contact: widget.contact,
      text: text,
      timestamp: DateTime.now(),
      isOutgoing: true,
      state: MessageState.sending,
    );

    _controller.clear();
    await store.save(msg);
    await _loadMessages();
    _scrollToBottom();

    // Simulate send/ack (replace with real CoAP later)
    await Future.delayed(const Duration(milliseconds: 500));
    await store.updateState(msg.id, MessageState.sent);
    await _loadMessages();

    // Simulate delivery ack
    await Future.delayed(const Duration(seconds: 1));
    await store.updateState(msg.id, MessageState.delivered);
    await _loadMessages();
  }

  Future<void> _retryMessage(Message msg) async {
    final store = context.read<MessageStore>();
    await store.updateState(msg.id, MessageState.sending);
    await _loadMessages();

    // Simulate retry
    await Future.delayed(const Duration(milliseconds: 500));
    await store.updateState(msg.id, MessageState.sent);
    await _loadMessages();
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOut,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.contact),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Column(
        children: [
          Expanded(
            child: ListView.builder(
              controller: _scrollController,
              padding: const EdgeInsets.all(8),
              itemCount: _messages.length,
              itemBuilder: (context, index) => _buildBubble(_messages[index]),
            ),
          ),
          _buildInputBar(),
        ],
      ),
    );
  }

  Widget _buildBubble(Message msg) {
    final isOut = msg.isOutgoing;
    return Align(
      alignment: isOut ? Alignment.centerRight : Alignment.centerLeft,
      child: GestureDetector(
        onTap: msg.state == MessageState.failed ? () => _retryMessage(msg) : null,
        child: Container(
          margin: const EdgeInsets.symmetric(vertical: 4),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          constraints: BoxConstraints(
            maxWidth: MediaQuery.of(context).size.width * 0.75,
          ),
          decoration: BoxDecoration(
            color: isOut ? Colors.blue.shade100 : Colors.grey.shade200,
            borderRadius: BorderRadius.circular(16),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text(msg.text),
              const SizedBox(height: 4),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    _formatTime(msg.timestamp),
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Colors.grey.shade600,
                    ),
                  ),
                  if (isOut) ...[
                    const SizedBox(width: 4),
                    _buildStateIndicator(msg.state),
                  ],
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStateIndicator(MessageState state) {
    return switch (state) {
      MessageState.sending => const SizedBox(
        width: 12, height: 12,
        child: CircularProgressIndicator(strokeWidth: 1.5),
      ),
      MessageState.sent => const Icon(Icons.check, size: 14, color: Colors.grey),
      MessageState.delivered => const Icon(Icons.done_all, size: 14, color: Colors.grey),
      MessageState.read => const Icon(Icons.done_all, size: 14, color: Colors.blue),
      MessageState.failed => const Icon(Icons.error_outline, size: 14, color: Colors.red),
    };
  }

  String _formatTime(DateTime dt) {
    return '${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}';
  }

  Widget _buildInputBar() {
    return SafeArea(
      child: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: Theme.of(context).scaffoldBackgroundColor,
          border: Border(top: BorderSide(color: Colors.grey.shade300)),
        ),
        child: Row(
          children: [
            Expanded(
              child: TextField(
                controller: _controller,
                decoration: const InputDecoration(
                  hintText: 'Message',
                  border: OutlineInputBorder(),
                  contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                ),
                textInputAction: TextInputAction.send,
                onSubmitted: (_) => _sendMessage(),
              ),
            ),
            const SizedBox(width: 8),
            IconButton.filled(
              onPressed: _sendMessage,
              icon: const Icon(Icons.send),
            ),
          ],
        ),
      ),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    _scrollController.dispose();
    super.dispose();
  }
}
