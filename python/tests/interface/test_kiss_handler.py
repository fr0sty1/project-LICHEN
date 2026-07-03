"""Tests for KISS command handler."""


from lichen.interface.kiss import (
    DefaultKissConfig,
    KissCommand,
    KissFrame,
    KissHandler,
    kiss_decode,
)


class TestKissHandlerDataCommand:
    def test_data_frame_calls_tx_callback(self):
        received = []
        handler = KissHandler(on_tx_frame=lambda port, data: received.append((port, data)))

        frame = KissFrame(port=0, command=KissCommand.DATA, data=b"hello")
        handler.handle(frame)

        assert received == [(0, b"hello")]

    def test_data_frame_no_callback_ok(self):
        handler = KissHandler()
        frame = KissFrame(port=0, command=KissCommand.DATA, data=b"hello")
        result = handler.handle(frame)
        assert result is None

    def test_data_frame_empty_payload(self):
        received = []
        handler = KissHandler(on_tx_frame=lambda port, data: received.append((port, data)))

        frame = KissFrame(port=0, command=KissCommand.DATA, data=b"")
        handler.handle(frame)

        assert received == [(0, b"")]

    def test_data_frame_includes_port(self):
        received = []
        handler = KissHandler(on_tx_frame=lambda port, data: received.append((port, data)))

        frame = KissFrame(port=3, command=KissCommand.DATA, data=b"test")
        handler.handle(frame)

        assert received == [(3, b"test")]


class TestKissHandlerConfigCommands:
    def test_txdelay_sets_config(self):
        config = DefaultKissConfig()
        handler = KissHandler(config=config)

        frame = KissFrame(port=0, command=KissCommand.TXDELAY, data=bytes([100]))
        handler.handle(frame)

        assert config.txdelay_ms == 100

    def test_persistence_sets_config(self):
        config = DefaultKissConfig()
        handler = KissHandler(config=config)

        frame = KissFrame(port=0, command=KissCommand.PERSISTENCE, data=bytes([128]))
        handler.handle(frame)

        assert config.persistence == 128

    def test_slottime_sets_config(self):
        config = DefaultKissConfig()
        handler = KissHandler(config=config)

        frame = KissFrame(port=0, command=KissCommand.SLOTTIME, data=bytes([20]))
        handler.handle(frame)

        assert config.slottime_ms == 20

    def test_txtail_sets_config(self):
        config = DefaultKissConfig()
        handler = KissHandler(config=config)

        frame = KissFrame(port=0, command=KissCommand.TXTAIL, data=bytes([15]))
        handler.handle(frame)

        assert config.txtail_ms == 15

    def test_fullduplex_true(self):
        config = DefaultKissConfig()
        handler = KissHandler(config=config)

        frame = KissFrame(port=0, command=KissCommand.FULLDUPLEX, data=bytes([1]))
        handler.handle(frame)

        assert config.fullduplex is True

    def test_fullduplex_false(self):
        config = DefaultKissConfig()
        config.fullduplex = True
        handler = KissHandler(config=config)

        frame = KissFrame(port=0, command=KissCommand.FULLDUPLEX, data=bytes([0]))
        handler.handle(frame)

        assert config.fullduplex is False

    def test_config_empty_data_ignored(self):
        config = DefaultKissConfig()
        original = config.txdelay_ms
        handler = KissHandler(config=config)

        frame = KissFrame(port=0, command=KissCommand.TXDELAY, data=b"")
        handler.handle(frame)

        assert config.txdelay_ms == original


class TestKissHandlerReturnCommand:
    def test_return_sets_exited(self):
        handler = KissHandler()
        assert handler.exited is False

        frame = KissFrame(port=0, command=KissCommand.RETURN, data=b"")
        handler.handle(frame)

        assert handler.exited is True

    def test_return_calls_callback(self):
        called = []
        handler = KissHandler(on_exit=lambda: called.append(True))

        frame = KissFrame(port=0, command=KissCommand.RETURN, data=b"")
        handler.handle(frame)

        assert called == [True]

    def test_after_exit_frames_ignored(self):
        received = []
        handler = KissHandler(on_tx_frame=lambda port, data: received.append((port, data)))

        handler.handle(KissFrame(port=0, command=KissCommand.RETURN, data=b""))
        handler.handle(KissFrame(port=0, command=KissCommand.DATA, data=b"ignored"))

        assert received == []

    def test_reset_clears_exited(self):
        handler = KissHandler()
        handler.handle(KissFrame(port=0, command=KissCommand.RETURN, data=b""))
        assert handler.exited is True

        handler.reset()
        assert handler.exited is False


class TestKissHandlerPortFilter:
    def test_port_filter_accepts_matching(self):
        received = []
        handler = KissHandler(
            on_tx_frame=lambda port, data: received.append((port, data)),
            port_filter=2,
        )

        frame = KissFrame(port=2, command=KissCommand.DATA, data=b"yes")
        handler.handle(frame)

        assert received == [(2, b"yes")]

    def test_port_filter_rejects_nonmatching(self):
        received = []
        handler = KissHandler(
            on_tx_frame=lambda port, data: received.append((port, data)),
            port_filter=2,
        )

        frame = KissFrame(port=0, command=KissCommand.DATA, data=b"no")
        handler.handle(frame)

        assert received == []

    def test_no_port_filter_accepts_all(self):
        received = []
        handler = KissHandler(on_tx_frame=lambda port, data: received.append((port, data)))

        for port in [0, 5, 15]:
            handler.handle(KissFrame(port=port, command=KissCommand.DATA, data=bytes([port])))

        assert len(received) == 3


class TestKissHandlerRxFrame:
    def test_rx_frame_encodes_data(self):
        handler = KissHandler()
        encoded = handler.rx_frame(b"test")

        frame = kiss_decode(encoded)
        assert frame.port == 0
        assert frame.command == KissCommand.DATA
        assert frame.data == b"test"

    def test_rx_frame_with_port(self):
        handler = KissHandler()
        encoded = handler.rx_frame(b"test", port=3)

        frame = kiss_decode(encoded)
        assert frame.port == 3

    def test_rx_frame_escapes_special_bytes(self):
        handler = KissHandler()
        payload = bytes([0xC0, 0xDB])
        encoded = handler.rx_frame(payload)

        frame = kiss_decode(encoded)
        assert frame.data == payload


class TestKissHandlerUnknownCommand:
    def test_unknown_command_ignored(self):
        handler = KissHandler()
        # Command 6 (SetHardware) is TNC-specific, should be ignored
        frame = KissFrame(port=0, command=6, data=b"whatever")
        result = handler.handle(frame)
        assert result is None


class TestDefaultKissConfig:
    def test_default_values(self):
        config = DefaultKissConfig()
        assert config.txdelay_ms == 50
        assert config.persistence == 63
        assert config.slottime_ms == 10
        assert config.txtail_ms == 10
        assert config.fullduplex is False

    def test_values_settable(self):
        config = DefaultKissConfig()
        config.txdelay_ms = 200
        config.persistence = 255
        config.slottime_ms = 5
        config.txtail_ms = 20
        config.fullduplex = True

        assert config.txdelay_ms == 200
        assert config.persistence == 255
        assert config.slottime_ms == 5
        assert config.txtail_ms == 20
        assert config.fullduplex is True
