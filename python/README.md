# LICHEN Python Prototype

Python implementation of the LICHEN mesh networking stack for protocol validation.

## Setup

```bash
cd python
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Structure

```
src/lichen/
├── sim/      # Wireless channel simulator
├── radio/    # Radio abstraction layer
└── link/     # Link layer (frames, signatures, replay protection)
```

## Running the Simulator

```bash
lichen-sim --node-port 4444 --api-port 4445
```

## Interactive TUI Node

Connect an interactive terminal node to a running simulation:

```bash
# Start the simulator in one terminal
lichen-sim --node-port 4444 --api-port 4445

# In another terminal, launch the TUI
lichen-tui --host localhost --port 4444 --sim default --node mynode
```

**Keyboard shortcuts:**
- `c` — Connect to simulator
- `t` — Focus transmit input
- `r` — Start receive
- `d` — Disconnect
- `q` — Quit

**Transmit:** Enter hex (`48656c6c6f`) or text (`hello`) and press Enter or click Send.

**Receive:** Set timeout in ms and click Start Receive. Results appear in the event log.

## Testing

```bash
pytest
```

## License

GPL-3.0-or-later
