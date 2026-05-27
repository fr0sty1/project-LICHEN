<!-- Part of LICHEN Protocol Specification -->

# Appendix B: RPL Configuration

## B.1. Objective Function

**MRHOF (Minimum Rank with Hysteresis Objective Function):**

```
ETX(link) = transmissions / successes
PathETX = sum(ETX(link)) for all links to root
Rank = (PathETX * 128) + MinHopRankIncrease
```

## B.2. Configuration Option Values

| Parameter | Value |
|-----------|-------|
| RPLInstanceID | 0 (default instance) |
| Mode of Operation | Non-Storing (MOP=1) |
| MinHopRankIncrease | 256 |
| MaxRankIncrease | 2048 |
| Default Lifetime | 30 minutes |
| Lifetime Unit | 60 seconds |

---

[← Previous: Appendix A](appendix-schc.md) | [Index](README.md) | [Next: Appendix C-E →](appendix-misc.md)
