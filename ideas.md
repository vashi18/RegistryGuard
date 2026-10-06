# RegistryGuard design direction

## Theme

**Midnight SOC console**: a calm, serious operations surface for reviewing endpoint telemetry without making uncertain detections look like confirmed breaches.

## Core principles

1. Make the state of the monitor obvious in every view.
2. Use severity color as a secondary cue; pair it with clear text and icons.
3. Put evidence before interpretation: old value, new value, location, timestamp, and path signals are always visible.
4. Treat the dashboard as a review workflow, not a decorative analytics wall.

## Visual system

- Canvas: near-black navy with slate panels and a subtle blue grid texture.
- Accent: electric cyan for active telemetry and links.
- Warning: amber for attention and review-needed states.
- Risk: vivid red for HIGH/CRITICAL, balanced by neutral labels.
- Healthy: mint green for online/active states.
- Layout: persistent navigation rail, responsive content grid, compact table rows, monospace technical fields.
- Interaction: short 160ms transitions, focus rings, no unnecessary motion.
- Typography: Inter/system UI for interface copy; ui-monospace for hashes, paths, PIDs and evidence.
- Brand voice: direct, evidence-led, careful about uncertainty.
- Wordmark: REGISTRYGUARD in uppercase with a shield/keyhole symbol.
- Signature color: #55D6FF.

## Brand mark

A flat filled shield with a negative-space keyhole and a small cyan telemetry tick. The same mark appears in the square icon, header, and favicon. The square icon uses an opaque full-bleed navy background with no rounded outer mask.
