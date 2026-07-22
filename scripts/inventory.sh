#!/usr/bin/env bash
# LICHEN Sales Inventory Tracker
# Usage: ./inventory.sh record <serial> <eui64> <price> <method> [note]
#        ./inventory.sh list
#        ./inventory.sh total

set -euo pipefail

INVENTORY_FILE="${INVENTORY_FILE:-lichen-sales.csv}"

init_inventory() {
  if [[ ! -f "$INVENTORY_FILE" ]]; then
    mkdir -p "$(dirname "$INVENTORY_FILE")"
    echo "timestamp,serial,eui64,price,payment_method,buyer_note" > "$INVENTORY_FILE"
    echo "Initialized inventory at $INVENTORY_FILE"
  fi
}

record_sale() {
  init_inventory
  local serial="${1:-}" eui="${2:-}" price="${3:-}" method="${4:-}" note="${5:-}"
  if [[ -z "$serial" || -z "$eui" || -z "$price" || -z "$method" ]]; then
    echo "Error: missing required args" >&2
    return 1
  fi
  local ts
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf '%s,%s,%s,%s,%s,"%s"\n' "$ts" "$serial" "$eui" "$price" "$method" "$note" >> "$INVENTORY_FILE"
  echo "Sale recorded for $serial. Total sales: $(wc -l < "$INVENTORY_FILE")"
}

list_inventory() {
  init_inventory
  echo "Current LICHEN Sales Inventory:"
  column -s, -t "$INVENTORY_FILE" 2>/dev/null || cat "$INVENTORY_FILE"
}

total_sales() {
  init_inventory
  local count=$(( $(wc -l < "$INVENTORY_FILE") - 1 ))
  echo "Total units sold: $count"
}

case "$1" in
  record) record_sale "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" ;;
  list) list_inventory ;;
  total) total_sales ;;
  *) 
    echo "LICHEN Sales Inventory"
    echo "Usage:"
    echo "  $0 record <serial> <eui64> <price> <method> [note]"
    echo "  $0 list"
    echo "  $0 total"
    exit 1
    ;;
esac
