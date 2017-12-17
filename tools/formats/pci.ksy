meta:
  id: pci
  endian: le
  license: CC0-1.0

seq:
  - id: header
    type: header
instances:
  capabilities:
    pos: header.cap_ptr
    type: capability

types:
  header:
    seq:
      - id: vendor_id
        type: u2
      - id: device_id
        type: u2
      - id: command_reg
        type: u2
      - id: status_reg
        type: u2
      - id: revision_id
        type: u1
      - id: class_code
        size: 3
      - id: cache_line
        type: u1
      - id: latency_timer
        type: u1
      - id: header_type
        type: u1
      - id: bist
        type: u1
      - id: bar
        type: bar
        repeat: expr
        repeat-expr: 6
      - id: cardbus_cis_ptr
        type: u4
      - id: subsystem_vendor_id
        type: u2
      - id: subsystem_device_id
        type: u2
      - id: expansion_rom_addr
        type: u4
      - id: cap_ptr
        type: u1
      - size: 7
      - id: irq_line
        type: u1
      - id: irq_pin
        type: u1
      - id: min_gnt
        type: u1
      - id: max_gnt
        type: u1
  bar:
    seq:
      - id: value
        type: u4
    instances:
      type:
        value: value & 1
      address:
        value: value & 0xFFFFFFFE
    doc: Base Address Register
  
  capability:
    seq:
      - id: id
        type: u1
      - id: next
        type: u1
    instances:
      capabilities:
        pos: next
        type: capability

