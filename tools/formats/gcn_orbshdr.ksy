meta:
  id: gcn_orbshdr
  endian: le
  license: CC0-1.0
    
instances:
  footer:
    pos: 80
    type: header
    
types:
  header:
    seq:
      - id: magic
        contents: 'OrbShdr'
      - id: unk1
        contents: [7]
      - id: type2
        type: b8
        enum: gcn_orbis_type
      - id: size
        type: u2
        
enums:
  gcn_orbis_type:
    0x41: gcn_orbis_ps
    0x45: gcn_orbis_vs
