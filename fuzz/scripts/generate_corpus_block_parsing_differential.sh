#!/bin/bash

##############################################################################
# Corpus Generator for Block Parsing Differential Fuzzer
#
# Input Format:
#   Mode 0: [1 byte mode=0x00][32 bytes block_hash]
#   Mode 1: [1 byte mode=0x01][4 bytes height_i32_LE]
#   Mode 2: [1 byte mode=0x02][1 byte height_idx][1 byte verbosity]
##############################################################################

set -e

CORPUS_DIR="${1:-.}"
mkdir -p "$CORPUS_DIR"

echo "================================================"
echo "Generating Corpus: block_parsing_differential"
echo "================================================"

create_seed() {
    local name=$1
    local data=$2
    printf "$data" > "$CORPUS_DIR/$name"
    echo "$name"
}

# ============================================================================
# MODE 0: Block Hashes (getblock)
# ============================================================================
echo ""
echo "Mode 0: Block Hashes (32 bytes)"
echo "==============================="

create_seed "00_genesis" "\x00\x00\x00\x00\x00\x19\xd6\x68\x9c\x08\x5a\xe1\x65\x83\x1e\x93\x4f\xf7\x63\xae\x46\xa2\xa6\xc1\x72\xb3\xf1\xb6\x0a\x8c\xe2\x6f"
create_seed "00_block1" "\x00\x00\x00\x00\x83\x9a\x8e\x68\x86\xab\x59\x51\xd7\x6f\x41\x14\x75\x42\x8a\xfc\x90\x94\x7e\xe3\x20\x16\x1b\xbf\x18\xeb\x60\x48"
create_seed "00_block100" "\x00\x00\x00\x00\x06\xfe\x28\xc0\xab\x6f\x1b\x37\x2c\x1a\x6a\x24\x6a\xe6\x3f\x74\xf9\x31\xe8\x36\x5e\x15\xa0\x89\xc6\x8d\x61\x90"
create_seed "00_zeros" "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
create_seed "00_maxval" "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

# ============================================================================
# MODE 1: Block Heights (getblockhash)
# ============================================================================
echo ""
echo "Mode 1: Block Heights (i32 little-endian)"
echo "=========================================="

create_seed "01_height_0" "\x01\x00\x00\x00\x00"
create_seed "01_height_1" "\x01\x01\x00\x00\x00"
create_seed "01_height_10" "\x01\x0a\x00\x00\x00"
create_seed "01_height_100" "\x01\x64\x00\x00\x00"
create_seed "01_height_1000" "\x01\xe8\x03\x00\x00"
create_seed "01_height_10000" "\x01\x10\x27\x00\x00"
create_seed "01_height_100000" "\x01\xa0\x86\x01\x00"
create_seed "01_height_neg1" "\x01\xff\xff\xff\xff"
create_seed "01_height_max" "\x01\xff\xff\xff\x7f"

# ============================================================================
# MODE 2: Height + Verbosity
# ============================================================================
echo ""
echo "Mode 2: Height+Verbosity Combinations"
echo "====================================="

create_seed "02_h0_v0" "\x02\x00\x00"
create_seed "02_h0_v1" "\x02\x00\x01"
create_seed "02_h1_v0" "\x02\x01\x00"
create_seed "02_h1_v1" "\x02\x01\x01"
create_seed "02_h100_v0" "\x02\x64\x00"
create_seed "02_h100_v1" "\x02\x64\x01"
create_seed "02_h255_v0" "\x02\xff\x00"
create_seed "02_h255_v1" "\x02\xff\x01"

echo ""
echo "Corpus generation complete: $(find "$CORPUS_DIR" -type f | wc -l) files"
