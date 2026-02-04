# BIP39 V Implementation

## Implemented Methods

# Install

```v
v install sibkod.bip39
```

### Core Functions
```v
// Generate random entropy (128-256 bits, multiples of 32)
pub fn new_entropy(bit_size int) ![]u8

// Create mnemonic phrase from entropy
pub fn new_mnemonic(entropy []u8) !string

// Recover entropy from mnemonic phrase
pub fn entropy_from_mnemonic(mnemonic string) ![]u8

// Generate seed from mnemonic and password
pub fn new_seed(mnemonic string, password string) ![]u8

// Validate mnemonic phrase
pub fn is_mnemonic_valid(mnemonic string) bool
```

# Usage Examples
## Basic Example
```v

import sibkod.bip39

// Generate 12-word mnemonic phrase
entropy := bip39.new_entropy(128)!
mnemonic := bip39.new_mnemonic(entropy)!
println('Mnemonic: ${mnemonic}')

// Create seed
seed := bip39.new_seed(mnemonic, '')!
println('Seed (64 bytes): ${seed.hex()}')

// Validation
if bip39.is_mnemonic_valid(mnemonic) {
println('Mnemonic is valid')
}

// Recover entropy
recovered := bip39.entropy_from_mnemonic(mnemonic)!
println('Entropy recovered: ${entropy == recovered}')
```

## Different Entropy Sizes
```v

import sibkod.bip39

// 12 words - 128 bits
entropy12 := bip39.new_entropy(128)!
mnemonic12 := bip39.new_mnemonic(entropy12)!

// 15 words - 160 bits
entropy15 := bip39.new_entropy(160)!
mnemonic15 := bip39.new_mnemonic(entropy15)!

// 18 words - 192 bits
entropy18 := bip39.new_entropy(192)!
mnemonic18 := bip39.new_mnemonic(entropy18)!

// 21 words - 224 bits
entropy21 := bip39.new_entropy(224)!
mnemonic21 := bip39.new_mnemonic(entropy21)!

// 24 words - 256 bits
entropy24 := bip39.new_entropy(256)!
mnemonic24 := bip39.new_mnemonic(entropy24)!
```
