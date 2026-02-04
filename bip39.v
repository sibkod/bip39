module bip39

import crypto.rand
import crypto.sha256
import crypto.sha512
import crypto.pbkdf2
import encoding.binary
import math.big

const last_11_bits_mask = big.integer_from_u64(0x7FF)
const shift_11_bits_mask = big.integer_from_u64(2048)
const big_one = big.integer_from_u64(1)
const big_two = big.integer_from_u64(2)

const word_length_checksum_masks = {
	12: big.integer_from_u64(0x0F)
	15: big.integer_from_u64(0x1F)
	18: big.integer_from_u64(0x3F)
	21: big.integer_from_u64(0x7F)
	24: big.integer_from_u64(0xFF)
}

const word_length_checksum_shifts = {
	12: big.integer_from_u64(16)
	15: big.integer_from_u64(8)
	18: big.integer_from_u64(4)
	21: big.integer_from_u64(2)
}

fn validate_entropy_bit_size(bit_size int) ! {
	if bit_size % 32 != 0 || bit_size < 128 || bit_size > 256 {
		return error('entropy length must be 128–256 bits and multiple of 32')
	}
}

pub fn new_entropy(bit_size int) ![]u8 {
	validate_entropy_bit_size(bit_size)!

	entropy := rand.read(bit_size) or { return error('failed to generate entropy') }
	return entropy[..bit_size / 8]
}

fn compute_checksum(data []u8) []u8 {
	return sha256.sum(data)
}

fn add_checksum(data []u8) []u8 {
	hash := compute_checksum(data)
	first_checksum_byte := hash[0]

	checksum_bit_length := data.len / 4

	mut data_big := big.integer_from_bytes(data)

	for i in 0 .. checksum_bit_length {
		data_big = data_big * big_two

		if (first_checksum_byte & (1 << u8(7 - i))) > 0 {
			data_big = data_big.bitwise_or(big_one)
		}
	}
	res, _ := data_big.bytes()
	return res
}

fn pad_byte_slice(slice []u8, length int) []u8 {
	if slice.len >= length {
		return slice.clone()
	}

	mut out := []u8{len: length}
	offset := length - slice.len

	for i in 0 .. slice.len {
		out[offset + i] = slice[i]
	}

	return out
}

fn split_mnemonic_words(mnemonic string) ![]string {
	words := mnemonic.trim_space().split(' ')

	if words.len % 3 != 0 || words.len < 12 || words.len > 24 {
		return error('invalid mnemonic')
	}

	return words
}

pub fn new_mnemonic(entropy []u8) !string {
	entropy_bit_length := entropy.len * 8
	checksum_bit_length := entropy_bit_length / 32
	sentence_length := (entropy_bit_length + checksum_bit_length) / 11

	validate_entropy_bit_size(entropy_bit_length)!

	checksummed_entropy := add_checksum(entropy)

	mut entropy_int := big.integer_from_bytes(checksummed_entropy)

	mut words := []string{len: sentence_length}

	for i := (sentence_length - 1); i >= 0; i-- {
		word := entropy_int.bitwise_and(last_11_bits_mask)
		entropy_int = entropy_int / shift_11_bits_mask
		w, _ := word.bytes()
		word_bytes := pad_byte_slice(w, 2)

		word_index := u16(word_bytes[0]) << 8 | u16(word_bytes[1])

		if word_index >= english_words.len {
			return error('word index out of range')
		}

		words[i] = english_words[word_index]
	}

	return words.join(' ')
}

pub fn entropy_from_mnemonic(mnemonic string) ![]u8 {
	words := split_mnemonic_words(mnemonic)!

	mut word_map := map[string]int{}
	for i, word in english_words {
		word_map[word] = i
	}

	mut b := big.zero_int

	for word in words {
		index := word_map[word] or { return error('word not found in wordlist') }

		mut word_bytes := []u8{len: 2}
		binary.big_endian_put_u16(mut word_bytes, u16(index))

		index_big := big.integer_from_bytes(word_bytes)

		b = b * shift_11_bits_mask
		b = b.bitwise_or(index_big)
	}

	checksum_mask := word_length_checksum_masks[words.len] or { return error('invalid mnemonic') }

	mut checksum := b.bitwise_and(checksum_mask)

	checksum_mask_plus_one := checksum_mask + big_one
	b = b / checksum_mask_plus_one

	expected_length := words.len / 3 * 4
	k, _ := b.bytes()
	entropy := pad_byte_slice(k, expected_length)

	hash := compute_checksum(entropy)
	mut entropy_checksum := big.integer_from_u64(u64(hash[0]))

	if words.len != 24 {
		checksum_shift := word_length_checksum_shifts[words.len] or {
			return error('invalid mnemonic')
		}
		entropy_checksum = entropy_checksum / checksum_shift
	}

	if checksum != entropy_checksum {
		return error('checksum incorrect')
	}

	return entropy
}

pub fn new_seed(mnemonic string, password string) ![]u8 {
	salt := 'mnemonic${password}'
	return pbkdf2.key(mnemonic.bytes(), salt.bytes(), 2048, 64, sha512.new())!
}

pub fn is_mnemonic_valid(mnemonic string) bool {
	_ := entropy_from_mnemonic(mnemonic) or { return false }
	return true
}
