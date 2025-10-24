# bitcoin_hd_wallet_keys.py
# -------------------------
#
# Python script to display individual keys within a Bitcoin heirarchical deterministic (HD) wallet. 
# Keys are selected via BIP32 derivation paths. The HD wallet is specified by a mnemonic sentence and a passphrase.
# Conforms to BIP32, BIP39, BIP43, BIP44, BIP49, BIP84 for coin_type' values of 0' or 1' (ie. resp. Bitcoin 
# mainnet/testnet registered coin types as per BIP44). When the derivation path is detected to have type BIP44, BIP49,
# or BIP84 the user specified testnet flag is overridden to a value of True/False for coin_type' of 1'/0' resp.
# Derivation path types which have the form of BIP44, BIP49, or BIP84 but which have coin_type' value other than 0'
# or 1' are classed as CUSTOM type (see below) so they are just treated as arbitrary user defined derivation paths.
#
# The term 'parent key' of an HD key means the whole derivation path except the rightmost derivation (this is undefined 
# for the master HD keys 'm' and 'M'). For example key m/49'/0'/50'/0/4 has parent m/49'/0'/50'/0 and so is BIP49 type,
# whereas m/49'/0'/50'/0/4/3 has parent m/49'/0'/50'/0/4 and so is not BIP49 type.
#
# Works in two modes :
# - single key mode (with -s switch)
# - range of keys mode (with -r switch)
# In single key mode private keys, addresses, extended private keys, and extended public keys are displayed for private key 
# derivation paths (commencing 'm'), and addresses and extended public keys are displayed for public key derivation paths 
# (commencing 'M').
# In range of keys mode, for a consecutive range of child keys under a specified parent key, addresses and private keys 
# are displayed for private key derivation paths (commencing 'm') and addresses are displayed for public key derivation 
# paths (commencing 'M').
#
# Addresses are displayed in either P2PKH, P2SH-P2WPKH, or P2WPKH format depending on the type of the parent key (the
# parent key types defined are CUSTOM, BIP44, BIP49, or BIP84). For CUSTOM and BIP44 the address type is P2PKH, for BIP49 
# the address type is P2SH-P2WPKH, and for BIP84 the address type is P2WPKH.
#
# Private keys are displayed in WIF compressed private key format.
#
# Extended private keys and extended public keys use the 'x', 'y', or 'z' (or resp. 't', 'u', 'v' for testnet) prefix 
# depending on the parent key type, in accordance with BIP32/BIP44, BIP49, and BIP84 resp. An option is available in 
# single key mode to override the x/y/z prefix.
#
# The definitions which are used of the parent derivation path types (ie. parent key types) BIP44, BIP49, and BIP84 are
# as follows :-
# BIP44 derivation path type : of form p/44'/coin_type'/account'/change
# BIP49 derivation path type : of form p/49'/coin_type'/account'/change
# BIP84 derivation path type : of form p/84'/coin_type'/account'/change
# where in each case p is either 'm' or 'M', coin_type' is 0' or 1' (ie. resp. Bitcoin mainnet/testnet registered coin 
# types as per BIP44), account' is any valid hardened child index, and 'change' is a non-hardened child index taking 
# the value 0 or 1.
# Any other form of derivation path is classed as 'CUSTOM', including the above BIP44, BIP49, BIP84 forms when the 
# coin_type' is not 0' or 1'. So for example key m/49'/0'/50'/0/4 has type BIP49, m/49'/0'/50'/0/4/3 has type CUSTOM,
# m/49'/0'/50'/2/4 has type CUSTOM, m/49'/2'/50'/0/4 has type CUSTOM, and m/85'/0'/50'/0/4 has type CUSTOM.
#
# A testnet flag may be specified which produces private keys, addresses, extended private keys, and extended public keys 
# with the testnet prefixes rather than the mainnet prefixes, though note the testnet flag override described above.
# 
# Usage :-
# Single key mode :
# python bitcoin_hd_wallet_keys.py -s <mnemonic_sentence> <passphrase> <derivation_path> <testnet_flag>
# or
# python bitcoin_hd_wallet_keys.py -s <mnemonic_sentence> <passphrase> <derivation_path> <ext_key_prefix_override> <testnet_flag>
# Range of keys mode :
# python bitcoin_hd_wallet_keys.py -r <mnemonic_sentence> <passphrase> <parent_derivation_path> <starting_child_key_index> <no_of_child_keys> <testnet_flag>
# Help mode :
# python bitcoin_hd_wallet_keys.py, or
# python bitcoin_hd_wallet_keys.py -h
# where :
# <mnemonic_sentence> = BIP39 mnemonic sentence, ie. the space separated mnemonic words concatenated into a single text 
# string as specified in BIP39. The mnemonic sentence may comprise 12, 15, 18, 21, or 24 words depending on the initial 
# entropy length (128 - 256 bits) that was used to derive the word list.
# <passphrase> = BIP39 optional passphrase, specify "" for the default value of an empty string.
# <derivation_path> = in single key mode BIP32 derivation path of the required key.
# <ext_key_prefix_override> = in single key mode specify bip32/bip44, bip49, or bip84 to override the prefix for extended keys.
# <parent_derivation_path> = in range of keys mode, BIP32 derivation path of the parent key of the required range of keys.
# <starting_child_key_index> = in range of keys mode, a non-hardened or a hardened child index, the latter denoted 
# by a ' suffix. The range of child keys cannot cross over from non-hardened keys to hardened keys.
# <no_of_child_keys> = in range of keys mode the number of child keys in range.
# <testnet_flag> = flag set to 1 for testnet, 0 for mainnet. If derivation path is of type BIP44, BIP49,
# or BIP84 the user specified testnet flag is overridden to a value of True/False for coin_type' of 1'/0' resp.
#
# Dependencies :
# Jimmy Song library and Bech32/Bech32m Python reference implementation - details given below under 'Imports'.
# 
# Testing :
# Tested on Python v3.8.10




########################################################################################################################
####################																				####################
####################									IMPORTS										####################
####################																				####################
########################################################################################################################


import sys
import re
from enum import Enum

import hmac
import hashlib


# Jimmy Song library
# ------------------
# Modules ecc.py and helper.py from the final version of the sample code from the book :
# Programming Bitcoin by Jimmy Song (2019), O'Reilly Media, ISBN 978-1-492-03149-9
# are used.
# These modules are available at :
# https://github.com/jimmysong/programmingbitcoin/tree/master/code-ch13
# To use the modules download them to your computer and place them in the current directory or place them 
# in another directory and set up the PYTHONPATH environment variable to point to them, eg. :
# export PYTHONPATH="/home/username/Jimmy Song/book-code/code-ch13"
# on Linux (note the double quotes are needed)
# or
# set PYTHONPATH=c:\Jimmy Song\book-code\code-ch13
# on Windows (note double quotes must not be used)
from ecc import S256Point, PrivateKey, N, G
from helper import encode_base58_checksum


# Bech32/Bech32m Python reference implementation
# ----------------------------------------------
# The module segwit_addr.py which is the Bech32/Bech32m Python reference implementation at :
# https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
# is required.
# To use the module download it to your computer and place it in the current directory or place it
# in another directory and set up the PYTHONPATH environment variable to point to it, eg. :
# export PYTHONPATH="/home/username/bech32"
# on Linux (note the double quotes are needed)
# or
# set PYTHONPATH=c:\bech32
# on Windows (note double quotes must not be used)
# For further information see :
# BIP173
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
# and :
# BIP350
# https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
from segwit_addr import encode




########################################################################################################################
####################																				####################
####################									DEFINITIONS									####################
####################																				####################
########################################################################################################################


FIRST_NON_HARDENED_CHILD_INDEX = 0
LAST_NON_HARDENED_CHILD_INDEX = 2 ** 31 - 1

FIRST_HARDENED_CHILD_INDEX = 2 ** 31
LAST_HARDENED_CHILD_INDEX = 2 ** 32 - 1


# Enumeration type to list the various parent derivation path types
class Parent_Derivation_Path_Type(Enum) :
	CUSTOM = 1
	BIP44 = 2
	BIP49 = 3
	BIP84 = 4


# Enumeration type for supported coin types
class Coin_Type(Enum) :
	BITCOIN_MAINNET = 1
	BITCOIN_TESTNET = 2
	NOT_APPLICABLE = 3




########################################################################################################################
####################																				####################
####################									FUNCTIONS									####################
####################																				####################
########################################################################################################################



# Function parent_type_to_prefix_type
# -----------------------------------
# Map parent derivation path types to version_prefix_type's suitable for passing into 
# functions base58check_ext_priv_key and base58check_ext_pub_key

def parent_type_to_prefix_type(path_type) :
	if (path_type == Parent_Derivation_Path_Type.CUSTOM) :
		return 'bip32/bip44'
	elif (path_type == Parent_Derivation_Path_Type.BIP44) :
		return 'bip32/bip44'
	elif (path_type == Parent_Derivation_Path_Type.BIP49) :
		return 'bip49'
	elif (path_type == Parent_Derivation_Path_Type.BIP84) :
		return 'bip84'



# Function parent_type_to_text
# ----------------------------
# Map parent derivation path types to text suitable for display to user

def parent_type_to_text(path_type) :
	if (path_type == Parent_Derivation_Path_Type.CUSTOM) :
		return 'Custom derivation path'
	elif (path_type == Parent_Derivation_Path_Type.BIP44) :
		return 'BIP44 derivation path'
	elif (path_type == Parent_Derivation_Path_Type.BIP49) :
		return 'BIP49 derivation path'
	elif (path_type == Parent_Derivation_Path_Type.BIP84) :
		return 'BIP84 derivation path'



# Function coin_type_to_text
# --------------------------
# Map coin types to text suitable for display to user

def coin_type_to_text(coin_type) :
	if (coin_type == Coin_Type.BITCOIN_MAINNET) :
		return 'Bitcoin Mainnet'
	elif (coin_type == Coin_Type.BITCOIN_TESTNET) :
		return 'Bitcoin Testnet'
	elif (coin_type == Coin_Type.NOT_APPLICABLE) :
		return 'Not Applicable'



# Function priv_to_pub
# --------------------
# convert 32 byte private key into 33 byte SEC1 compressed public key

def priv_to_pub(priv_key) :
	priv_key_int = int.from_bytes(priv_key, byteorder='big', signed=False)
	return PrivateKey(priv_key_int).point.sec(compressed=True)



# Function priv_to_wif
# --------------------
# convert 32 byte private key into compressed WIF format commencing with 'K' or 'L' for mainnet or 'c' for testnet

def priv_to_wif(priv_key, testnet=False) :
	priv_key_int = int.from_bytes(priv_key, byteorder='big', signed=False)
	return PrivateKey(priv_key_int).wif(compressed=True, testnet=testnet)



# Function hash160
# ----------------
# Perform sha256 hash on input data followed by a ripemd160 hash, producing a 20 byte hash output, as per 
# Mastering Bitcoin 2nd Ed. by Andreas Antonopolous, pg. 65
# Input parameter :
# b = byte array

def hash160(b) :
	# There is a constructor method named 'sha256' in the hashlib module but no constructor method 'ripemd160', 
	# so for the latter we have to use the 'new' method. The 'new' method allows data to be pre-populated 
	# in the hash object as the optional second parameter. 
	# The 'digest' method of the hash object returns a byte array.
	return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()



# Function pub_to_p2pkh_address
# -----------------------------
# convert 33 byte SEC1 compressed public key into Base58Check encoded P2PKH address commencing with '1' for mainnet 
# or 'm' or 'n' for testnet. P2PKH address max length is 34 chars (fixed length 34 for testnet).

def pub_to_p2pkh_address(pub_key, testnet=False) :
	if testnet:
		version_prefix = bytes.fromhex('6f')
	else:
		version_prefix = bytes.fromhex('00')
	payload = hash160(pub_key)
	return encode_base58_checksum(version_prefix + payload)



# Function pub_to_p2sh_p2wpkh_address
# -----------------------------------
# convert 33 byte SEC1 compressed public key into Base58Check encoded P2SH-P2WPKH address commencing with '3'
# for mainnet or '2' for testnet. P2SH-P2WPKH address is of fixed length 34/35 chars resp. for mainnet/testnet.

def pub_to_p2sh_p2wpkh_address(pub_key, testnet=False) :
	# by BIP141 redeemScript must be exactly a push of the version byte 0x00 plus a push of the 20 byte P2WPKH witness program.
	# The 20 byte P2WPKH witness program is the hash160 of the pub_key.
	# ie. the redeemScript is what would normally appear in the P2WPKH scriptPubKey if we were not wrapping the P2WPKH inside a P2SH.
	redeemScript = bytes.fromhex('0014') + hash160(pub_key)

	if testnet:
		version_prefix = bytes.fromhex('c4')
	else:
		version_prefix = bytes.fromhex('05')
	payload = hash160(redeemScript)
	return encode_base58_checksum(version_prefix + payload)



# Function pub_to_p2wpkh_address
# ------------------------------
# convert 33 byte SEC1 compressed public key into Bech32 encoded P2WPKH address commencing with 'bc1q' for mainnet 
# or 'tb1q' for testnet. Bech32 encoded P2WPKH address is of fixed length 42 chars for mainnet/testnet.

def pub_to_p2wpkh_address(pub_key, testnet=False) :
	# set human-readable part
	if testnet :
		hrp = 'tb'
	else :
		hrp = 'bc'

	version_byte = 0
	witness_program = hash160(pub_key)
	bech32_address = encode(hrp, version_byte, witness_program)

	if not bech32_address :
		print('ERROR in function pub_to_p2wpkh_address : failed to construct Bech32 segwit address')
		sys.exit(2)

	return bech32_address



# Function key_fingerprint
# ------------------------
# calculate the 4 byte BIP32 key fingerprint from the SEC1 compressed public key

def key_fingerprint(pub_key) :
	return hash160(pub_key)[0:4]



# Function base58check_ext_priv_key
# ---------------------------------
#
# Converts a BIP32 ext priv key (priv_key, chain_code) to its Base58Check encoded form in accordance with BIP32 :
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Serialization_format
#
# Input parameters :
# depth = integer in range 0-255 (0 if master key)
# parent_fingerprint = byte array of length 4 (all zero bytes if master key)
# child_index = integer in range 0 - 2^32-1, the index of the key as a child key (0 if master key)
# chain_code = byte array of length 32
# priv_key = byte array of length 32
# version_prefix_type = 'bip32/bip44' (default), 'bip49', or 'bip84'
# testnet = boolean
#
# Returns :
# Base58Check encoded BIP32 extended private key of the key specified by the input parameters
#
# The choice of parameter version_prefix_type determines the mainnet/testnet version prefixes that will be used in 
# formulating the Base58Check encoded BIP32 ext priv key. These version prefixes are :
# bip32/bip44 :	0x0488ade4/0x04358394 (ie. 0x0488ade4 for mainnet and 0x04358394 for testnet)
# bip49 :		0x049d7878/0x044a4e28
# bip84 :		0x04b2430c/0x045f18bc
# They result in mainnet/testnet ext priv keys with the following prefixes :
# bip32/bip44 :	xprv/tprv (ie. xprv for mainnet and tprv for testnet)
# bip49 :		yprv/uprv
# bip84 :		zprv/vprv
#
# The choice of version_prefix_type should correspond with the derivation path of the key's parent. This function though 
# does not request what that derivation path is and so cannot check it - the function requests only enough information 
# to construct the Base58Check encoded BIP32 private key. The correct choice of version_prefix_type per derivation
# path type is shown below (see also function parent_type_to_prefix_type) :-
# Custom derivation path :												'bip32/bip44'
# BIP44 derivation path (of form m/44'/coin_type'/account'/change) :	'bip32/bip44'
# BIP49 derivation path (of form m/49'/coin_type'/account'/change) :	'bip49'
# BIP84 derivation path (of form m/84'/coin_type'/account'/change) :	'bip84'

def base58check_ext_priv_key(depth, parent_fingerprint, child_index, chain_code, priv_key, version_prefix_type = 'bip32/bip44', testnet=False) :

	if version_prefix_type == 'bip32/bip44' :
		if not testnet :
			version_prefix = bytes.fromhex('0488ade4')
		else :
			version_prefix = bytes.fromhex('04358394')
	elif version_prefix_type == 'bip49' :
		if not testnet :
			version_prefix = bytes.fromhex('049d7878')
		else :
			version_prefix = bytes.fromhex('044a4e28')
	elif version_prefix_type == 'bip84' :
		if not testnet :
			version_prefix = bytes.fromhex('04b2430c')
		else :
			version_prefix = bytes.fromhex('045f18bc')

	depth_byte = depth.to_bytes(length=1, byteorder='big', signed=False)

	# note unlike many other places in Bitcoin this integer encoding is big endian
	child_index_bytes = child_index.to_bytes(length=4, byteorder='big', signed=False)

	payload = depth_byte + parent_fingerprint + child_index_bytes + chain_code + b'\x00' + priv_key

	return encode_base58_checksum(version_prefix + payload)



# Function base58check_ext_pub_key
# --------------------------------
#
# Converts a BIP32 ext pub key (pub_key, chain_code) to its Base58Check encoded form in accordance with BIP32 :
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Serialization_format
#
# Input parameters :
# depth = integer in range 0-255 (0 if master key)
# parent_fingerprint = byte array of length 4 (all zero bytes if master key)
# child_index = integer in range 0 - 2^32-1, the index of the key as a child key (0 if master key)
# chain_code = byte array of length 32
# pub_key = byte array of length 33 containing SEC1 compressed public key
# version_prefix_type = 'bip32/bip44' (default), 'bip49', or 'bip84'
# testnet = boolean
#
# Returns :
# Base58Check encoded BIP32 extended public key of the child key specified by the input parameters
#
# The choice of parameter version_prefix_type determines the mainnet/testnet version prefixes that will be used in 
# formulating the Base58Check encoded BIP32 ext pub key. These version prefixes are :
# bip32/bip44 :	0x0488b21e/0x043587cf (ie. 0x0488b21e for mainnet and 0x043587cf for testnet)
# bip49 :		0x049d7cb2/0x044a5262
# bip84 :		0x04b24746/0x045f1cf6
# They result in mainnet/testnet ext pub keys with the following prefixes :
# bip32/bip44 :	xpub/tpub (ie. xpub for mainnet and tpub for testnet)
# bip49 :		ypub/upub
# bip84 :		zpub/vpub
# The choice of version_prefix_type should correspond with the derivation path of the key's parent. This function though 
# does not request what that derivation path is and so cannot check it - the function requests only enough information 
# to construct the Base58Check encoded BIP32 private key. The correct choice of version_prefix_type per derivation
# path type is shown below (also see function parent_type_to_prefix_type) :-
# custom derivation path :												'bip32/bip44'
# BIP44 derivation path (of form M/44'/coin_type'/account'/change) :	'bip32/bip44'
# BIP49 derivation path (of form M/49'/coin_type'/account'/change) :	'bip49'
# BIP84 derivation path (of form M/84'/coin_type'/account'/change) :	'bip84'

def base58check_ext_pub_key(depth, parent_fingerprint, child_index, chain_code, pub_key, version_prefix_type = 'bip32/bip44', testnet=False):

	if version_prefix_type == 'bip32/bip44' :
		if not testnet :
			version_prefix = bytes.fromhex('0488b21e')
		else :
			version_prefix = bytes.fromhex('043587cf')
	elif version_prefix_type == 'bip49' :
		if not testnet :
			version_prefix = bytes.fromhex('049d7cb2')
		else :
			version_prefix = bytes.fromhex('044a5262')
	elif version_prefix_type == 'bip84' :
		if not testnet :
			version_prefix = bytes.fromhex('04b24746')
		else :
			version_prefix = bytes.fromhex('045f1cf6')

	depth_byte = depth.to_bytes(length=1, byteorder='big', signed=False)

	# note unlike many other places in Bitcoin this integer encoding is big endian
	child_index_bytes = child_index.to_bytes(length=4, byteorder='big', signed=False)

	payload = depth_byte + parent_fingerprint + child_index_bytes + chain_code + pub_key

	return encode_base58_checksum(version_prefix + payload)



# Function derive_child_ext_priv_key
# ----------------------------------
#
# Produces the BIP32 extended private key (child_priv_key, child_chain_code) for a specified child of a parent extended private key
# (parent_priv_key, parent_chain_code). The child is specified by a child_index in the range [0, 2^32-1] and may be hardened
# or non-hardened.
# Input parameters :
# parent_priv_key = byte array of length 32
# parent_chain_code = byte array of length 32
# child_index = integer in range [0, 2^32-1] specifying the child
# Returns :
# child_priv_key = byte array of length 32
# child_chain_code = byte array of length 32
# or terminates script with an error if an unsuitable hash value arose during the derivation (very low probability event) 
# in which case the child cannot exist for the given child_index.

def derive_child_ext_priv_key(parent_priv_key, parent_chain_code, child_index) :
	parent_priv_key_int = int.from_bytes(parent_priv_key, byteorder='big', signed=False)
	child_index_bytes = child_index.to_bytes(length=4, byteorder='big', signed=False)

	if (child_index >= FIRST_HARDENED_CHILD_INDEX) :
		# hardened derivation
		hmac_output = hmac.new(parent_chain_code, b'\x00' + parent_priv_key + child_index_bytes, 'sha512').digest()
	else :
		# non-hardened derivation
		parent_pub_key = PrivateKey(parent_priv_key_int).point.sec(compressed=True)
		hmac_output = hmac.new(parent_chain_code, parent_pub_key + child_index_bytes, 'sha512').digest()

	hmac_output_left = hmac_output[:32]
	hmac_output_right = hmac_output[32:]
	hmac_output_left_int = int.from_bytes(hmac_output_left, byteorder='big', signed=False)

	# as per BIP32 spec
	if (hmac_output_left_int >= N) :
		print('ERROR in function derive_child_ext_priv_key : an unsuitable hash value arose during the derivation, use a different child index')
		sys.exit(2)

	child_priv_key_int = (hmac_output_left_int + parent_priv_key_int) % N
	if (child_priv_key_int == 0) :
		# zero is not permissable as a private key
		print('ERROR in function derive_child_ext_priv_key : an unsuitable hash value arose during the derivation, use a different child index')
		sys.exit(2)

	child_priv_key = child_priv_key_int.to_bytes(length=32, byteorder='big', signed=False)
	child_chain_code = hmac_output_right

	return (child_priv_key, child_chain_code)



# Function derive_child_ext_pub_key
# ---------------------------------
#
# Produces the BIP32 extended public key (child_pub_key, child_chain_code) for a specified child of a parent extended public key
# (parent_pub_key, parent_chain_code). The child is specified by a child_index in the range [0, 2^32-1], however the function
# will fail if the child is hardened.
# Input parameters :
# parent_pub_key = byte array of length 33 containing SEC1 compressed public key
# parent_chain_code = byte array of length 32
# child_index = integer in range [0, 2^32-1] specifying the child key
# Returns :
# child_pub_key = byte array of length 33 containing SEC1 compressed public key
# child_chain_code = byte array of length 32
# or terminates script with an error if either :
# (1) child_index >= HARDENED_INDEX_BEGIN, ie. a hardened child (the requested extended pub key derivation is then not possible), or
# (2) an unsuitable hash value arises during the derivation (very low probability event) in which case the child cannot exist for 
# the given child_index.

def derive_child_ext_pub_key(parent_pub_key, parent_chain_code, child_index) :
	child_index_bytes = child_index.to_bytes(length=4, byteorder='big', signed=False)

	if (child_index >= FIRST_HARDENED_CHILD_INDEX) :
		# hardened child, requested extended pub key derivation not possible
		print("ERROR in function derive_child_ext_pub_key : public parent key to public child key derivation not possible for hardened child index {}'".format(child_index - FIRST_HARDENED_CHILD_INDEX))
		sys.exit(2)
	else :
		# non-hardened derivation
		hmac_output = hmac.new(parent_chain_code, parent_pub_key + child_index_bytes, 'sha512').digest()

	hmac_output_left = hmac_output[:32]
	hmac_output_right = hmac_output[32:]
	hmac_output_left_int = int.from_bytes(hmac_output_left, byteorder='big', signed=False)

	# as per BIP32 spec
	if (hmac_output_left_int >= N) :
		print('ERROR in function derive_child_ext_pub_key : an unsuitable hash value arose during the derivation, use a different child index')
		sys.exit(2)

	child_pub_key_point = (hmac_output_left_int*G) + S256Point.parse(parent_pub_key) 
	if (child_pub_key_point.x is None) :
		# ie. child_pub_key_point is point at infinity on the elliptic curve (this means the associated 
		# private key for this pub key is zero, which is an invalid value for a private key)
		print('ERROR in function derive_child_ext_pub_key : an unsuitable hash value arose during the derivation, use a different child index')
		sys.exit(2)

	child_pub_key = child_pub_key_point.sec(compressed=True)
	child_chain_code = hmac_output_right

	return (child_pub_key, child_chain_code)



# Function get_parent_type
# ------------------------
#
# Accepts the list parent_path_components from function derivation_path_ext_key (so the first component is either 'm' 
# or 'M' and all elements in the list beyond the first are child indices in integer form) and determines whether 
# this parent's derivation path conforms with BIP44, BIP49, BIP84, or none of these. In the latter case the 
# parent derivation path type is classed as 'CUSTOM'. The return value is a 2-tuple containing the parent type and 
# the coin type, with the coin type in the case of a parent type of 'CUSTOM' always being 'NOT_APPLICABLE'.
# When the parent type is BIP44, BIP49, or BIP84 then the coin type is either BITCOIN_MAINNET or BITCOIN_TESTNET.
#
# The definitions which are used of a parent derivation path conforming with BIP44, BIP49, BIP84 are as follows :-
# BIP44 derivation path : of form p/44'/coin_type'/account'/change
# BIP49 derivation path : of form p/49'/coin_type'/account'/change
# BIP84 derivation path : of form p/84'/coin_type'/account'/change
# where in each case p is either 'm' or 'M', coin_type' is 0' or 1' (ie. resp. the Bitcoin mainnet/testnet registered coin 
# types as per BIP44), account' is any valid hardened child index, and 'change' is a non-hardened child index taking 
# the value 0 or 1. Any other form of derivation path is classed as 'CUSTOM'.

def get_parent_type(parent_path_components) :
	if len(parent_path_components) != 5 :
		return (Parent_Derivation_Path_Type.CUSTOM, Coin_Type.NOT_APPLICABLE)

	if	(	parent_path_components[1] >= FIRST_HARDENED_CHILD_INDEX and parent_path_components[1] <= LAST_HARDENED_CHILD_INDEX 	and
			parent_path_components[2] >= FIRST_HARDENED_CHILD_INDEX	and parent_path_components[2] <= FIRST_HARDENED_CHILD_INDEX + 1 and
			parent_path_components[3] >= FIRST_HARDENED_CHILD_INDEX and parent_path_components[3] <= LAST_HARDENED_CHILD_INDEX 	and
			parent_path_components[4] >= FIRST_NON_HARDENED_CHILD_INDEX and parent_path_components[4] <= FIRST_NON_HARDENED_CHILD_INDEX + 1) :
		if parent_path_components[2] == FIRST_HARDENED_CHILD_INDEX :
			coin_type = Coin_Type.BITCOIN_MAINNET
		else :
			coin_type = Coin_Type.BITCOIN_TESTNET
		if parent_path_components[1] == FIRST_HARDENED_CHILD_INDEX + 44 :
			return (Parent_Derivation_Path_Type.BIP44, coin_type)
		elif parent_path_components[1] == FIRST_HARDENED_CHILD_INDEX + 49 :
			return (Parent_Derivation_Path_Type.BIP49, coin_type)
		elif parent_path_components[1] == FIRST_HARDENED_CHILD_INDEX + 84 :
			return (Parent_Derivation_Path_Type.BIP84, coin_type)
		else :
			return (Parent_Derivation_Path_Type.CUSTOM, Coin_Type.NOT_APPLICABLE)
	else :
		return (Parent_Derivation_Path_Type.CUSTOM, Coin_Type.NOT_APPLICABLE)



# Function derivation_path_ext_key
# --------------------------------
#
# For the specified derivation path returns a BIP32 extended private key (priv_key, chain_code) or BIP32 extended
# public key (pub_key, chain_code) plus ancillary information relating to the key. The derivation commences at the master key 
# denoted by 'm' (master private key) or 'M' (master public key). Assumes the global variables master_priv_key,
# master_pub_key, and master_chain_code have been populated.
# Checks if derivation_path is of the correct format, terminating the script with an error if it is not. 
# The correct format is as described in Mastering Bitcoin 2nd Ed. by Andreas Antonopolous, pg. 113. Or as described in :
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-The_key_tree 
# except with the child index number for a hardened child denoted by the suffixed prime character ' rather than
# the subscript H.
# Returns :
# (depth, parent_fingerprint, child_index, chain_code, key, parent_type, coin_type)
# ie. as the 1st 5 parameters to functions base58check_ext_priv_key/base58check_ext_pub_key, plus the parent_type
# and coin_type.

def derivation_path_ext_key(derivation_path) :
	path_components = derivation_path.split('/')

	no_of_path_components = len(path_components)

	# check first path component is valid - must be 'm' or 'M'
	if (path_components[0] != 'm' and path_components[0] != 'M') :
		print("ERROR in function derivation_path_ext_key : First component in HD wallet derivation path must be 'm' or 'M'")
		sys.exit(2)

	# check all path components beyond the first are valid and convert them to child index integers. Exit script 
	# with an error if an invalid format component is detected. Loop is not entered if there is only one path component.
	for i in range(1, no_of_path_components) :
		if (path_components[i].isdecimal()) :
			# non-hardened child index
			path_components[i] = int(path_components[i])
			if not (path_components[i] >= FIRST_NON_HARDENED_CHILD_INDEX and path_components[i] <= LAST_NON_HARDENED_CHILD_INDEX) :
				print("ERROR in function derivation_path_ext_key : non-hardened child index {} is out of range".format(path_components[i]))
				sys.exit(2)
		else :
			match = re.search("(^\d+)'$", path_components[i])
			if (match) :
				# hardened child index
				path_components[i] = int(match.group(1)) + FIRST_HARDENED_CHILD_INDEX
				if not (path_components[i] >= FIRST_HARDENED_CHILD_INDEX and path_components[i] <= LAST_HARDENED_CHILD_INDEX) :
					print("ERROR in function derivation_path_ext_key : hardened child index {}' is out of range".format(path_components[i] - FIRST_HARDENED_CHILD_INDEX))
					sys.exit(2)
			else :
				print("ERROR in function derivation_path_ext_key : invalid child index {} in HD wallet derivation path".format(path_components[i]))
				sys.exit(2)

	# set the zero-based depth
	depth = no_of_path_components - 1
	if depth > 0 :
		# exclude the last component to get the parent path
		parent_path_components = path_components[:depth]
		(parent_type, coin_type) = get_parent_type(parent_path_components)
	else :
		# for code clarity the case of depth == 0 is handled within the if branches below
		pass

	if (path_components[0] == 'm') :
		# private key derivation sequence
		# commence at the master extended private key
		(priv_key, chain_code) = (master_priv_key, master_chain_code)
		# check for case of a master key path - no derivations are then needed
		if depth == 0 :
			return (0, bytes.fromhex('00000000'), 0, chain_code, priv_key, Parent_Derivation_Path_Type.CUSTOM, Coin_Type.NOT_APPLICABLE)
		# derive down to the parent so we can get its fingerprint
		for i in range(1, depth) :
			# note loop is never entered if only two path components
			child_index = path_components[i]
			(priv_key, chain_code) = derive_child_ext_priv_key(priv_key, chain_code, child_index)
		parent_fingerprint = key_fingerprint(priv_to_pub(priv_key))
		# do final derivation to the required key
		child_index = path_components[depth]
		(priv_key, chain_code) = derive_child_ext_priv_key(priv_key, chain_code, child_index)
		return (depth, parent_fingerprint, child_index, chain_code, priv_key, parent_type, coin_type)
	elif (path_components[0] == 'M') :
		# public key derivation sequence
		# commence at the master extended public key
		(pub_key, chain_code) = (master_pub_key, master_chain_code)
		# check for case of a master key path - no derivations are then needed
		if depth == 0 :
			return (0, bytes.fromhex('00000000'), 0, chain_code, pub_key, Parent_Derivation_Path_Type.CUSTOM, Coin_Type.NOT_APPLICABLE)
		# derive down to the parent so we can get its fingerprint
		for i in range(1, depth) :
			# note loop is never entered if only two path components
			child_index = path_components[i]
			# note function derive_child_ext_pub_key will handle the error if child_index >= FIRST_HARDENED_CHILD_INDEX
			(pub_key, chain_code) = derive_child_ext_pub_key(pub_key, chain_code, child_index)
		parent_fingerprint = key_fingerprint(pub_key)
		# do final derivation to the required key
		child_index = path_components[depth]
		(pub_key, chain_code) = derive_child_ext_pub_key(pub_key, chain_code, child_index)
		return (depth, parent_fingerprint, child_index, chain_code, pub_key, parent_type, coin_type)



# Function derivation_path_child_key_list
# ---------------------------------------
#
# For the specified parent derivation path derives a list of child private keys or a list of child public keys.
# Each private key is in the form of a byte array of length 32. Each public key is in the form of a byte array of 
# length 33 containing the SEC1 compressed public key. The derivation commences at the master key denoted by 'm'
# (master private key) or 'M' (master public key). Assumes the global variables master_priv_key, master_pub_key,
# and master_chain_code have been populated. Does not perform any check that the parent_derivation_path is of the
# correct format, and assumes it has been formerly checked (for example during execution of function 
# derivation_path_ext_key). Assumes that the input parameters starting_child_key_index and no_of_child_keys
# specify a valid child key range.
# Input parameters :
# starting_child_key_index = integer in the range [0, 2^32-1] representing the hardened or non-hardened child key
# that is first in the list
# no_of_child_keys = number of child keys to derive from the parent key
# Returns :
# a list of child private keys or a list of child public keys 

def derivation_path_child_key_list(parent_derivation_path, starting_child_key_index, no_of_child_keys) :
	path_components = parent_derivation_path.split('/')

	no_of_path_components = len(path_components)

	# convert all path components beyond the first to child index integers.
	for i in range(1, no_of_path_components) :
		if (path_components[i].isdecimal()) :
			# non-hardened child index
			path_components[i] = int(path_components[i])
		else :
			match = re.search("(^\d+)'$", path_components[i])
			# hardened child index
			path_components[i] = int(match.group(1)) + FIRST_HARDENED_CHILD_INDEX

	if (path_components[0] == 'm') :
		# private key derivation sequence
		# commence at the master extended private key
		(priv_key, chain_code) = (master_priv_key, master_chain_code)
		# derive down to the parent key
		for i in range(1, no_of_path_components) :
			# note loop is never entered if only one path component
			child_index = path_components[i]
			(priv_key, chain_code) = derive_child_ext_priv_key(priv_key, chain_code, child_index)
		(parent_priv_key, parent_chain_code) = (priv_key, chain_code)
		# do derivations to the required child keys and store them in a list
		child_priv_key_list = []
		for child_index in range(starting_child_key_index, starting_child_key_index + no_of_child_keys) :
			(priv_key, chain_code) = derive_child_ext_priv_key(parent_priv_key, parent_chain_code, child_index)
			child_priv_key_list.append(priv_key)
		return child_priv_key_list
	elif (path_components[0] == 'M') :
		# public key derivation sequence
		# commence at the master extended public key
		(pub_key, chain_code) = (master_pub_key, master_chain_code)
		# derive down to the parent key
		for i in range(1, no_of_path_components) :
			# note loop is never entered if only one path component
			child_index = path_components[i]
			(pub_key, chain_code) = derive_child_ext_pub_key(pub_key, chain_code, child_index)
		(parent_pub_key, parent_chain_code) = (pub_key, chain_code)
		# do derivations to the required child keys and store them in a list
		child_pub_key_list = []
		for child_index in range(starting_child_key_index, starting_child_key_index + no_of_child_keys) :
			(pub_key, chain_code) = derive_child_ext_pub_key(parent_pub_key, parent_chain_code, child_index)
			child_pub_key_list.append(pub_key)
		return child_pub_key_list



# Function compute_seed
# ---------------------
#
# Computes BIP39 seed.
# Input parameters :
# mnemonic_sentence = BIP39 mnemonic sentence, ie. the space separated mnemonic words concatenated into a single text string,
# passphrase = optional passphrase as a text string.
# As specified in BIP39 the mnemonic sentence may comprise 12, 15, 18, 21, or 24 words depending on the initial entropy 
# length (128 - 256 bits) that was used to derive the word list.
# Returns :
# The 512 bit (64 byte) seed generated from the input parameters by the PBKDF2 key derivation function

def compute_seed(mnemonic_sentence, passphrase='') :
	kdf_hash_name = 'sha512'
	kdf_password = mnemonic_sentence.encode()
	kdf_salt = b'mnemonic' + passphrase.encode()
	kdf_iterations = 2048
	return hashlib.pbkdf2_hmac(kdf_hash_name, kdf_password, kdf_salt, kdf_iterations)



# Function get_range_info
# -----------------------
#
# Input parameters :
# starting_child_key_index = string as entered by user representing the start of the child key index range
# no_of_child_keys = integer entered by user representing number of child keys in the range
# Returns :
# starting_child_key_index = integer in range 0 to 2^32 - 1 representing a hardened or non-hardened child key
# child_key_range_is_hardened = boolean to say whether the range consists of hardened or non-hardened child keys
# (cannot contain a mix of both).
# Validates that the range is within the required limits, exiting the script with an error if not.

def get_range_info(starting_child_key_index, no_of_child_keys) :
	if (starting_child_key_index.isdecimal()) :
		# child key range is non-hardened
		child_key_range_is_hardened = False
		starting_child_key_index = int(starting_child_key_index)
		if not (starting_child_key_index >= FIRST_NON_HARDENED_CHILD_INDEX and starting_child_key_index <= LAST_NON_HARDENED_CHILD_INDEX) :
			print("ERROR in function get_range_info : non-hardened child index {} is out of range".format(starting_child_key_index))
			sys.exit(2)
		# don't permit crossover of key range into hardened keys
		if starting_child_key_index + no_of_child_keys - 1 > LAST_NON_HARDENED_CHILD_INDEX :
			print("ERROR in function get_range_info : range of non-hardened child key indices too large")
			sys.exit(2)
	else :
		match = re.search("(^\d+)'$", starting_child_key_index)
		if (match) :
			# child key range is hardened
			child_key_range_is_hardened = True
			starting_child_key_index = int(match.group(1)) + FIRST_HARDENED_CHILD_INDEX
			if not (starting_child_key_index >= FIRST_HARDENED_CHILD_INDEX and starting_child_key_index <= LAST_HARDENED_CHILD_INDEX):
				print("ERROR in function get_range_info : hardened child index {}' is out of range".format(starting_child_key_index - FIRST_HARDENED_CHILD_INDEX))
				sys.exit(2)
			# check range is within limit
			if starting_child_key_index + no_of_child_keys - 1 > LAST_HARDENED_CHILD_INDEX :
				print("ERROR in function get_range_info : range of hardened child key indices too large")
				sys.exit(2)
		else :
			print("ERROR in function get_range_info : invalid child index {}".format(starting_child_key_index))
			sys.exit(2)
	return (starting_child_key_index, child_key_range_is_hardened)



# Function print_help_message
#

def print_help_message() :
	print(
"""
bitcoin_hd_wallet_keys.py
-------------------------
Python script to display individual keys within a Bitcoin heirarchical deterministic (HD) wallet. 
Keys are selected via BIP32 derivation paths. The HD wallet is specified by a mnemonic sentence and a passphrase.
Conforms to BIP32, BIP39, BIP43, BIP44, BIP49, BIP84 for coin_type' values of 0' or 1' (ie. resp. Bitcoin 
mainnet/testnet registered coin types as per BIP44).
Usage :-
Single key mode :
python bitcoin_hd_wallet_keys.py -s <mnemonic_sentence> <passphrase> <derivation_path> <testnet_flag>
or
python bitcoin_hd_wallet_keys.py -s <mnemonic_sentence> <passphrase> <derivation_path> <ext_key_prefix_override> <testnet_flag>
Range of keys mode :
python bitcoin_hd_wallet_keys.py -r <mnemonic_sentence> <passphrase> <parent_derivation_path> <starting_child_key_index> <no_of_child_keys> <testnet_flag>
Help mode :
python bitcoin_hd_wallet_keys.py, or
python bitcoin_hd_wallet_keys.py -h
where :
<mnemonic_sentence> = BIP39 mnemonic sentence, ie. the space separated mnemonic words concatenated into a single text 
string as specified in BIP39. The mnemonic sentence may comprise 12, 15, 18, 21, or 24 words depending on the initial 
entropy length (128 - 256 bits) that was used to derive the word list.
<passphrase> = BIP39 optional passphrase, specify "" for the default value of an empty string.
<derivation_path> = in single key mode BIP32 derivation path of the required key.
<ext_key_prefix_override> = in single key mode specify bip32/bip44, bip49, or bip84 to override the prefix for extended keys.
<parent_derivation_path> = in range of keys mode, BIP32 derivation path of the parent key of the required range of keys.
<starting_child_key_index> = in range of keys mode, a non-hardened or a hardened child index, the latter denoted 
by a ' suffix. The range of child keys cannot cross over from non-hardened keys to hardened keys.
<no_of_child_keys> = in range of keys mode the number of child keys in range.
<testnet_flag> = flag set to 1 for testnet, 0 for mainnet. If derivation path is of type BIP44, BIP49,
or BIP84 the user specified testnet flag is overridden to a value of True/False for coin_type' of 1'/0' resp.
""")




########################################################################################################################
####################																				####################
####################								MAIN PROGRAM									####################
####################																				####################
########################################################################################################################



if len(sys.argv) == 1 or (sys.argv[1] == '-h') :
	# no command line arguments
	print_help_message()
	sys.exit(0)

single_key_mode_requested = (sys.argv[1] == '-s')

mnemonic_sentence = sys.argv[2]
passphrase = sys.argv[3]

# determine mode requested
if single_key_mode_requested :
	derivation_path = sys.argv[4]
	if len(sys.argv) == 6 :
		# 5 command line parameters form
		ext_key_prefix_override = None
		testnet_flag = sys.argv[5]
	else :
		# 6 command line parameters form
		ext_key_prefix_override = sys.argv[5]
		testnet_flag = sys.argv[6]
else :
	parent_derivation_path = sys.argv[4]
	starting_child_key_index = sys.argv[5]
	no_of_child_keys = int(sys.argv[6])
	# convert string starting_child_key_index to integer, determine whether the range is hardened or not, and check if 
	# the key range is valid exiting script with an error if it is not
	(starting_child_key_index, child_key_range_is_hardened) = get_range_info(starting_child_key_index, no_of_child_keys)
	testnet_flag = sys.argv[7]

# set defaults
if not mnemonic_sentence :
	mnemonic_sentence = 'fit crunch census knee piano sail logic fiber purchase over obvious describe'
if not passphrase :
	passphrase = ''

if int(testnet_flag) :
	testnet = True
else :
	testnet = False



seed = compute_seed(mnemonic_sentence, passphrase)

# compute master key as described in BIP32 :
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Master_key_generation
# Also described in Mastering Bitcoin 2nd Ed. by Andreas Antonopolous, pg. 106
hashed_seed = hmac.new(key=b'Bitcoin seed', msg=seed, digestmod='sha512').digest()
master_priv_key = hashed_seed[:32]
master_chain_code = hashed_seed[32:]
master_pub_key = priv_to_pub(master_priv_key)



if single_key_mode_requested :
	# Compute the required key. This function will terminate the script with an error if derivation_path 
	# is not a valid form.
	(depth, parent_fingerprint, child_index, chain_code, key, parent_type, coin_type) = derivation_path_ext_key(derivation_path)

	# if parent_type is BIP44, BIP49, or BIP84 then child under the parent must be non-hardened (as per BIP44)
	if (parent_type != Parent_Derivation_Path_Type.CUSTOM and child_index >= FIRST_HARDENED_CHILD_INDEX) :
		print("ERROR in main script : a key with parent type BIP44, BIP49, or BIP84 cannot have a hardened address index under the parent")
		sys.exit(2)

	private_key_derivation = (len(key) == 32)
	version_prefix_type = parent_type_to_prefix_type(parent_type)
	parent_type_text = parent_type_to_text(parent_type)
	coin_type_text = coin_type_to_text(coin_type)

	# apply the ext key prefix override if specified by user
	if ext_key_prefix_override :
		version_prefix_type = ext_key_prefix_override

	# override the user specified testnet flag if the coin_type is BITCOIN_MAINNET or BITCOIN_TESTNET
	# (this means the parent_type must be BIP44, BIP49, or BIP84). Override it to value False/True if 
	# coin_type is BITCOIN_MAINNET/BITCOIN_TESTNET resp.
	if (coin_type != Coin_Type.NOT_APPLICABLE) : testnet = (coin_type == Coin_Type.BITCOIN_TESTNET)

	if (private_key_derivation) :
		# a private key derivation path was supplied by user (ie. commencing 'm'). The same Base58Check encoded WIF private 
		# key is provided irrespective of the parent_type but the Base58Check encoded extended private key provided 
		# varies depending on the parent_type via the version_prefix_type
		priv_key_wif = priv_to_wif(key, testnet)
		ext_priv_key = base58check_ext_priv_key(depth, parent_fingerprint, child_index, chain_code, key, version_prefix_type, testnet)
		pub_key = priv_to_pub(key)
	else :
		# a public key derivation path was supplied by user (ie. commencing 'M')
		pub_key = key

	# Whether user supplied a private key derivation path or a public key derivation path we provide the address 
	# corresponding to the 33 byte long SEC1 compressed public key, this address being of the appropriate type 
	# (ie. P2PKH, P2SH-P2WPKH, or P2WPKH) depending on the parent_type, and we provide the Base58Check encoded 
	# extended public key which also varies depending on the parent_type (via the version_prefix_type)
	if parent_type == Parent_Derivation_Path_Type.CUSTOM :
		# parent derivation path type is CUSTOM so display the Base58Check encoded P2PKH address for the public key
		address = pub_to_p2pkh_address(pub_key, testnet)
	elif parent_type == Parent_Derivation_Path_Type.BIP44 :
		# parent derivation path type is BIP44, ie. of form x/44'/coin_type'/account'/change,
		# (where x = 'm' or 'M') so display the Base58Check encoded P2PKH address for the public key
		address = pub_to_p2pkh_address(pub_key, testnet)
	elif parent_type == Parent_Derivation_Path_Type.BIP49 :
		# parent derivation path type is BIP49, ie. x/49'/coin_type'/account'/change,
		# (where x = 'm' or 'M') so display the Base58Check encoded P2SH-P2WPKH address for the public key
		address = pub_to_p2sh_p2wpkh_address(pub_key, testnet)
	elif parent_type == Parent_Derivation_Path_Type.BIP84 :
		# parent derivation path type is BIP84, ie. x/84'/coin_type'/account'/change,
		# (where x = 'm' or 'M') so display the Bech32 encoded P2WPKH address for the public key
		address = pub_to_p2wpkh_address(pub_key, testnet)
	ext_pub_key = base58check_ext_pub_key(depth, parent_fingerprint, child_index, chain_code, pub_key, version_prefix_type, testnet)

	# set up the longest label length as text width
	text_width = len('Extended key prefix override')
	print('\n{:{}} : {}'.format('Detected key type', text_width, parent_type_text))
	if ext_key_prefix_override :
		print('{:{}} : {}'.format('Extended key prefix override', text_width, ext_key_prefix_override))
	else :
		print('{:{}} : {}'.format('Extended key prefix override', text_width, 'None'))
	print('{:{}} : {}'.format('Detected coin type', text_width, coin_type_text))
	print('{:{}} : {}'.format('Testnet', text_width, 'Yes' if testnet else 'No'))
	if (private_key_derivation) :
		print('{:{}} : {}'.format('Private key', text_width, priv_key_wif))
	print('{:{}} : {}'.format('Address', text_width, address))
	if (private_key_derivation) :
		print('{:{}} : {}'.format('Extended private key', text_width, ext_priv_key))
	print('{:{}} : {}'.format('Extended public key', text_width, ext_pub_key))
else :
	# a consecutive range of child keys under a specified parent key has been requested.
	# The range is either wholly within the non-hardened child key range or wholly within the hardened child key range
	# as indicated by the boolean variable child_key_range_is_hardened obtained above.

	# determine the derivation path column width in the output from the last child key's full derivation
	# path as this will be the longest in the range. Note last_child_key_index will be an integer in the 
	# range 0 to 2^32 - 1 and if it is hardened we must convert it to string with the trailing ' character.
	last_child_key_index = starting_child_key_index + no_of_child_keys - 1
	if child_key_range_is_hardened :
		last_child_derivation_path = parent_derivation_path + '/' + str(last_child_key_index - FIRST_HARDENED_CHILD_INDEX) + "'"
	else :
		last_child_derivation_path = parent_derivation_path + '/' + str(last_child_key_index)
	derivation_path_width = len(last_child_derivation_path)
	derivation_path_column_width = max(derivation_path_width + 12, 25)
	derivation_path_column_title = 'Derivation Path'
	derivation_path_column_underline_length = max(derivation_path_width, len(derivation_path_column_title))

	# the following function call is used to determine the parent_type and the coin_type and whether we are 
	# performing private or public key derivation. The parent_type determines the type of the addresses we 
	# will generate. The function also checks the validity of the parent_derivation_path specified by the user.
	# We just pass in the last_child_derivation_path we derived above as this suffices to give us the 
	# information we need. The 1st 4 params returned are unused.
	(depth, parent_fingerprint, child_index, chain_code, key, parent_type, coin_type) = derivation_path_ext_key(last_child_derivation_path)

	# if parent_type is BIP44, BIP49, or BIP84 then child keys under the parent must be non-hardened (as per BIP44)
	if (parent_type != Parent_Derivation_Path_Type.CUSTOM and child_key_range_is_hardened) :
		print("ERROR in main script : a key with parent type BIP44, BIP49, or BIP84 cannot have a hardened address index under the parent")
		sys.exit(2)

	private_key_derivation = (len(key) == 32)

	# override the user specified testnet flag if the coin_type is BITCOIN_MAINNET or BITCOIN_TESTNET
	# (this means the parent_type must be BIP44, BIP49, or BIP84). Override it to value False/True if 
	# coin_type is BITCOIN_MAINNET/BITCOIN_TESTNET resp.
	if (coin_type != Coin_Type.NOT_APPLICABLE) : testnet = (coin_type == Coin_Type.BITCOIN_TESTNET)

	if parent_type == Parent_Derivation_Path_Type.CUSTOM :
		# parent derivation path type is CUSTOM so address is of type P2PKH of max length 34 chars 
		# (fixed length 34 for testnet)
		address_width = 34
	elif parent_type == Parent_Derivation_Path_Type.BIP44 :
		# parent derivation path type is BIP44, ie. of form x/44'/coin_type'/account'/change, so address is 
		# of type P2PKH of max length 34 chars (fixed length 34 for testnet)
		address_width = 34
	elif parent_type == Parent_Derivation_Path_Type.BIP49 :
		# parent derivation path type is BIP49, ie. x/49'/coin_type'/account'/change, (where x = 'm' or 'M')
		# so address is of type P2SH-P2WPKH of length 34/35 chars resp. for mainnet/testnet
		address_width = 35
	elif parent_type == Parent_Derivation_Path_Type.BIP84 :
		# parent derivation path type is BIP84, ie. x/84'/coin_type'/account'/change, (where x = 'm' or 'M')
		# so address is a Bech32 encoded P2WPKH address of length 42 chars for mainnet/testnet
		address_width = 42
	# allow additional 10 chars to right as spacing
	address_column_width = address_width + 10
	address_column_title = 'Address'

	private_key_column_title = 'Private Key'

	parent_type_text = parent_type_to_text(parent_type)
	coin_type_text = coin_type_to_text(coin_type)

	# set up the longest label length as text width
	text_width = len('Detected coin type')
	print('\n{:{}} : {}'.format('Detected key type', text_width, parent_type_text))
	print('{:{}} : {}'.format('Detected coin type', text_width, coin_type_text))
	print('{:{}} : {}\n'.format('Testnet', text_width, 'Yes' if testnet else 'No'))

	if private_key_derivation :
		# width of a WIF compressed private key (mainnet/testnet) is always 52
		private_key_width = 52

		# print the heading
		print('{:{}}{:{}}{}'.format(derivation_path_column_title, derivation_path_column_width, address_column_title, address_column_width, private_key_column_title))
		print('{:{}}{:{}}{}'.format('-'*derivation_path_column_underline_length, derivation_path_column_width, '-'*address_width, address_column_width, '-'*private_key_width))

		child_priv_key_list = derivation_path_child_key_list(parent_derivation_path, starting_child_key_index, no_of_child_keys)
		j = 0
		for i in range(starting_child_key_index, starting_child_key_index + no_of_child_keys) :
			# obtain the 3 items we need to display for the child key, namely the key's derivation path, its WIF compressed
			# private key, and its address, and put into the variables derivation_path, priv_key_wif, and address
			if child_key_range_is_hardened :
				derivation_path = parent_derivation_path + '/' + str(i - FIRST_HARDENED_CHILD_INDEX) + "'"
			else :
				derivation_path = parent_derivation_path + '/' + str(i)
			priv_key = child_priv_key_list[j]
			j += 1
			priv_key_wif = priv_to_wif(priv_key, testnet)
			pub_key = priv_to_pub(priv_key)
			if parent_type == Parent_Derivation_Path_Type.CUSTOM :
				# parent derivation path type is CUSTOM so display the Base58Check encoded P2PKH address for the public key
				address = pub_to_p2pkh_address(pub_key, testnet)
			elif parent_type == Parent_Derivation_Path_Type.BIP44 :
				# parent derivation path type is BIP44, ie. of form x/44'/coin_type'/account'/change,
				# (where x = 'm' or 'M') so display the Base58Check encoded P2PKH address for the public key
				address = pub_to_p2pkh_address(pub_key, testnet)
			elif parent_type == Parent_Derivation_Path_Type.BIP49 :
				# parent derivation path type is BIP49, ie. x/49'/coin_type'/account'/change,
				# (where x = 'm' or 'M') so display the Base58Check encoded P2SH-P2WPKH address for the public key
				address = pub_to_p2sh_p2wpkh_address(pub_key, testnet)
			elif parent_type == Parent_Derivation_Path_Type.BIP84 :
				# parent derivation path type is BIP84, ie. x/84'/coin_type'/account'/change,
				# (where x = 'm' or 'M') so display the Bech32 encoded P2WPKH address for the public key
				address = pub_to_p2wpkh_address(pub_key, testnet)
			print('{:{}}{:{}}{}'.format(derivation_path, derivation_path_column_width, address, address_column_width, priv_key_wif))
	else :
		# print the heading
		print('{:{}}{}'.format(derivation_path_column_title, derivation_path_column_width, address_column_title))
		print('{:{}}{}'.format('-'*derivation_path_column_underline_length, derivation_path_column_width, '-'*address_width))

		child_pub_key_list = derivation_path_child_key_list(parent_derivation_path, starting_child_key_index, no_of_child_keys)
		j = 0
		for i in range(starting_child_key_index, starting_child_key_index + no_of_child_keys) :
			# obtain the 2 items we need to display for the child key, namely the key's derivation path and its 
			# address, and put them into the variables derivation_path and address
			if child_key_range_is_hardened :
				derivation_path = parent_derivation_path + '/' + str(i - FIRST_HARDENED_CHILD_INDEX) + "'"
			else :
				derivation_path = parent_derivation_path + '/' + str(i)
			pub_key = child_pub_key_list[j]
			j += 1
			if parent_type == Parent_Derivation_Path_Type.CUSTOM :
				# parent derivation path type is CUSTOM so display the Base58Check encoded P2PKH address for the public key
				address = pub_to_p2pkh_address(pub_key, testnet)
			elif parent_type == Parent_Derivation_Path_Type.BIP44 :
				# parent derivation path type is BIP44, ie. of form x/44'/coin_type'/account'/change,
				# (where x = 'm' or 'M') so display the Base58Check encoded P2PKH address for the public key
				address = pub_to_p2pkh_address(pub_key, testnet)
			elif parent_type == Parent_Derivation_Path_Type.BIP49 :
				# parent derivation path type is BIP49, ie. x/49'/coin_type'/account'/change,
				# (where x = 'm' or 'M') so display the Base58Check encoded P2SH-P2WPKH address for the public key
				address = pub_to_p2sh_p2wpkh_address(pub_key, testnet)
			elif parent_type == Parent_Derivation_Path_Type.BIP84 :
				# parent derivation path type is BIP84, ie. x/84'/coin_type'/account'/change,
				# (where x = 'm' or 'M') so display the Bech32 encoded P2WPKH address for the public key
				address = pub_to_p2wpkh_address(pub_key, testnet)
			print('{:{}}{:{}}'.format(derivation_path, derivation_path_column_width, address, address_column_width))

