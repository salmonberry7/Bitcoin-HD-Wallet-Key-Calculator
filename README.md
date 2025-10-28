```

NO WARRANTY OR CLAIM OF FITNESS FOR ANY PURPOSE IS PROVIDED FOR THIS PROGRAM.

ALPHA STAGE CODE, LIMITED TESTING DONE.


bitcoin_hd_wallet_keys.py
-------------------------

Python script to display individual keys within a Bitcoin heirarchical deterministic (HD) wallet. 
Keys are selected via BIP32 derivation paths. The HD wallet is specified by a mnemonic sentence and a passphrase.
Conforms to BIP32, BIP39, BIP43, BIP44, BIP49, BIP84 for coin_type' values of 0' or 1' (ie. resp. Bitcoin 
mainnet/testnet registered coin types as per BIP44). When the derivation path is detected to have type BIP44, BIP49,
or BIP84 the user specified testnet flag is overridden to a value of True/False for coin_type' of 1'/0' resp.
Derivation path types which have the form of BIP44, BIP49, or BIP84 but which have coin_type' value other than 0'
or 1' are classed as CUSTOM type (see below) so they are just treated as arbitrary user defined derivation paths.

The term 'parent key' of an HD key means the whole derivation path except the rightmost derivation (this is undefined 
for the master HD keys 'm' and 'M'). For example key m/49'/0'/50'/0/4 has parent m/49'/0'/50'/0 and so is BIP49 type,
whereas m/49'/0'/50'/0/4/3 has parent m/49'/0'/50'/0/4 and so is not BIP49 type.

Works in two modes :
- single key mode (with -s switch)
- range of keys mode (with -r switch)
In single key mode private keys, addresses, extended private keys, and extended public keys are displayed for private key 
derivation paths (commencing 'm'), and addresses and extended public keys are displayed for public key derivation paths 
(commencing 'M').
In range of keys mode, for a consecutive range of child keys under a specified parent key, addresses and private keys 
are displayed for private key derivation paths (commencing 'm') and addresses are displayed for public key derivation 
paths (commencing 'M').

Addresses are displayed in either P2PKH, P2SH-P2WPKH, or P2WPKH format depending on the type of the parent key (the
parent key types defined are CUSTOM, BIP44, BIP49, or BIP84). For CUSTOM and BIP44 the address type is P2PKH, for BIP49 
the address type is P2SH-P2WPKH, and for BIP84 the address type is P2WPKH.

Private keys are displayed in WIF compressed private key format.

Extended private keys and extended public keys use the 'x', 'y', or 'z' (or resp. 't', 'u', 'v' for testnet) prefix 
depending on the parent key type, in accordance with BIP32/BIP44, BIP49, and BIP84 resp. An option is available in 
single key mode to override the x/y/z prefix.

The definitions which are used of the parent derivation path types (ie. parent key types) BIP44, BIP49, and BIP84 are
as follows :-
BIP44 derivation path type : of form p/44'/coin_type'/account'/change
BIP49 derivation path type : of form p/49'/coin_type'/account'/change
BIP84 derivation path type : of form p/84'/coin_type'/account'/change
where in each case p is either 'm' or 'M', coin_type' is 0' or 1' (ie. resp. Bitcoin mainnet/testnet registered coin 
types as per BIP44), account' is any valid hardened child index, and 'change' is a non-hardened child index taking 
the value 0 or 1.
Any other form of derivation path is classed as 'CUSTOM', including the above BIP44, BIP49, BIP84 forms when the 
coin_type' is not 0' or 1'. So for example key m/49'/0'/50'/0/4 has type BIP49, m/49'/0'/50'/0/4/3 has type CUSTOM,
m/49'/0'/50'/2/4 has type CUSTOM, m/49'/2'/50'/0/4 has type CUSTOM, and m/85'/0'/50'/0/4 has type CUSTOM.

A testnet flag may be specified which produces private keys, addresses, extended private keys, and extended public keys 
with the testnet prefixes rather than the mainnet prefixes, though note the testnet flag override described above.

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

Dependencies :
Jimmy Song library and Bech32/Bech32m Python reference implementation - details given below under 'Imports'.

Testing :
Tested on Python v3.8.10
```
