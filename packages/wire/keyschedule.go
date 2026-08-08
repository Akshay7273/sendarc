package wire

// DirectionalKey is an AEAD key plus the 4-byte salt that prefixes its GCM nonces.
type DirectionalKey struct {
	Key  []byte // 32 bytes (AES-256)
	Salt []byte // 4 bytes — nonce = salt || counter_u64_be
}

// TransferKeys are both directional keys derived from one handshake.
type TransferKeys struct {
	O2J DirectionalKey // offerer → joiner
	J2O DirectionalKey // joiner → offerer
}

// DeriveMaster derives the master key, bound to the full handshake transcript so any
// tampering that survived key confirmation still changes every downstream key:
// HKDF(Ke, "sendarc/1 master" || TT).
func DeriveMaster(ke, transcript []byte) ([]byte, error) {
	info := append([]byte(infoMaster), transcript...)
	return hkdfSHA256(ke, nil, info, aeadKeyBytes)
}

// deriveDirectional derives one directional key + nonce salt from the master key.
func deriveDirectional(master []byte, info string) (DirectionalKey, error) {
	out, err := hkdfSHA256(master, nil, []byte(info), aeadKeyBytes+aeadSaltBytes)
	if err != nil {
		return DirectionalKey{}, err
	}
	return DirectionalKey{Key: out[:aeadKeyBytes], Salt: out[aeadKeyBytes:]}, nil
}

// DeriveTransferKeys derives both directional transfer keys from the master key.
func DeriveTransferKeys(master []byte) (TransferKeys, error) {
	o2j, err := deriveDirectional(master, infoDirOffererJoiner)
	if err != nil {
		return TransferKeys{}, err
	}
	j2o, err := deriveDirectional(master, infoDirJoinerOfferer)
	if err != nil {
		return TransferKeys{}, err
	}
	return TransferKeys{O2J: o2j, J2O: j2o}, nil
}
