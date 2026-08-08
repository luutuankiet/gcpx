package bundle

import "testing"

func TestSealOpenRoundTrip(t *testing.T) {
	plain := []byte(`{"refresh_token":"secret"}`)
	env, err := Seal(plain, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	out, err := Open(env, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plain) {
		t.Errorf("round trip mismatch: %s", out)
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	env, err := Seal([]byte("x"), "right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(env, "wrong"); err == nil {
		t.Error("decryption with the wrong passphrase must fail")
	}
}

// A refresh token must never be recoverable from the envelope itself.
func TestCiphertextHidesPlaintext(t *testing.T) {
	env, err := Seal([]byte("super-secret-refresh-token"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	if containsSub(env, "super-secret") {
		t.Error("plaintext leaked into the envelope")
	}
}

func containsSub(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestRejectsNonBundle(t *testing.T) {
	if _, err := Open("just some text", "pw"); err == nil {
		t.Error("expected a rejection for a non-bundle input")
	}
}
