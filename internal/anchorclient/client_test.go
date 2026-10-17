package anchorclient

import "testing"

func TestValidateBaseURL(t *testing.T) {
	ok := []string{
		"https://anchor.example.com",
		"https://anchor.example.com/prefix/",
		"http://127.0.0.1:8080",
		"http://localhost:9",
		"http://[::1]:9",
	}
	for _, u := range ok {
		if _, err := ValidateBaseURL(u); err != nil {
			t.Errorf("%q should be accepted: %v", u, err)
		}
	}
	bad := []string{
		"",
		"http://anchor.example.com",
		"http://10.0.0.5",
		"http://127.0.0.1.example.com",
		"ftp://anchor.example.com",
		"anchor.example.com",
		"https://user:pw@anchor.example.com",
		"https://anchor.example.com/?x=1",
		"https:///nohost",
	}
	for _, u := range bad {
		if _, err := ValidateBaseURL(u); err == nil {
			t.Errorf("%q should be rejected", u)
		}
	}
}
