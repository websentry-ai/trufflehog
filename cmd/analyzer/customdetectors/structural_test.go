package customdetectors

import "testing"

func TestIsStripeObjectID(t *testing.T) {
	objectIDs := []string{
		"du_1TIUcBBrSQGfJTjiR3r4WQh4",
		"ch_3OqYmore0123456789abcd",
		"pi_3OabcdEFGHijklMNOPqrst",
		"cus_Oabcdefghijklmno",
		"sub_1NabcDEfghIJKlmno",
		"evt_1Nabcdefghijklmnop",
		"acct_1AbCdEfGhIjKlMnO",
		"we_1AbCdEfGhIjKlMnOpQrStUv",
		"pm_1AbCdEfGhIjKlMnOp",
		"si_AbCdEfGhIjKlMn",
	}
	for _, id := range objectIDs {
		if !IsStripeObjectID(id) {
			t.Errorf("expected %q to be a Stripe object ID", id)
		}
	}

	notObjectIDs := []string{
		"sk_live_fake",
		"rk_live_fake",
		"pk_test_fake",
		"sk_live_1AbCdEfGhIjKlMnOpQrSt",
		"rk_live_1AbCdEfGhIjKlMnOpQrSt",
		"whsec_1AbCdEfGhIjKlMnOpQrSt",
		"ghp_0123456789abcdefghijklmnopqrstuvwxyz",
		"n27p22cchdt2k3kx",
		"du_short",
		"AKIAIOSFODNN7EXAMPLE",
	}
	for _, id := range notObjectIDs {
		if IsStripeObjectID(id) {
			t.Errorf("expected %q NOT to be a Stripe object ID", id)
		}
	}
}
