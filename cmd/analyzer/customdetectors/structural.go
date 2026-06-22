package customdetectors

import (
	regexp "github.com/wasilibs/go-re2"
)

var stripeObjectIDPat = regexp.MustCompile(`^(?:du|dp|pi|ch|in|re|txn|cus|sub|evt|po|tr|seti|price|prod|card|ba|src|tok|il|inv|cs|qt|cn|cr|or|py|ipi|rcpt)_[A-Za-z0-9]{12,}$`)

func IsStripeObjectID(s string) bool {
	return stripeObjectIDPat.MatchString(s)
}
