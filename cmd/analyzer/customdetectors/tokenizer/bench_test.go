package tokenizer

import (
	"context"
	"strings"
	"testing"
)

func syntheticInput(size int) string {
	var b strings.Builder
	unit := `password=aB3xKp9Qm2Lr7TzWqDv token: xyz123abc456Def please rotate the credential before friday `
	for b.Len() < size {
		b.WriteString(unit)
	}
	return b.String()[:size]
}

func benchmarkTokenize(b *testing.B, tk Tokenizer) {
	sizes := []int{64 << 10, 256 << 10, 1 << 20}
	for _, size := range sizes {
		input := syntheticInput(size)
		b.Run(sizeName(size), func(b *testing.B) {
			ctx := context.Background()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = tk.Tokenize(ctx, input)
			}
		})
	}
}

func sizeName(size int) string {
	switch size {
	case 64 << 10:
		return "64KiB"
	case 256 << 10:
		return "256KiB"
	case 1 << 20:
		return "1MiB"
	default:
		return "unknown"
	}
}

func BenchmarkTokenizeWhitespace(b *testing.B) {
	benchmarkTokenize(b, whitespaceTokenizer{})
}

func BenchmarkTokenizeStructural(b *testing.B) {
	benchmarkTokenize(b, structuralTokenizer{})
}
