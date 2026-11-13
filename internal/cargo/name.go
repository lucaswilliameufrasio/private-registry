package cargo

import (
	"strings"
)

// NameIdentity returns a conservative collision key for the verified sparse
// name subset. ASCII case and '-' versus '_' collide, avoiding ambiguous Rust
// crate names. The caller must reserve this key transactionally and separately
// enforce repository scope; this function neither reserves nor authorizes it.
func NameIdentity(name string) (string, error) {
	if _, err := SparseIndexPath(name); err != nil {
		return "", err
	}
	return strings.ReplaceAll(strings.ToLower(name), "-", "_"), nil
}
