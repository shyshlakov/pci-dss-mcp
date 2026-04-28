package taint_ssa

import (
	"go/constant"
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/ssa"
)

// minHardcodedKeyBytes mirrors the AST engine's >= 16 char heuristic for
// hardcoded-key detection (scanner/cryptoscanner/hardcoded.go). Aligns
// with crypto/aes minimum key size of 16 bytes.
const minHardcodedKeyBytes = 16

// cryptoSinkSpecs identifies the (package path, function or method name)
// pairs that count as crypto sinks for the PoC. AES, DES, cipher modes,
// and HMAC are the parity surface.
var cryptoSinkSpecs = []struct {
	pkg  string
	name string
}{
	{"crypto/aes", "NewCipher"},
	{"crypto/des", "NewCipher"},
	{"crypto/des", "NewTripleDESCipher"},
	{"crypto/cipher", "NewCBCEncrypter"},
	{"crypto/cipher", "NewCBCDecrypter"},
	{"crypto/cipher", "NewGCM"},
	{"crypto/cipher", "NewGCMWithNonceSize"},
	{"crypto/cipher", "NewGCMWithTagSize"},
	{"crypto/cipher", "NewCFBEncrypter"},
	{"crypto/cipher", "NewCFBDecrypter"},
	{"crypto/cipher", "NewCTR"},
	{"crypto/cipher", "NewOFB"},
	{"crypto/hmac", "New"},
}

func init() {
	hardcodedKeySourceImpl = hardcodedKeySourceConcrete
	cryptoSinkImpl = cryptoSinkConcrete
}

func hardcodedKeySourceConcrete(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	if !ok || c.Value == nil {
		return false
	}
	if !isStringOrByteSliceType(c.Type()) {
		return false
	}
	if c.Value.Kind() != constant.String {
		return false
	}
	s := constant.StringVal(c.Value)
	return len(s) >= minHardcodedKeyBytes
}

func isStringOrByteSliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	if basic, ok := t.Underlying().(*types.Basic); ok {
		return basic.Kind() == types.String || basic.Kind() == types.UntypedString
	}
	if slice, ok := t.Underlying().(*types.Slice); ok {
		if elem, ok := slice.Elem().Underlying().(*types.Basic); ok {
			return elem.Kind() == types.Byte || elem.Kind() == types.Uint8
		}
	}
	return false
}

func cryptoSinkConcrete(call *ssa.Call) bool {
	if call == nil {
		return false
	}
	pkg, name := calleePackageAndName(call)
	for _, spec := range cryptoSinkSpecs {
		if pkg == spec.pkg && name == spec.name {
			return true
		}
	}
	return false
}

// RunCryptoHardcodedKey scans every SSA function for hardcoded-key
// constants that flow to a crypto sink call. Findings are deduplicated by
// (file, line).
func RunCryptoHardcodedKey(p *Program) []Finding {
	if p == nil {
		return nil
	}
	var out []Finding
	seen := map[string]bool{}
	for _, fn := range p.Functions() {
		if fn == nil {
			continue
		}
		for _, f := range scanCryptoHardcodedKeyInFunction(p, fn) {
			key := f.File + ":" + strconv.Itoa(f.Line)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

// scanCryptoHardcodedKeyInFunction walks crypto sink calls inside fn and,
// for each, performs a backward scan of the call's arg-producing
// instructions to find a *ssa.Const whose payload meets the hardcoded-key
// heuristic. Backward instead of forward because *ssa.Const has no
// Referrers list (constants are interned and shared).
func scanCryptoHardcodedKeyInFunction(p *Program, fn *ssa.Function) []Finding {
	var out []Finding
	for _, block := range fn.Blocks {
		if block == nil {
			continue
		}
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok || !cryptoSinkConcrete(call) {
				continue
			}
			common := call.Common()
			if common == nil {
				continue
			}
			for _, arg := range common.Args {
				if c := findHardcodedKeyConst(arg, taintWalkBudget); c != nil {
					pos := p.Prog.Fset.Position(constSourcePos(c, call))
					out = append(out, Finding{
						RuleID:      "CRYPTO-HARDCODED-KEY",
						File:        pos.Filename,
						Line:        pos.Line,
						Description: "Hardcoded constant flows to crypto sink",
					})
					break
				}
			}
		}
	}
	return out
}

func constSourcePos(c *ssa.Const, fallback *ssa.Call) token.Pos {
	if pos := c.Pos(); pos != token.NoPos {
		return pos
	}
	if fallback != nil {
		return fallback.Pos()
	}
	return token.NoPos
}

// findHardcodedKeyConst walks backward through SSA value-producing
// instructions to locate a hardcoded-key *ssa.Const that ultimately feeds
// the seed value. Recognizes Const, UnOp (deref), Convert, ChangeType,
// Slice, IndexAddr, FieldAddr loads, and Call args (1-operand pass-through
// helpers like []byte conversion).
func findHardcodedKeyConst(v ssa.Value, budget int) *ssa.Const {
	visited := map[ssa.Value]bool{}
	var walk func(v ssa.Value, remaining int) *ssa.Const
	walk = func(v ssa.Value, remaining int) *ssa.Const {
		if v == nil || remaining <= 0 || visited[v] {
			return nil
		}
		visited[v] = true
		switch x := v.(type) {
		case *ssa.Const:
			if hardcodedKeySourceConcrete(x) {
				return x
			}
		case *ssa.UnOp:
			return walk(x.X, remaining-1)
		case *ssa.Convert:
			return walk(x.X, remaining-1)
		case *ssa.ChangeType:
			return walk(x.X, remaining-1)
		case *ssa.Slice:
			return walk(x.X, remaining-1)
		case *ssa.MakeInterface:
			return walk(x.X, remaining-1)
		case *ssa.FieldAddr:
			return walk(x.X, remaining-1)
		case *ssa.IndexAddr:
			return walk(x.X, remaining-1)
		case *ssa.Phi:
			for _, edge := range x.Edges {
				if found := walk(edge, remaining-1); found != nil {
					return found
				}
			}
		case *ssa.Call:
			common := x.Common()
			if common != nil {
				for _, arg := range common.Args {
					if found := walk(arg, remaining-1); found != nil {
						return found
					}
				}
			}
		case *ssa.Alloc:
			return walkAllocBack(x, remaining-1, walk)
		}
		return nil
	}
	return walk(v, budget)
}

// walkAllocBack scans Stores into an allocation and recurses into the
// stored values. Models the pattern key := []byte("..."); aes.NewCipher(key).
func walkAllocBack(alloc *ssa.Alloc, remaining int, walk func(ssa.Value, int) *ssa.Const) *ssa.Const {
	referrers := alloc.Referrers()
	if referrers == nil {
		return nil
	}
	for _, ref := range *referrers {
		if store, ok := ref.(*ssa.Store); ok {
			if found := walk(store.Val, remaining); found != nil {
				return found
			}
		}
	}
	return nil
}
