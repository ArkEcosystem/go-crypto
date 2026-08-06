package crypto

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	UnitWei  = "wei"
	UnitGwei = "gwei"
	UnitArk  = "ark"
)

var ErrUnsupportedUnit = errors.New("crypto: unsupported unit")

func unitDecimals(unit string) (int, error) {
	switch strings.ToLower(unit) {
	case UnitWei:
		return 0, nil
	case UnitGwei:
		return 9, nil
	case UnitArk:
		return 18, nil
	default:
		return 0, fmt.Errorf("%w: %q (supported units are %q, %q, and %q)", ErrUnsupportedUnit, unit, UnitWei, UnitGwei, UnitArk)
	}
}

func ParseUnits(value string, unit string) (*big.Int, error) {
	decimals, err := unitDecimals(unit)
	if err != nil {
		return nil, err
	}

	negative := strings.HasPrefix(value, "-")
	v := strings.TrimPrefix(value, "-")

	if v == "" || strings.Contains(v, "-") {
		return nil, fmt.Errorf("crypto: %q is not a valid decimal number", value)
	}

	intPart, fracPart := v, ""
	if i := strings.IndexByte(v, '.'); i >= 0 {
		intPart, fracPart = v[:i], v[i+1:]
	}
	if intPart == "" {
		intPart = "0"
	}

	if len(fracPart) > decimals {
		if strings.Trim(fracPart[decimals:], "0") != "" {
			return nil, fmt.Errorf("crypto: %s has more precision than %s (%d decimals) supports", value, unit, decimals)
		}
		fracPart = fracPart[:decimals]
	} else {
		fracPart += strings.Repeat("0", decimals-len(fracPart))
	}

	digits := strings.TrimLeft(intPart+fracPart, "0")
	if digits == "" {
		digits = "0"
	}

	result, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return nil, fmt.Errorf("crypto: %q is not a valid decimal number", value)
	}
	if negative {
		result.Neg(result)
	}

	return result, nil
}

func FormatUnits(valueWei *big.Int, unit string) (string, error) {
	decimals, err := unitDecimals(unit)
	if err != nil {
		return "", err
	}

	negative := valueWei.Sign() < 0
	digits := new(big.Int).Abs(valueWei).String()

	if len(digits) <= decimals {
		digits = strings.Repeat("0", decimals-len(digits)+1) + digits
	}

	intPart := digits[:len(digits)-decimals]
	fracPart := strings.TrimRight(digits[len(digits)-decimals:], "0")

	result := intPart
	if fracPart != "" {
		result += "." + fracPart
	}
	if negative && result != "0" {
		result = "-" + result
	}

	return result, nil
}

func withUnitSuffix(value string, suffix []string) string {
	if len(suffix) > 0 && suffix[0] != "" {
		return value + " " + suffix[0]
	}
	return value
}

func WeiToArk(valueWei *big.Int, suffix ...string) string {
	formatted, _ := FormatUnits(valueWei, UnitArk)
	return withUnitSuffix(formatted, suffix)
}

func GweiToArk(valueGwei *big.Int, suffix ...string) string {
	wei := new(big.Int).Mul(valueGwei, big.NewInt(1_000_000_000))
	formatted, _ := FormatUnits(wei, UnitArk)
	return withUnitSuffix(formatted, suffix)
}
