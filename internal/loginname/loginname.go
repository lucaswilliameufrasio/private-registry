package loginname

import "strings"

func Normalize(value string) string {
	value = strings.TrimSpace(value)
	for _, character := range value {
		if character > 0x7f {
			return ""
		}
	}
	return strings.ToLower(value)
}

func Valid(value string) bool {
	if len(value) < 3 || len(value) > 63 {
		return false
	}
	for index, character := range value {
		isAlphanumeric := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		if index == 0 || index == len(value)-1 {
			if !isAlphanumeric {
				return false
			}
			continue
		}
		if !isAlphanumeric && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
