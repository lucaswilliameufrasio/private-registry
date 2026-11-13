package main

import (
	"crypto/subtle"
	"errors"
	"io"
	"os"

	"golang.org/x/term"
)

type administratorPrompt struct {
	LoginName   string
	DisplayName string
	Email       string
	Password    []byte
}

func promptAdministrator(input *os.File, output io.Writer) (administratorPrompt, error) {
	loginName, err := readTerminalLine(input, output, "Login username: ")
	if err != nil {
		return administratorPrompt{}, err
	}
	displayName, err := readTerminalLine(input, output, "Display name: ")
	if err != nil {
		return administratorPrompt{}, err
	}
	email, err := readTerminalLine(input, output, "Contact email: ")
	if err != nil {
		return administratorPrompt{}, err
	}

	password, err := readTerminalPassword(input, output, "Password (input hidden): ")
	if err != nil {
		return administratorPrompt{}, err
	}
	confirmation, err := readTerminalPassword(input, output, "Confirm password (input hidden): ")
	if err != nil {
		clear(password)
		return administratorPrompt{}, err
	}
	defer clear(confirmation)
	if subtle.ConstantTimeCompare(password, confirmation) != 1 {
		clear(password)
		return administratorPrompt{}, errors.New("password confirmation did not match")
	}

	return administratorPrompt{
		LoginName:   loginName,
		DisplayName: displayName,
		Email:       email,
		Password:    password,
	}, nil
}

func readTerminalLine(input *os.File, output io.Writer, prompt string) (string, error) {
	if input == nil || output == nil {
		return "", errors.New("terminal input could not be read")
	}
	if _, err := io.WriteString(output, prompt); err != nil {
		return "", errors.New("terminal prompt could not be written")
	}

	line := make([]byte, 0, 128)
	var next [1]byte
	for {
		read, err := input.Read(next[:])
		if read > 0 {
			if next[0] == '\n' {
				if len(line) > 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
				return string(line), nil
			}
			line = append(line, next[0])
			if len(line) > 2048 {
				return "", errors.New("terminal input exceeds the allowed size")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return string(line), nil
			}
			return "", errors.New("terminal input could not be read")
		}
		if read == 0 {
			return "", errors.New("terminal input could not be read")
		}
	}
}

func readTerminalPassword(input *os.File, output io.Writer, prompt string) ([]byte, error) {
	if input == nil || output == nil {
		return nil, errors.New("terminal password input could not be read")
	}
	if _, err := io.WriteString(output, prompt); err != nil {
		return nil, errors.New("terminal password prompt could not be written")
	}
	password, readErr := term.ReadPassword(int(input.Fd()))
	_, writeErr := io.WriteString(output, "\n")
	if readErr != nil {
		clear(password)
		return nil, errors.New("terminal password input could not be read")
	}
	if writeErr != nil {
		clear(password)
		return nil, errors.New("terminal password prompt could not be written")
	}
	return password, nil
}
