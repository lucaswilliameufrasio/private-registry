package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/term"
	"private-registry/internal/gomod"
)

const publishUsage = "usage: registryctl publish go -url HTTPS_ORIGIN -workspace UUID -repository UUID -dir DIRECTORY -version VERSION -source-time RFC3339 -login NAME"

func runPublishGo(ctx context.Context, args []string, out io.Writer) (retErr error) {
	flags := flag.NewFlagSet("publish go", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	origin := flags.String("url", "", "registry HTTPS origin")
	workspace := flags.String("workspace", "", "workspace ID")
	repository := flags.String("repository", "", "repository ID")
	dir := flags.String("dir", "", "module directory")
	version := flags.String("version", "", "module version")
	sourceTime := flags.String("source-time", "", "explicit source time")
	login := flags.String("login", "", "login name")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *dir == "" || *version == "" || *login == "" || out == nil {
		return errors.New(publishUsage)
	}
	parsed, err := url.Parse(*origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("registry URL must be an HTTPS origin")
	}
	for _, id := range []string{*workspace, *repository} {
		parsedID, err := uuid.Parse(id)
		if err != nil || parsedID.String() != id {
			return errors.New("workspace and repository must be canonical UUIDs")
		}
	}
	when, err := time.Parse(time.RFC3339Nano, *sourceTime)
	if err != nil {
		return errors.New("source time must be an explicit RFC3339 timestamp")
	}
	archive, err := os.CreateTemp("", "registryctl-go-*.zip")
	if err != nil {
		return errors.New("temporary archive could not be created")
	}
	defer func() {
		_ = archive.Close()
		_ = os.Remove(archive.Name())
	}()
	operation, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	packed, err := gomod.PackDirectory(operation, *dir, *version, archive, 10000)
	if err != nil {
		return err
	}
	base := strings.TrimSuffix(parsed.String(), "/")
	client, err := authenticateInteractive(operation, base, *login)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, logoutInteractiveSession(client, base))
		client.CloseIdleConnections()
	}()
	return uploadPackedGo(operation, client, base, *workspace, *repository, when, packed, archive, out)
}

func authenticateInteractive(ctx context.Context, base, login string) (*http.Client, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("interactive terminal required for password and MFA")
	}
	_, _ = fmt.Fprint(os.Stderr, "Password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, errors.New("password could not be read")
	}
	defer clear(password)
	client, err := newRegistryClient()
	if err != nil {
		return nil, err
	}
	stage, err := loginForPublish(ctx, client, base, login, string(password))
	clear(password)
	if err != nil {
		client.CloseIdleConnections()
		return nil, err
	}
	if stage != "mfa_challenge" {
		logoutErr := logoutInteractiveSession(client, base)
		client.CloseIdleConnections()
		return nil, errors.Join(errors.New("publication requires an enrolled MFA credential; enroll in the web interface first"), logoutErr)
	}
	_, _ = fmt.Fprint(os.Stderr, "MFA code: ")
	code, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		logoutErr := logoutInteractiveSession(client, base)
		client.CloseIdleConnections()
		return nil, errors.Join(errors.New("MFA code could not be read"), logoutErr)
	}
	defer clear(code)
	if _, err := publishJSON(ctx, client, base, http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]string{"code": string(code)}, true); err != nil {
		logoutErr := logoutInteractiveSession(client, base)
		client.CloseIdleConnections()
		return nil, errors.Join(err, logoutErr)
	}
	clear(code)
	return client, nil
}

func newRegistryClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, errors.New("session could not be created")
	}
	return &http.Client{Jar: jar, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func runPublicationAction(ctx context.Context, action string, args []string, out io.Writer) (retErr error) {
	const usage = "usage: registryctl publication {status|finalize} -url HTTPS_ORIGIN -workspace UUID -repository UUID -id UUID -login NAME"
	flags := flag.NewFlagSet("publication "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	origin := flags.String("url", "", "registry HTTPS origin")
	workspace := flags.String("workspace", "", "workspace ID")
	repository := flags.String("repository", "", "repository ID")
	id := flags.String("id", "", "upload session ID")
	login := flags.String("login", "", "login name")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *login == "" || out == nil {
		return errors.New(usage)
	}
	parsed, err := url.Parse(*origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("registry URL must be an HTTPS origin")
	}
	for _, value := range []string{*workspace, *repository, *id} {
		parsedID, err := uuid.Parse(value)
		if err != nil || parsedID.String() != value {
			return errors.New("workspace, repository and session must be canonical UUIDs")
		}
	}
	operation, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	base := strings.TrimSuffix(parsed.String(), "/")
	client, err := authenticateInteractive(operation, base, *login)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, logoutInteractiveSession(client, base))
		client.CloseIdleConnections()
	}()
	path := "/api/v1/workspaces/" + *workspace + "/repositories/" + *repository + "/go/uploads/" + *id
	return publicationAction(operation, client, base, path, action, out)
}

// Logout gets a separate bounded context so a cancelled operation does not
// silently leave its authenticated session active until idle expiry.
func logoutInteractiveSession(client *http.Client, base string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := publishRequest(ctx, client, base, http.MethodPost, "/api/v1/auth/logout", "", nil, true); err != nil {
		return errors.New("session logout was not confirmed; it will remain subject to server expiry or revocation")
	}
	return nil
}

func publicationAction(ctx context.Context, client *http.Client, base, path, action string, out io.Writer) error {
	status, err := readPublicationStatus(ctx, client, base, path)
	if err != nil {
		return err
	}
	if action == "status" {
		return json.NewEncoder(out).Encode(status)
	}
	if action != "finalize" || status.Invalidated {
		return errors.New("publication requires reconciliation")
	}
	if status.Status == "published" {
		_, err := fmt.Fprintln(out, "published")
		return err
	}
	if status.Status != "uploaded" || (status.ReviewState != "approved" && status.ReviewState != "not_required") {
		return errors.New("publication is not ready; inspect its status before retrying")
	}
	if _, err := publishRequest(ctx, client, base, http.MethodPost, path+"/publish", "", nil, true); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "published")
	return err
}

func loginForPublish(ctx context.Context, client *http.Client, base, login, password string) (string, error) {
	body, err := publishJSON(ctx, client, base, http.MethodPost, "/api/v1/auth/login", map[string]string{"login_name": login, "password": password}, false)
	if err != nil {
		return "", err
	}
	var response struct {
		Stage string `json:"stage"`
	}
	if err := json.Unmarshal(body, &response); err != nil || response.Stage == "" {
		return "", errors.New("registry login response is invalid")
	}
	return response.Stage, nil
}

func publishJSON(ctx context.Context, client *http.Client, base, method, path string, value any, csrf bool) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("registry request could not be prepared")
	}
	return publishRequest(ctx, client, base, method, path, "application/json", bytes.NewReader(body), csrf)
}

func publishRequest(ctx context.Context, client *http.Client, base, method, path, contentType string, body io.Reader, csrf bool) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return nil, errors.New("registry request could not be prepared")
	}
	request.Header.Set("Origin", base)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if csrf {
		var token string
		for _, cookie := range client.Jar.Cookies(request.URL) {
			if cookie.Name == "__Host-registry-csrf" {
				token = cookie.Value
			}
		}
		if token == "" {
			return nil, errors.New("registry session is unavailable")
		}
		request.Header.Set("X-CSRF-Token", token)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("registry request failed; outcome may be unknown")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("registry response could not be read; outcome may be unknown")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("registry request returned HTTP %d", response.StatusCode)
	}
	return data, nil
}

func uploadPackedGo(ctx context.Context, client *http.Client, base, workspace, repository string, when time.Time, packed gomod.PackedModule, archive io.Reader, out io.Writer) error {
	path := "/api/v1/workspaces/" + workspace + "/repositories/" + repository + "/go/uploads"
	data, err := publishJSON(ctx, client, base, http.MethodPost, path, struct {
		ModulePath string `json:"module_path"`
		Version    string `json:"version"`
		SourceTime string `json:"source_time"`
		GoMod      string `json:"go_mod"`
		ZipSize    int64  `json:"zip_size"`
		ZipSHA256  string `json:"zip_sha256"`
	}{packed.ModulePath, packed.Version, when.UTC().Format(time.RFC3339Nano), string(packed.ModBytes), packed.ZipSize, packed.ZipSHA256}, true)
	if err != nil {
		return err
	}
	var receipt struct {
		ID string `json:"upload_session_id"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		return errors.New("registry reservation response is invalid")
	}
	id, err := uuid.Parse(receipt.ID)
	if err != nil || id.String() != receipt.ID {
		return errors.New("registry reservation response is invalid")
	}
	if _, err := fmt.Fprintf(out, "upload_session_id: %s\n", receipt.ID); err != nil {
		return errors.New("reservation created but its identity could not be written")
	}
	statusPath := path + "/" + receipt.ID
	status, err := readPublicationStatus(ctx, client, base, statusPath)
	if err != nil {
		return err
	}
	switch status.Status {
	case "receiving":
		if _, err := publishRequest(ctx, client, base, http.MethodPut, statusPath+"/content", "application/octet-stream", archive, true); err != nil {
			return err
		}
		status, err = readPublicationStatus(ctx, client, base, statusPath)
		if err != nil {
			return err
		}
	case "uploaded":
		// An earlier identical request may have succeeded before its response was lost.
	case "published":
		_, err := fmt.Fprintln(out, "published")
		return err
	default:
		return errors.New("upload session requires reconciliation before retrying")
	}
	if status.Invalidated || status.Status != "uploaded" {
		return errors.New("upload receipt requires reconciliation")
	}
	if status.ReviewState == "awaiting_review" {
		_, err := fmt.Fprintln(out, "uploaded; awaiting human review (not published)")
		return err
	}
	if status.ReviewState != "not_required" && status.ReviewState != "approved" {
		return errors.New("upload review state requires reconciliation")
	}
	if _, err := publishRequest(ctx, client, base, http.MethodPost, statusPath+"/publish", "", nil, true); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "published")
	return err
}

type publicationStatus struct {
	Status      string `json:"status"`
	ReviewState string `json:"review_state"`
	Invalidated bool   `json:"recovery_invalidated"`
}

func readPublicationStatus(ctx context.Context, client *http.Client, base, path string) (publicationStatus, error) {
	data, err := publishRequest(ctx, client, base, http.MethodGet, path, "", nil, false)
	if err != nil {
		return publicationStatus{}, err
	}
	var status publicationStatus
	if err := json.Unmarshal(data, &status); err != nil || status.Status == "" || status.ReviewState == "" {
		return publicationStatus{}, errors.New("registry upload status response is invalid")
	}
	return status, nil
}
