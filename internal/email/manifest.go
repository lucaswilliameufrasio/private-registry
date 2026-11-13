package email

import "encoding/json"

type manifestVariable struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Example  string `json:"example"`
}

type manifestTemplate struct {
	ID              string             `json:"id"`
	ApplicationID   *string            `json:"application_id"`
	TemplateKey     string             `json:"template_key"`
	Name            string             `json:"name"`
	Channel         string             `json:"channel"`
	Locale          string             `json:"locale"`
	EditorMode      string             `json:"editor_mode"`
	SubjectTemplate string             `json:"subject_template"`
	HTMLSource      string             `json:"html_source"`
	TextSource      string             `json:"text_source"`
	Variables       []manifestVariable `json:"variables"`
	PreviewData     map[string]string  `json:"preview_data"`
}

// SabiaManifest returns the Sabiá templates-as-code manifest
// (sabia/templates.json) generated from the same sources Render uses, so a
// message reads the same through every provider.
func SabiaManifest() ([]byte, error) {
	templates := make([]manifestTemplate, 0, len(definitions))
	for _, item := range definitions {
		entry := manifestTemplate{ID: item.ID, TemplateKey: string(item.Key), Name: item.Name, Channel: "email", Locale: Locale, EditorMode: "html", SubjectTemplate: item.Subject, HTMLSource: item.HTML, TextSource: item.Text, PreviewData: map[string]string{}}
		for _, v := range item.Vars {
			entry.Variables = append(entry.Variables, manifestVariable{Key: v.Key, Label: v.Label, Type: string(v.Type), Required: true, Example: v.Example})
			entry.PreviewData[v.Key] = v.Example
		}
		templates = append(templates, entry)
	}
	encoded, err := json.MarshalIndent(map[string]any{"version": 1, "templates": templates}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
