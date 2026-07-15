package oathcontracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedExamplesVerifyAndRejectMutation(t *testing.T) {
	examples := []string{
		"exec-assessment-v3.signed.json",
		"publish-assessment-v2.signed.json",
		"registry-verdict-v1.signed.json",
	}
	for _, name := range examples {
		contents, err := os.ReadFile(filepath.Join("..", "..", "examples", name))
		if err != nil {
			t.Fatal(err)
		}
		valid, err := VerifySignedDocument(contents)
		if err != nil || !valid {
			t.Fatalf("%s: signature rejected: %v", name, err)
		}
		var document map[string]any
		if err := json.Unmarshal(contents, &document); err != nil {
			t.Fatal(err)
		}
		document["generated_at"] = document["generated_at"].(float64) + 1
		mutated, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		valid, err = VerifySignedDocument(mutated)
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Fatalf("%s: mutation was accepted", name)
		}
	}
}

func TestVerifySignedDocumentRejectsTrailingJSON(t *testing.T) {
	valid, err := VerifySignedDocument([]byte(`{} {}`))
	if err == nil || valid {
		t.Fatalf("trailing JSON was not rejected: valid=%v err=%v", valid, err)
	}
}
