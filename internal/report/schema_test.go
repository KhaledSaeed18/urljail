package report

import (
	"bytes"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/protobuf/encoding/protojson"
)

// The generated JSON Schema (make gen) must accept what Write produces.
func TestReportMatchesSchema(t *testing.T) {
	c := jsonschema.NewCompiler()
	schema, err := c.Compile("../../api/schema/report.v0.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, withGuest := range []bool{true, false} {
		r, err := Build(writeRun(t, withGuest))
		if err != nil {
			t.Fatal(err)
		}
		b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("withGuest=%v: report doesn't match the schema: %v", withGuest, err)
		}
	}
}
