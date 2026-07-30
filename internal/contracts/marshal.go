package contracts

import "encoding/json"

func marshalCanonical(value any) ([]byte, error) { return json.Marshal(value) }
