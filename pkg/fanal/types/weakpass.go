package types

import stypes "gitee.com/anesec/ferret/secrets/types"

type WeakPassword struct {
	stypes.WeakPassword `json:",omitempty"`
	Layer               Layer `json:",omitempty"`
}
