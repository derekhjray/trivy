package types

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

type DetectedWeakPassword ftypes.WeakPassword

func (DetectedWeakPassword) findingType() FindingType { return FindingTypeWeakPassword }
