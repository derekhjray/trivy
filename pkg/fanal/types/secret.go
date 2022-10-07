package types

type SecretRuleCategory string

type Secret struct {
	FilePath string          `json:",omitempty"`
	FileInfo *FileInfo       `json:",omitempty"`
	Findings []SecretFinding `json:",omitempty"`
}

type SecretFinding struct {
	RuleID    string             `json:",omitempty"`
	Category  SecretRuleCategory `json:",omitempty"`
	Severity  string             `json:",omitempty"`
	Title     string             `json:",omitempty"`
	StartLine int                `json:",omitempty"`
	EndLine   int                `json:",omitempty"`
	Code      Code               `json:",omitempty"`
	Match     string             `json:",omitempty"`
	Layer     Layer              `json:",omitempty"`
}
