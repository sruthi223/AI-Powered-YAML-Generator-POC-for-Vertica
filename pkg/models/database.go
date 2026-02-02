package models

// DBInfo contains information about a Vertica database
type DBInfo struct {
	DatabaseName string
	Version      string
	IsEon        bool
	ShardCount   int
	CommunalPath string
	DataPath     string
	DepotPath    string
	CatalogPath  string
	// Storage sizes in MB (retrieved from actual database)
	DepotSizeMB   float64
	CatalogSizeMB float64
	RequestSizeMB float64 // Combined depot + catalog size
}

// SubclusterInfo contains information about a Vertica subcluster
type SubclusterInfo struct {
	Name        string
	IsPrimary   bool
	NodeCount   int
	Nodes       []string
	SandboxName string
}

// SubclusterSpec represents a subcluster specification
type SubclusterSpec struct {
	Name string
	Size int
	Type string
}
