package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strings"

	"vertica-mcp-server/pkg/models"
)

const (
	// Query constants with parameterized placeholders to prevent SQL injection
	ShardCountQuery          = "SELECT COUNT(*) FROM SHARDS WHERE SHARD_TYPE != 'Replica'"
	StorageLocationQuery     = "SELECT location_path FROM storage_locations WHERE sharing_type = ?"
	DiskStorageLocationQuery = "SELECT NODE_NAME, STORAGE_PATH FROM DISK_STORAGE WHERE STORAGE_USAGE = ?"
	NodeCountQuery           = "SELECT COUNT(*) FROM NODES"
	SubclusterQuery          = "SELECT SUBCLUSTER_NAME, IS_PRIMARY FROM SUBCLUSTERS ORDER BY NODE_NAME"
	VersionQuery             = "SELECT VERSION()"
	DepotSizeQuery           = "SELECT MAX(DISK_SPACE_USED_MB+DISK_SPACE_FREE_MB) FROM DISK_STORAGE WHERE STORAGE_USAGE = 'DEPOT'"
	ConfigParametersQuery    = "SELECT parameter_name, current_value FROM configuration_parameters WHERE parameter_name ILIKE ?"
	SubclusterNodesQuery     = "SELECT DISTINCT node_name FROM subclusters WHERE subcluster_name = ? ORDER BY node_name"
	SubclusterSandboxQuery   = "SELECT DISTINCT sandbox FROM subclusters WHERE subcluster_name = ? LIMIT 1"
	NodesCountQuery          = "SELECT COUNT(*) FROM nodes"
	PrimaryNodeCountQuery    = "SELECT COUNT(DISTINCT node_name) FROM subclusters WHERE is_primary = true"
	AWSAuthQuery             = "SELECT parameter_name, current_value FROM configuration_parameters WHERE parameter_name = 'AWSAuth'"
)

// Repository provides database access methods
type Repository interface {
	InspectDatabase(ctx context.Context) (*models.DBInfo, error)
	InspectSubclusters(ctx context.Context) ([]models.SubclusterInfo, error)
	GetCommunalConfig(ctx context.Context, communalPath, dbName string) (*models.Communal, error)
	GetDepotSize(ctx context.Context) (float64, error)
	GetS3Credentials(ctx context.Context) (accessKey, secretKey string, err error)
	Close() error
}

// verticaRepository implements Repository for Vertica databases
type verticaRepository struct {
	db *sql.DB
}

// NewRepository creates a new database repository
func NewRepository(db *sql.DB) Repository {
	return &verticaRepository{db: db}
}

// InspectDatabase retrieves database metadata
func (r *verticaRepository) InspectDatabase(ctx context.Context) (*models.DBInfo, error) {
	info := &models.DBInfo{}

	// Get database name
	if err := r.db.QueryRowContext(ctx, "SELECT current_database()").Scan(&info.DatabaseName); err != nil {
		return nil, fmt.Errorf("failed to get database name: %w", err)
	}

	// Get version
	var versionStr string
	if err := r.db.QueryRowContext(ctx, VersionQuery).Scan(&versionStr); err != nil {
		return nil, fmt.Errorf("failed to get version: %w", err)
	}
	info.Version = extractVersion(versionStr)

	// Get communal storage location
	var locationPath sql.NullString
	err := r.db.QueryRowContext(ctx, StorageLocationQuery, "COMMUNAL").Scan(&locationPath)

	if err == sql.ErrNoRows {
		info.IsEon = false
		info.CommunalPath = ""
		log.Println("Detected Enterprise mode (no communal storage)")
	} else if err != nil {
		// Try alternative query
		err2 := r.db.QueryRowContext(ctx, "SELECT location_path FROM storage_locations WHERE sharing_type = 'COMMUNAL' LIMIT 1").Scan(&locationPath)
		if err2 == sql.ErrNoRows {
			info.IsEon = false
			info.CommunalPath = ""
			log.Println("Detected Enterprise mode (no communal storage)")
		} else if err2 != nil {
			return nil, fmt.Errorf("failed to query communal storage: %w", err2)
		} else {
			info.IsEon = true
			info.CommunalPath = locationPath.String
			log.Printf("Detected Eon mode with communal path: %s", info.CommunalPath)
		}
	} else {
		info.IsEon = locationPath.Valid
		if locationPath.Valid {
			info.CommunalPath = locationPath.String
			log.Printf("Detected Eon mode with communal path: %s", info.CommunalPath)
		} else {
			log.Println("Detected Enterprise mode")
		}
	}

	// Get data paths
	info.DataPath = r.getStoragePath(ctx, "DATA,TEMP", "/data")

	// Get depot paths
	info.DepotPath = r.getStoragePath(ctx, "DEPOT", "/depot")

	// Get catalog paths
	info.CatalogPath = r.getStoragePath(ctx, "CATALOG", "/data")

	// Get shard count
	if info.IsEon {
		var shardCount int
		err := r.db.QueryRowContext(ctx, ShardCountQuery).Scan(&shardCount)
		if err != nil {
			var primaryNodeCount int
			err = r.db.QueryRowContext(ctx, PrimaryNodeCountQuery).Scan(&primaryNodeCount)
			if err == nil && primaryNodeCount > 0 {
				info.ShardCount = primaryNodeCount * 2
			} else {
				info.ShardCount = 6 // default
			}
		} else {
			info.ShardCount = shardCount
		}
	} else {
		var nodeCount int
		err := r.db.QueryRowContext(ctx, NodeCountQuery).Scan(&nodeCount)
		if err == nil {
			info.ShardCount = nodeCount
		} else {
			info.ShardCount = 3 // default
		}
	}

	// Get depot size (matches vdbgen implementation)
	info.DepotSizeMB, err = r.GetDepotSize(ctx)
	if err != nil {
		log.Printf("⚠️  Could not retrieve depot size: %v, using default", err)
		info.DepotSizeMB = 0
	}

	// Get catalog size (matches vdbgen implementation)
	info.CatalogSizeMB, err = r.getCatalogSize(ctx)
	if err != nil {
		log.Printf("⚠️  Could not retrieve catalog size: %v, using default", err)
		info.CatalogSizeMB = 0
	}

	// Calculate total request size (depot + catalog)
	info.RequestSizeMB = info.DepotSizeMB + info.CatalogSizeMB
	if info.RequestSizeMB > 0 {
		log.Printf("✓ Retrieved storage sizes: Depot=%.0fMi, Catalog=%.0fMi, Total=%.0fMi",
			info.DepotSizeMB, info.CatalogSizeMB, info.RequestSizeMB)
	}

	return info, nil
}

// getStoragePath retrieves storage path for a given usage type
func (r *verticaRepository) getStoragePath(ctx context.Context, usageType, defaultPath string) string {
	rows, err := r.db.QueryContext(ctx, DiskStorageLocationQuery, usageType)
	if err != nil {
		log.Printf("query error for %s: %v", usageType, err)
		return defaultPath
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var nodeName, storagePath string
		if err := rows.Scan(&nodeName, &storagePath); err != nil {
			log.Printf("scan error: %v", err)
			continue
		}
		paths = append(paths, storagePath)
	}

	if len(paths) > 0 {
		return paths[0]
	}
	return defaultPath
}

// InspectSubclusters retrieves subcluster information
func (r *verticaRepository) InspectSubclusters(ctx context.Context) ([]models.SubclusterInfo, error) {
	var subclusters []models.SubclusterInfo

	rows, err := r.db.QueryContext(ctx, SubclusterQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query subclusters: %w", err)
	}
	defer rows.Close()

	scMap := make(map[string]*models.SubclusterInfo)
	for rows.Next() {
		var scName string
		var isPrimary bool
		if err := rows.Scan(&scName, &isPrimary); err != nil {
			log.Printf("Warning: failed to scan subcluster row: %v", err)
			continue
		}

		if _, exists := scMap[scName]; !exists {
			scMap[scName] = &models.SubclusterInfo{
				Name:      scName,
				IsPrimary: isPrimary,
				Nodes:     []string{},
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating subcluster rows: %w", err)
	}

	// Get nodes for each subcluster
	for scName, sc := range scMap {
		nodeRows, err := r.db.QueryContext(ctx, SubclusterNodesQuery, scName)
		if err != nil {
			log.Printf("Warning: failed to query nodes for subcluster %s: %v", scName, err)
			sc.NodeCount = 0
			continue
		}

		for nodeRows.Next() {
			var nodeName string
			if err := nodeRows.Scan(&nodeName); err != nil {
				log.Printf("Warning: failed to scan node name: %v", err)
				continue
			}
			sc.Nodes = append(sc.Nodes, nodeName)
		}
		nodeRows.Close()

		sc.NodeCount = len(sc.Nodes)

		// Get sandbox name
		var sandboxName sql.NullString
		err = r.db.QueryRowContext(ctx, SubclusterSandboxQuery, scName).Scan(&sandboxName)
		if err == nil && sandboxName.Valid {
			sc.SandboxName = sandboxName.String
		}
	}

	// Convert map to slice
	for _, sc := range scMap {
		subclusters = append(subclusters, *sc)
	}

	// Sort subclusters
	sort.Slice(subclusters, func(i, j int) bool {
		if subclusters[i].IsPrimary != subclusters[j].IsPrimary {
			return subclusters[i].IsPrimary
		}
		return subclusters[i].Name < subclusters[j].Name
	})

	// Handle Enterprise mode
	if len(subclusters) == 0 {
		log.Println("WARNING: No subclusters found - likely Enterprise mode database, creating default subcluster")

		var nodeCount int
		err := r.db.QueryRowContext(ctx, NodesCountQuery).Scan(&nodeCount)
		if err != nil {
			log.Printf("WARNING: Could not query node count: %v, defaulting to 3 nodes", err)
			nodeCount = 3
		}

		subclusters = append(subclusters, models.SubclusterInfo{
			Name:      "default_subcluster",
			IsPrimary: true,
			NodeCount: nodeCount,
		})
	}

	return subclusters, nil
}

// GetCommunalConfig retrieves communal configuration from database
func (r *verticaRepository) GetCommunalConfig(ctx context.Context, communalPath, dbName string) (*models.Communal, error) {
	communal := &models.Communal{
		Path: communalPath,
	}

	// Query AWS-related parameters
	rows, err := r.db.QueryContext(ctx, ConfigParametersQuery, "%AWS%")
	if err != nil {
		return communal, nil // Return basic config if query fails
	}
	defer rows.Close()

	params := make(map[string]string)
	for rows.Next() {
		var paramName, currentValue string
		if err := rows.Scan(&paramName, &currentValue); err != nil {
			continue
		}
		params[paramName] = currentValue
	}

	// Extract configuration from parameters
	if endpoint, ok := params["AWSEndpoint"]; ok && endpoint != "" {
		communal.Endpoint = endpoint
	}
	if region, ok := params["AWSRegion"]; ok && region != "" {
		communal.Region = region
	}

	// Set credential secret name
	communal.CredentialSecret = fmt.Sprintf("%s-s3-creds", dbName)

	return communal, nil
}

// GetDepotSize retrieves the depot size in MB (matches vdbgen implementation)
func (r *verticaRepository) GetDepotSize(ctx context.Context) (float64, error) {
	var depotSizeMB float64
	err := r.db.QueryRowContext(ctx, DepotSizeQuery).Scan(&depotSizeMB)
	if err != nil {
		return 0, err
	}
	return depotSizeMB, nil
}

// getCatalogSize retrieves the catalog + data size in MB (matches vdbgen implementation)
func (r *verticaRepository) getCatalogSize(ctx context.Context) (float64, error) {
	var catalogSizeMB float64
	// Query matches vdbgen: MAX(DISK_SPACE_USED_MB+DISK_SPACE_FREE_MB) for CATALOG or DATA,TEMP
	query := "SELECT MAX(DISK_SPACE_USED_MB+DISK_SPACE_FREE_MB) FROM DISK_STORAGE WHERE STORAGE_USAGE IN ('CATALOG','DATA,TEMP')"
	err := r.db.QueryRowContext(ctx, query).Scan(&catalogSizeMB)
	if err != nil {
		return 0, err
	}
	return catalogSizeMB, nil
}

// GetS3Credentials retrieves S3 access and secret keys from database (matches vdbgen implementation)
func (r *verticaRepository) GetS3Credentials(ctx context.Context) (accessKey, secretKey string, err error) {
	var paramName, authValue string
	err = r.db.QueryRowContext(ctx, AWSAuthQuery).Scan(&paramName, &authValue)
	if err == sql.ErrNoRows {
		// No AWS credentials configured
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("failed to query AWS credentials: %w", err)
	}

	// Parse credentials in format "accessKey:secretKey" (matches vdbgen implementation)
	// vdbgen uses regexp.MustCompile(`:`) and splits into 2 components
	parts := strings.SplitN(authValue, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid AWSAuth format: expected 'accessKey:secretKey', got %d parts", len(parts))
	}

	return parts[0], parts[1], nil
}

// Close closes the database connection
func (r *verticaRepository) Close() error {
	return r.db.Close()
}

// extractVersion extracts version number from version string
func extractVersion(versionStr string) string {
	// Version string format: "Vertica Analytic Database v25.1.0-0"
	// Extract just the version number
	if len(versionStr) > 0 {
		// Simple extraction - can be enhanced
		return versionStr
	}
	return "unknown"
}
