package models

// VerticaDB represents a Kubernetes VerticaDB custom resource
type VerticaDB struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// Secret represents a Kubernetes Secret resource
type Secret struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   Metadata          `yaml:"metadata"`
	Data       map[string]string `yaml:"data,omitempty"`
}

// ConfigMap represents a Kubernetes ConfigMap resource
type ConfigMap struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   Metadata          `yaml:"metadata"`
	Data       map[string]string `yaml:"data,omitempty"`
}

// KObjs represents all Kubernetes objects to be generated
type KObjs struct {
	Vdb                     VerticaDB
	CredSecret              Secret
	HasLicense              bool
	LicenseSecret           Secret
	HasPassword             bool
	SuperuserPasswordSecret Secret
	HasCAFile               bool
	CAFile                  Secret
	HasHadoopConfig         bool
	HadoopConfig            ConfigMap
	HasKerberosSecret       bool
	KerberosSecret          Secret
}

type LocalObjectReference struct {
	Name string `yaml:"name"`
}

type Spec struct {
	Image                      string                      `yaml:"image,omitempty"`
	Subclusters                []Subcluster                `yaml:"subclusters"`
	TemporarySubclusterRouting *TemporarySubclusterRouting `yaml:"temporarySubclusterRouting,omitempty"`
	ShardCount                 int                         `yaml:"shardCount,omitempty"`
	Communal                   *Communal                   `yaml:"communal,omitempty"`
	Local                      *Local                      `yaml:"local,omitempty"`
	Sandboxes                  []Sandbox                   `yaml:"sandboxes,omitempty"`

	InitPolicy   string        `yaml:"initPolicy,omitempty"`
	DBName       string        `yaml:"dbName,omitempty"`
	RestorePoint *RestorePoint `yaml:"restorePoint,omitempty"`
	ReviveOrder  []ReviveStep  `yaml:"reviveOrder,omitempty"`

	UpgradePolicy string `yaml:"upgradePolicy,omitempty"`

	SuperuserPasswordSecret string `yaml:"superuserPasswordSecret,omitempty"`
	PasswordSecret          string `yaml:"passwordSecret,omitempty"`
	KerberosSecret          string `yaml:"kerberosSecret,omitempty"`
	LicenseSecret           string `yaml:"licenseSecret,omitempty"`
	EncryptSpreadComm       string `yaml:"encryptSpreadComm,omitempty"`

	CertSecrets    []LocalObjectReference `yaml:"certSecrets,omitempty"`
	Certifications *Certifications        `yaml:"certifications,omitempty"`

	Volumes      []Volume      `yaml:"volumes,omitempty"`
	VolumeMounts []VolumeMount `yaml:"volumeMounts,omitempty"`

	LivenessProbeOverride  *Probe `yaml:"livenessProbeOverride,omitempty"`
	ReadinessProbeOverride *Probe `yaml:"readinessProbeOverride,omitempty"`
	StartupProbeOverride   *Probe `yaml:"startupProbeOverride,omitempty"`

	Sidecars []Container `yaml:"sidecars,omitempty"`

	PodSecurityContext *PodSecurityContext `yaml:"podSecurityContext,omitempty"`
	SecurityContext    *SecurityContext    `yaml:"securityContext,omitempty"`

	ServiceAccountName string `yaml:"serviceAccountName,omitempty"`

	ImagePullSecrets []ImagePullSecret `yaml:"imagePullSecrets,omitempty"`
	ImagePullPolicy  string            `yaml:"imagePullPolicy,omitempty"`

	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`

	// TLS Configuration (Simple approach - works in all versions)
	NMATLSSecret string `yaml:"nmaTLSSecret,omitempty"` // Available in all versions (25.1, 25.2, 25.3+)

	// TLS Configuration (Advanced approach - 25.3+ only)
	HTTPSNMATLS     *TLSConfig `yaml:"httpsNMATLS,omitempty"`     // Available in 25.3+
	ClientServerTLS *TLSConfig `yaml:"clientServerTLS,omitempty"` // Available in 25.3+

	// NMA Security Context (25.2+)
	NMASecurityContext *SecurityContext `yaml:"nmaSecurityContext,omitempty"` // Available in 25.2+

	// Global Service Port Configuration (25.3+)
	ServiceClientPort int `yaml:"serviceClientPort,omitempty"` // Default: 5433 (25.3+)
	ServiceHTTPSPort  int `yaml:"serviceHTTPSPort,omitempty"`  // Default: 8443 (25.3+)

	// Proxy configuration (all versions)
	Proxy *Proxy `yaml:"proxy,omitempty"`

	AutoRestartVertica *bool `yaml:"autoRestartVertica,omitempty"`

	// Hadoop configuration (all versions)
	HadoopConfig string `yaml:"hadoopConfig,omitempty"`

	// Requeue configuration
	KSafety int `yaml:"kSafety,omitempty"` // 0, 1, or 2

	// Custom environment variables (25.4+)
	ExtraEnv []EnvVar    `yaml:"extraEnv,omitempty"` // Custom environment variables (25.4+)
	EnvFrom  []EnvSource `yaml:"envFrom,omitempty"`  // Import all env vars from ConfigMaps or Secrets (25.4+)
}

type TLSConfig struct {
	Mode       string         `yaml:"mode,omitempty"`       // disable, enable, try_verify, verify_ca, verify_full
	Secret     string         `yaml:"secret,omitempty"`     // TLS secret name
	AutoRotate *TLSAutoRotate `yaml:"autoRotate,omitempty"` // Automatic rotation config (25.4+)
}

// TLSAutoRotate defines automatic TLS secret rotation configuration (25.4+)
type TLSAutoRotate struct {
	Interval     int      `yaml:"interval,omitempty"`     // Duration in minutes between rotations (minimum 10 mins)
	RestartAtEnd bool     `yaml:"restartAtEnd,omitempty"` // If true, continuously cycle through secrets
	Secrets      []string `yaml:"secrets,omitempty"`      // List of TLS secrets to rotate through
}

type Proxy struct {
	Image string `yaml:"image,omitempty"` // Default: opentext/client-proxy:latest
}

type SubclusterProxy struct {
	Replicas  int        `yaml:"replicas,omitempty"`  // Default: 1
	Resources *Resources `yaml:"resources,omitempty"` // Proxy resource limits/requests
}

type Container struct {
	Name            string           `yaml:"name"`
	Image           string           `yaml:"image,omitempty"`
	Command         []string         `yaml:"command,omitempty"`
	Args            []string         `yaml:"args,omitempty"`
	Env             []EnvVar         `yaml:"env,omitempty"`
	VolumeMounts    []VolumeMount    `yaml:"volumeMounts,omitempty"`
	Resources       *Resources       `yaml:"resources,omitempty"`
	SecurityContext *SecurityContext `yaml:"securityContext,omitempty"`
}

type EnvVar struct {
	Name      string        `yaml:"name"`
	Value     string        `yaml:"value,omitempty"`
	ValueFrom *EnvVarSource `yaml:"valueFrom,omitempty"`
}

type EnvVarSource struct {
	SecretKeyRef    *SecretKeyRef    `yaml:"secretKeyRef,omitempty"`
	ConfigMapKeyRef *ConfigMapKeyRef `yaml:"configMapKeyRef,omitempty"`
}

type SecretKeyRef struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

type ConfigMapKeyRef struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

// EnvSource represents a source to populate environment variables (25.4+)
type EnvSource struct {
	ConfigMapRef *ConfigMapEnvSource `yaml:"configMapRef,omitempty"` // ConfigMap to import
	SecretRef    *SecretEnvSource    `yaml:"secretRef,omitempty"`    // Secret to import
	Prefix       string              `yaml:"prefix,omitempty"`       // Optional prefix for all imported vars
}

type ConfigMapEnvSource struct {
	Name string `yaml:"name"` // Name of the ConfigMap
}

type SecretEnvSource struct {
	Name string `yaml:"name"` // Name of the Secret
}

type Subcluster struct {
	Name                string            `yaml:"name"`
	Size                int               `yaml:"size"`
	Type                string            `yaml:"type,omitempty"`
	ServiceName         string            `yaml:"serviceName,omitempty"`
	ServiceType         string            `yaml:"serviceType,omitempty"`
	ClientNodePort      int               `yaml:"clientNodePort,omitempty"`
	VerticaHTTPNodePort int               `yaml:"verticaHTTPNodePort,omitempty"`
	ExternalIPs         []string          `yaml:"externalIPs,omitempty"`
	LoadBalancerIP      string            `yaml:"loadBalancerIP,omitempty"`
	NodeSelector        map[string]string `yaml:"nodeSelector,omitempty"`
	Affinity            *Affinity         `yaml:"affinity,omitempty"`
	PriorityClassName   string            `yaml:"priorityClassName,omitempty"`
	Tolerations         []Toleration      `yaml:"tolerations,omitempty"`
	Resources           *Resources        `yaml:"resources,omitempty"`
	ServiceAnnotations  map[string]string `yaml:"serviceAnnotations,omitempty"`
	ImageOverride       string            `yaml:"imageOverride,omitempty"`

	// Proxy configuration (all versions)
	Proxy *SubclusterProxy `yaml:"proxy,omitempty"`

	// Shutdown control (all versions)
	Shutdown bool `yaml:"shutdown,omitempty"` // Available in all 25.x versions

	// Individual service ports (25.3+)
	ServiceClientPort int `yaml:"serviceClientPort,omitempty"` // Available in 25.3+
	ServiceHTTPSPort  int `yaml:"serviceHTTPSPort,omitempty"`  // Available in 25.3+
}

type TemporarySubclusterRouting struct {
	Names    []string            `yaml:"names,omitempty"`
	Template *SubclusterTemplate `yaml:"template,omitempty"` // Template for creating temporary subcluster
}

// SubclusterTemplate defines the template for temporary subclusters during upgrades
type SubclusterTemplate struct {
	Name        string `yaml:"name"`
	Size        int    `yaml:"size"`
	ServiceName string `yaml:"serviceName,omitempty"`
	IsPrimary   bool   `yaml:"isPrimary,omitempty"`
}

type Communal struct {
	Path                   string            `yaml:"path"`
	Endpoint               string            `yaml:"endpoint,omitempty"`
	CredentialSecret       string            `yaml:"credentialSecret,omitempty"`
	CaFile                 string            `yaml:"caFile,omitempty"`
	Region                 string            `yaml:"region,omitempty"`
	IncludeUIDInPath       bool              `yaml:"includeUIDInPath,omitempty"`
	AdditionalConfig       map[string]string `yaml:"additionalConfig,omitempty"`
	S3ServerSideEncryption string            `yaml:"s3ServerSideEncryption,omitempty"`
	S3SSECustomerKeySecret string            `yaml:"s3SSECustomerKeySecret,omitempty"`
}

type Local struct {
	DataPath     string `yaml:"dataPath,omitempty"`
	DepotPath    string `yaml:"depotPath,omitempty"`
	CatalogPath  string `yaml:"catalogPath,omitempty"`
	RequestSize  string `yaml:"requestSize,omitempty"`
	StorageClass string `yaml:"storageClass,omitempty"`
	DepotVolume  string `yaml:"depotVolume,omitempty"`
}

type Sandbox struct {
	Name        string                 `yaml:"name"`
	Subclusters []SandboxSubclusterRef `yaml:"subclusters,omitempty"`
	Image       string                 `yaml:"image,omitempty"`
	Shutdown    bool                   `yaml:"shutdown,omitempty"` // Available in all 25.x versions
}

// SandboxSubclusterRef references an existing subcluster by name for sandboxing (25.4+: supports type field)
type SandboxSubclusterRef struct {
	Name string `yaml:"name"`           // Name of the subcluster to add to sandbox
	Type string `yaml:"type,omitempty"` // Subcluster type: "primary" or "secondary" (25.4+)
}

type RestorePoint struct {
	Archive          string `yaml:"archive,omitempty"`
	Index            int    `yaml:"index,omitempty"`
	ID               string `yaml:"id,omitempty"`
	NumRestorePoints int    `yaml:"numRestorePoints,omitempty"` // Available in 25.3+ (0 = unlimited)
}

type ReviveStep struct {
	SubclusterIndex int `yaml:"subclusterIndex"` // Index in subclusters array
	PodCount        int `yaml:"podCount"`        // Number of pods from this subcluster
}

type Certifications struct {
	HTTPSTLSSecret string `yaml:"httpsTLSSecret,omitempty"`
	SSLSecret      string `yaml:"sslSecret,omitempty"`
	SSLCertFile    string `yaml:"sslCertFile,omitempty"`
	SSLCAFile      string `yaml:"sslCAFile,omitempty"`
}

type Volume struct {
	Name                  string                 `yaml:"name"`
	EmptyDir              *EmptyDirVolumeSource  `yaml:"emptyDir,omitempty"`
	HostPath              *HostPathVolumeSource  `yaml:"hostPath,omitempty"`
	Secret                *SecretVolumeSource    `yaml:"secret,omitempty"`
	ConfigMap             *ConfigMapVolumeSource `yaml:"configMap,omitempty"`
	PersistentVolumeClaim *PVCVolumeSource       `yaml:"persistentVolumeClaim,omitempty"`
}

type EmptyDirVolumeSource struct {
	Medium    string `yaml:"medium,omitempty"`
	SizeLimit string `yaml:"sizeLimit,omitempty"`
}

type HostPathVolumeSource struct {
	Path string `yaml:"path"`
	Type string `yaml:"type,omitempty"`
}

type SecretVolumeSource struct {
	SecretName string `yaml:"secretName"`
}

type ConfigMapVolumeSource struct {
	Name string `yaml:"name"`
}

type PVCVolumeSource struct {
	ClaimName string `yaml:"claimName"`
}

type VolumeMount struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
	SubPath   string `yaml:"subPath,omitempty"`
	ReadOnly  bool   `yaml:"readOnly,omitempty"`
}

type Resources struct {
	Requests *ResourceList `yaml:"requests,omitempty"`
	Limits   *ResourceList `yaml:"limits,omitempty"`
}

type ResourceList struct {
	CPU    string `yaml:"cpu,omitempty"`
	Memory string `yaml:"memory,omitempty"`
}

type Probe struct {
	HTTPGet             *HTTPGetAction   `yaml:"httpGet,omitempty"`
	Exec                *ExecAction      `yaml:"exec,omitempty"`
	TCPSocket           *TCPSocketAction `yaml:"tcpSocket,omitempty"`
	InitialDelaySeconds int              `yaml:"initialDelaySeconds,omitempty"`
	PeriodSeconds       int              `yaml:"periodSeconds,omitempty"`
	TimeoutSeconds      int              `yaml:"timeoutSeconds,omitempty"`
	SuccessThreshold    int              `yaml:"successThreshold,omitempty"`
	FailureThreshold    int              `yaml:"failureThreshold,omitempty"`
}

type HTTPGetAction struct {
	Path   string `yaml:"path"`
	Port   int    `yaml:"port"`
	Scheme string `yaml:"scheme,omitempty"`
}

type ExecAction struct {
	Command []string `yaml:"command"`
}

type TCPSocketAction struct {
	Port int `yaml:"port"`
}

type Affinity struct {
	NodeAffinity    *NodeAffinity    `yaml:"nodeAffinity,omitempty"`
	PodAffinity     *PodAffinity     `yaml:"podAffinity,omitempty"`
	PodAntiAffinity *PodAntiAffinity `yaml:"podAntiAffinity,omitempty"`
}

type NodeAffinity struct {
	RequiredDuringSchedulingIgnoredDuringExecution  *NodeSelector             `yaml:"requiredDuringSchedulingIgnoredDuringExecution,omitempty"`
	PreferredDuringSchedulingIgnoredDuringExecution []PreferredSchedulingTerm `yaml:"preferredDuringSchedulingIgnoredDuringExecution,omitempty"`
}

type NodeSelector struct {
	NodeSelectorTerms []NodeSelectorTerm `yaml:"nodeSelectorTerms"`
}

type NodeSelectorTerm struct {
	MatchExpressions []NodeSelectorRequirement `yaml:"matchExpressions,omitempty"`
	MatchFields      []NodeSelectorRequirement `yaml:"matchFields,omitempty"`
}

type NodeSelectorRequirement struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values,omitempty"`
}

type PreferredSchedulingTerm struct {
	Weight     int              `yaml:"weight"`
	Preference NodeSelectorTerm `yaml:"preference"`
}

type PodAffinity struct {
	RequiredDuringSchedulingIgnoredDuringExecution  []PodAffinityTerm         `yaml:"requiredDuringSchedulingIgnoredDuringExecution,omitempty"`
	PreferredDuringSchedulingIgnoredDuringExecution []WeightedPodAffinityTerm `yaml:"preferredDuringSchedulingIgnoredDuringExecution,omitempty"`
}

type PodAntiAffinity struct {
	RequiredDuringSchedulingIgnoredDuringExecution  []PodAffinityTerm         `yaml:"requiredDuringSchedulingIgnoredDuringExecution,omitempty"`
	PreferredDuringSchedulingIgnoredDuringExecution []WeightedPodAffinityTerm `yaml:"preferredDuringSchedulingIgnoredDuringExecution,omitempty"`
}

type PodAffinityTerm struct {
	LabelSelector *LabelSelector `yaml:"labelSelector,omitempty"`
	Namespaces    []string       `yaml:"namespaces,omitempty"`
	TopologyKey   string         `yaml:"topologyKey"`
}

type WeightedPodAffinityTerm struct {
	Weight          int             `yaml:"weight"`
	PodAffinityTerm PodAffinityTerm `yaml:"podAffinityTerm"`
}

type LabelSelector struct {
	MatchLabels      map[string]string         `yaml:"matchLabels,omitempty"`
	MatchExpressions []NodeSelectorRequirement `yaml:"matchExpressions,omitempty"`
}

type Toleration struct {
	Key               string `yaml:"key,omitempty"`
	Operator          string `yaml:"operator,omitempty"`
	Value             string `yaml:"value,omitempty"`
	Effect            string `yaml:"effect,omitempty"`
	TolerationSeconds *int64 `yaml:"tolerationSeconds,omitempty"`
}

type PodSecurityContext struct {
	RunAsUser           *int64 `yaml:"runAsUser,omitempty"`
	RunAsGroup          *int64 `yaml:"runAsGroup,omitempty"`
	FSGroup             *int64 `yaml:"fsGroup,omitempty"`
	RunAsNonRoot        *bool  `yaml:"runAsNonRoot,omitempty"`
	FSGroupChangePolicy string `yaml:"fsGroupChangePolicy,omitempty"`
}

type SecurityContext struct {
	RunAsUser                *int64        `yaml:"runAsUser,omitempty"`
	RunAsGroup               *int64        `yaml:"runAsGroup,omitempty"`
	RunAsNonRoot             *bool         `yaml:"runAsNonRoot,omitempty"`
	ReadOnlyRootFilesystem   *bool         `yaml:"readOnlyRootFilesystem,omitempty"`
	AllowPrivilegeEscalation *bool         `yaml:"allowPrivilegeEscalation,omitempty"`
	Capabilities             *Capabilities `yaml:"capabilities,omitempty"`
}

type Capabilities struct {
	Add  []string `yaml:"add,omitempty"`
	Drop []string `yaml:"drop,omitempty"`
}

type ImagePullSecret struct {
	Name string `yaml:"name"`
}
