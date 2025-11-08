package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

var validVerbs = map[string]struct{}{
	"*":                {},
	"get":              {},
	"list":             {},
	"watch":            {},
	"create":           {},
	"update":           {},
	"patch":            {},
	"delete":           {},
	"deletecollection": {},
	"proxy":            {},
	"connect":          {},
}

type clusterData struct {
	version     string
	resourceMap []*v1.APIResourceList
}

type groupResourceList struct {
	groupWithoutVersion string
	resources           []v1.APIResource
}

func main() {
	var (
		kubeConfig string
	)

	rootCmd := &cobra.Command{
		Use:   fmt.Sprintf("%s [flags] policy.yaml", filepath.Base(os.Args[0])),
		Short: "Validate a Kubernetes audit policy file",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := runPolicyCheck(args[0], kubeConfig); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	rootCmd.Flags().StringVarP(&kubeConfig, "kubeconfig", "k", "", "Path to alternate kubeconfig file")
	rootCmd.Execute()
}

func runPolicyCheck(policyPath, kubeConfig string) error {

	errorCount := 0
	warnCount := 0

	// Get kubeconfig for cluster
	config, err := getKubeconfig(kubeConfig)

	if err != nil {
		return err
	}

	// Create discovery client - used to discover resources in the cluster.
	dc, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return fmt.Errorf("FATAL: failed to create discovery client: %w", err)
	}

	// Read info about the cluster and all the resources it knows
	clusterData, err := getClusterData(dc)
	if err != nil {
		return err
	}

	fmt.Printf("Testing %s against known resources for API Server at %s running Kubernetes %s\n\n", policyPath, config.Host, clusterData.version)

	// Read policy file
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("FATAL: failed to read file: %w", err)
	}

	// Set up scheme & decoder for audit.k8s.io/v1
	scheme := runtime.NewScheme()
	utilruntime.Must(auditv1.AddToScheme(scheme))
	codecs := serializer.NewCodecFactory(scheme)
	decoder := codecs.UniversalDeserializer()

	// Decode policy document to a generic runtime.Object
	// Will fail here if YAML has syntax errors or does not represent a policy
	policyObject, gvk, err := decoder.Decode(data, nil, nil)
	if err != nil {
		return fmt.Errorf("FATAL: failed to decode YAML: %w", err)
	}

	// Cast to concrete policy object
	policy, ok := policyObject.(*auditv1.Policy)
	if !ok {
		return fmt.Errorf("FATAL: unexpected type: got %T for %s", policyObject, gvk.String())
	}

	// Begin validations

	// Must have at least one rule
	if len(policy.Rules) == 0 {
		return errors.New("FATAL: invalid policy: must have at least one rule")
	}

	// If top level omitStages, validate them
	if err := validateOmitStages(policy.OmitStages); err != nil {
		fmt.Printf("ERROR: top level: %v", err)
		errorCount++
	}

	// Read namespaces
	ns, err := getNamespaces(config)

	if err != nil {
		fmt.Printf("WARN:  Unable to list namespaces. Namespaces will not be checked: %v\n", err)
		warnCount++
	}

	// Validate each rule
	for i, rule := range policy.Rules {

		// Must have level
		if rule.Level == "" {
			fmt.Printf("ERROR: rule[%d]: missing required field 'level'\n", i)
			errorCount++
			continue
		}

		// Validate level
		switch rule.Level {
		case "None", "Metadata", "Request", "RequestResponse":
			// ok
		default:
			fmt.Printf("ERROR: rule[%d]: invalid level %q\n", i, rule.Level)
			errorCount++
			continue
		}

		// If rule level omitStages, validate them
		if err := validateOmitStages(rule.OmitStages); err != nil {
			fmt.Printf("ERROR: rule[%d]: %v\n", i, err)
			errorCount++
			continue
		}

		// If verbs, validate them
		for _, verb := range rule.Verbs {
			if _, ok := validVerbs[verb]; !ok {
				fmt.Printf("ERROR: rule[%d]: invalid verb %q\n", i, verb)
				errorCount++
				continue
			}
		}

		// Validate namespaces.
		// Only warn if NS not found - it may be created later.
		for _, n := range rule.Namespaces {
			if !slices.Contains(ns, n) {
				fmt.Printf("WARN:  rule[%d]: namespace %q does not exist\n", i, n)
				warnCount++
			}
		}

		// group/resource check
		for _, gr := range rule.Resources {

			// Get the known resource list for the group.
			resourceList := findResourcesForGroups(gr.Group, clusterData.resourceMap)

			// If nothing returned then the group is invalid
			if resourceList == nil {

				fmt.Printf("ERROR: rule[%d]: unrecognised group %q\n", i, gr.Group)
				errorCount++
				continue
			}

			// Validate each resource
			for _, resource := range gr.Resources {

				// Name of resource without any subresource
				// e.g. pods/log -> pods
				baseResource := func() string {

					if strings.Contains(resource, "/") {
						return strings.SplitN(resource, "/", 2)[0]
					}
					return resource
				}()

				// Render group name for printing in messages
				groupText := func() string {
					if gr.Group == "" {
						return `""`
					}
					return `"` + gr.Group + `"`
				}()

				// Look up the resource in the group
				apiResource := findResource(baseResource, resourceList)

				if apiResource == nil {
					fmt.Printf("ERROR: rule[%d]: unrecognised resource %q for group %s\n", i, baseResource, groupText)
					errorCount++
					continue
				}

				// Is it a subresource, e.g. pods/log
				if strings.Contains(resource, "/") {

					// Get all subresources for the resource, e.g. pods, pods/log, pods/status etc
					subResources, err := listSubresources(
						dc,
						schema.GroupKind{
							Group: gr.Group,
							Kind:  apiResource.Kind,
						},
					)

					if err != nil {
						fmt.Printf("WARN:  rule[%d]: cannot get subresources for resource %q in group %s\n", i, apiResource.Kind, groupText)
						warnCount++
						continue
					}

					// Look up the full resource name e.g. pods/logs
					if !slices.Contains(subResources, resource) {
						fmt.Printf("ERROR: rule[%d]: unrecognised resource %q for group %s\n", i, resource, groupText)
						errorCount++
					}
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("Errors:  ", errorCount)
	fmt.Println("Warnings:", warnCount)

	if errorCount == 0 {
		fmt.Println("\nPolicy file is syntactically valid ✔")
		return nil
	}

	fmt.Println()
	return fmt.Errorf("%s file contains errors", policyPath)
}

func getKubeconfig(kubeconfigPath string) (*rest.Config, error) {

	// If a kubeconfig path is provided, try loading it first
	if kubeconfigPath != "" {
		loadingRules := &clientcmd.ClientConfigLoadingRules{
			ExplicitPath: kubeconfigPath,
		}
		kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules,
			&clientcmd.ConfigOverrides{},
		)

		config, err := kubeconfig.ClientConfig()
		if err == nil {
			return config, nil
		}
		// If loading the specified kubeconfig fails, return the error
		return nil, fmt.Errorf("failed to load kubeconfig from %s: %w", kubeconfigPath, err)
	}

	// Otherwise, try in-cluster config (service account)
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	// Fallback to default kubeconfig path if in-cluster fails
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	)

	config, err = kubeconfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load default kubeconfig: %w", err)
	}

	return config, nil
}

func getNamespaces(config *rest.Config) ([]string, error) {

	// Create API client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create clientset: %w", err)
	}

	// List namespaces (kubectl get namespaces)
	ns, err := clientset.CoreV1().Namespaces().List(context.Background(), v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list namespaces: %w", err)
	}

	// We only need the names of the namespaces
	res := []string{}

	for _, n := range ns.Items {
		res = append(res, n.Name)
	}

	return res, nil
}

// getClusterData reads cluster information and all known resource types
// from the cluster in the manner of kubectl api-resources
func getClusterData(dc *discovery.DiscoveryClient) (*clusterData, error) {

	// Same version info as "kubectl version"
	version, err := dc.ServerVersion()

	if err != nil {
		return nil, fmt.Errorf("failed to determine server version: %w", err)
	}

	// Read all resources
	if resources, err := dc.ServerPreferredResources(); err != nil {
		return nil, fmt.Errorf("failed to read server resource list: %w", err)
	} else {
		return &clusterData{
			version:     version.String(),
			resourceMap: resources,
		}, nil
	}
}

// listSubresources returns a list of subressource names (e.g. "status", "log")
// for the given GroupKind in the current cluster.
func listSubresources(dc *discovery.DiscoveryClient, gk schema.GroupKind) ([]string, error) {

	// Build RESTMapper from live API
	apiGroupResources, err := restmapper.GetAPIGroupResources(dc)
	if err != nil {
		return nil, fmt.Errorf("fetching API group resources: %w", err)
	}
	mapper := restmapper.NewDiscoveryRESTMapper(apiGroupResources)

	// Resolve the canonical GroupVersion for this GroupKind
	mapping, err := mapper.RESTMapping(gk, "")
	if err != nil {
		return nil, fmt.Errorf("mapping kind %s: %w", gk.String(), err)
	}

	// List all resources for that GroupVersion
	resList, err := dc.ServerResourcesForGroupVersion(mapping.GroupVersionKind.GroupVersion().String())
	if err != nil {
		return nil, fmt.Errorf("listing resources for %s: %w", mapping.GroupVersionKind.GroupVersion(), err)
	}

	// Collect all subresources for this Kind
	var subs []string
	for _, r := range resList.APIResources {
		if r.Kind != gk.Kind {
			continue
		}
		subs = append(subs, r.Name)
	}

	return subs, nil
}

// findResourcesForGroups gets all the resources for a given group
// at all known versions of that group
func findResourcesForGroups(policyGroup string, resources []*v1.APIResourceList) *groupResourceList {

	var matches []*v1.APIResourceList

	group := func() string {
		if policyGroup == "" {
			return "v1"
		}
		return policyGroup
	}()

	for _, list := range resources {
		if list.GroupVersion == group {
			// Will be true for "v1"
			return &groupResourceList{
				groupWithoutVersion: group,
				resources:           list.APIResources,
			}
		}

		// Gather all group versions for unversioned group
		// e.g. "autocaling" = autoscaling/v1 + autoscaling/v2
		if strings.HasPrefix(list.GroupVersion, group+"/") {
			matches = append(matches, list)
		}
	}

	// Combine the resources from all versioned groups,
	// since policy does not state specific versions for groups
	result := &groupResourceList{
		groupWithoutVersion: group,
		resources:           []v1.APIResource{},
	}

	for _, m := range matches {
		result.resources = append(result.resources, m.APIResources...)
	}

	return result
}

// findResource looks up the given resource in the list of
// known resources for a group
func findResource(resource string, list *groupResourceList) *v1.APIResource {

	for i, res := range list.resources {
		if res.Name == resource {
			return &list.resources[i]
		}
	}

	return nil
}

func validateOmitStages(omitStages []auditv1.Stage) error {

	for _, stage := range omitStages {
		switch stage {
		case "RequestReceived", "ResponseStarted", "ResponseComplete", "Panic":
			// ok
		default:
			return fmt.Errorf("invalid omitStage %q", stage)
		}
	}

	return nil
}
