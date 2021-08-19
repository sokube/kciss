package main

import (
	"context"
	"encoding/json"
	"io/ioutil"

	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func GetCurrentNamespace() (ns string) {
	ns = ""

	// Get current namespace
	data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err == nil {
		ns = string(data)
	}

	return ns
}

type DockerAuthEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DockerAuths struct {
	Auths map[string]DockerAuthEntry `json:"auths"`
}

func ParseDockerAuths(data []byte) *DockerAuths {
	var da DockerAuths
	da.Auths = make(map[string]DockerAuthEntry)
	json.Unmarshal(data, &da)
	return &da
}

// Does a full catalog of the docker auth type secrets on the cluster
// Creates a map registry address -> auth entry
func LocalDockerConfigSecrets(clientset *kubernetes.Clientset) (registries DockerAuths) {

	registries.Auths = make(map[string]DockerAuthEntry)
	log.Logger.Info().Msg("Collecting cluster secrets for registries authentication")

	// Retrieve cluster secrets from API server
	secrets, err := clientset.CoreV1().Secrets("").List(context.TODO(), metav1.ListOptions{FieldSelector: "type=kubernetes.io/dockerconfigjson"})
	if err != nil {
		log.Logger.Error().Err(err).Msg("Error listing secrets")
		return registries
	}

	// Decode each one and put it in a dictionary
	for _, secret := range secrets.Items {
		test := ParseDockerAuths(secret.Data[".dockerconfigjson"])
		for reg, auth := range test.Auths {
			log.Logger.Debug().Str("Registry", reg).Msg("Collected registry auth information")
			registries.Auths[reg] = DockerAuthEntry{Username: auth.Username, Password: auth.Password}
		}
	}

	return registries
}

// Does a full catalogs of the images and namespaces on the current cluster
// Also builds a image->namespaces map to find easily in which namespace an image is used (and how many times)
func ClusterImageCatalog(clientset *kubernetes.Clientset) (ns map[string]VulnSummary, imgs map[string]VulnSummary, imgs_ns map[string]map[string]uint32, err error) {
	err = nil
	ns = make(map[string]VulnSummary)
	imgs = make(map[string]VulnSummary)
	imgs_ns = make(map[string]map[string]uint32)

	// Retrieve pods from kubeapi
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return
	}

	// Populate the sets: namespaces, images, and image->namespace map
	for _, pod := range pods.Items {
		ns[pod.ObjectMeta.Namespace] = VulnSummary{}
		for _, container := range pod.Spec.Containers {
			imgs[container.Image] = VulnSummary{}
			_, ok := imgs_ns[container.Image]
			if !ok {
				imgs_ns[container.Image] = make(map[string]uint32)
			}
			imgs_ns[container.Image][pod.ObjectMeta.Namespace] += 1
			log.Logger.Debug().Uint32("counter", imgs_ns[container.Image][pod.ObjectMeta.Namespace]).Str("image", container.Image).Str("namespace", pod.ObjectMeta.Namespace).Msg("Namespace/Image collected")
		}
	}
	return
}
