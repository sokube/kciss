package main

import (
	"flag"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	namespacesVulnsReported = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "namespace_vulnerabilities_total",
		Help: "Number of vulnerabilities found in the namespace workloads",
	}, []string{"namespace", "severity"})
	imagesVulnsReported = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "image_vulnerabilities_total",
		Help: "Number of vulnerabilities found in the image",
	}, []string{"image", "severity"})
)

func main() {
	// UNIX Time is faster and smaller than most timestamps
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: zerolog.TimeFormatUnix})
	log.Info().Msg("kciss starting")

	// Retrieve command flags
	interval := flag.Int("interval", 300, "Interval for metrics reporting in seconds")
	trivyServer := flag.String("server", "", "Address of the trivy server")
	trivyBinary := flag.String("trivy", "/usr/local/bin/trivy", "Path to the trivy binary")
	endPoint := flag.String("endpoint", "/kciss-metrics", "endpoint for metrics")
	flag.Parse()

	log.Info().Msg("Starting metrics server on :9300")
	http.Handle(*endPoint, promhttp.Handler())
	go Run(int(*interval), *trivyServer, *trivyBinary)
	http.ListenAndServe(":9300", nil)
}

func Run(interval int, trivyserver string, trivypath string) {
	// creates the in-cluster config
	log.Info().Msg("Create incluster config")
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	// creates the clientset
	log.Info().Msg("Create clientset")
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// Endless loop
	for {
		log.Info().Msg("Starting cluster analysis")

		log.Info().Msg("Starting secrets collection")
		registries := LocalDockerConfigSecrets(clientset)

		// Creates the cluster images & namespaces catalog
		namespaces, images, imagesInNamespaces, err := ClusterImageCatalog(clientset)
		if err != nil {
			log.Fatal().Err(err)
			break
		}

		// Scan container images found in the cluster, accumulate in namespace metrics
		for v := range images {

			images[v], err = TrivyScanImage(trivyserver, trivypath, v, registries)
			if err != nil {
				log.Error().Str("Image", v).Err(err).Msg("Image scan problem")
			}

			// Report the image vulns in the namespace where this image is used
			log.Info().Str("Image", v).Interface("Summary", images[v]).Msg("Image scan complete")
			for ns, occurence := range imagesInNamespaces[v] {
				namespaces[ns] = namespaces[ns].Add(images[v].Mult(occurence))
			}

			// Prevent bursts
			time.Sleep(20 * time.Second)
		}

		log.Info().Msg("---> Images Vulnerabilities Summary")
		imagesVulnsReported.Reset()
		for i, sum := range images {
			log.Info().Str("Image", i).Interface("Vulnerabilities", sum).Msg("     Summary for:")
			imagesVulnsReported.WithLabelValues(i, "critical").Set((float64(sum.Critical)))
			imagesVulnsReported.WithLabelValues(i, "high").Set((float64(sum.High)))
			imagesVulnsReported.WithLabelValues(i, "medium").Set((float64(sum.Medium)))
			imagesVulnsReported.WithLabelValues(i, "low").Set((float64(sum.Low)))
		}
		log.Info().Msg("---> Namespaces Vulnerabilities Summary")
		namespacesVulnsReported.Reset()
		for ns, sum := range namespaces {
			log.Info().Str("Namespace", ns).Interface("Vulnerabilities", sum).Msg("     Summary for:")
			namespacesVulnsReported.WithLabelValues(ns, "critical").Set((float64(sum.Critical)))
			namespacesVulnsReported.WithLabelValues(ns, "high").Set((float64(sum.High)))
			namespacesVulnsReported.WithLabelValues(ns, "medium").Set((float64(sum.Medium)))
			namespacesVulnsReported.WithLabelValues(ns, "low").Set((float64(sum.Low)))
		}

		time.Sleep(time.Duration(interval) * time.Second)
	}
}
