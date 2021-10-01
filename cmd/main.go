package main

import (
	"flag"
	"fmt"
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

// Structure for configuration command line parameters
type KcissConfig struct {
	TrivyBinaryPath     string
	TrivyServer         string
	ClusterScanInterval uint64
	ImageScanExpiration uint64
}

// Various Vulnerabilities Levels
const CRITICAL = 0
const HIGH = 1
const MEDIUM = 2
const LOW = 3
const UNKNOWN = 4

// Structure for the cluster image catalog
type ClusterImageCatalogEntry struct {
	Image           string      // image
	Namespaces      []string    // namespaces that run this image
	LastScanned     time.Time   // last time it was scanned
	ScanSucceeded   bool        // Whether the scan succeeded
	Vulnerabilities [5][]string // Vulnerabilities report [LEVEL][CVE,CVE2,etc]
	FlagForRemoval  bool        // This entry should be removed (ie last cluster scan did not find this image at all)
}

// Prometheus metrics
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
	var config KcissConfig
	flag.Uint64Var(&config.ClusterScanInterval, "interval", 300, "Interval for metrics reporting in seconds")
	flag.Uint64Var(&config.ImageScanExpiration, "expire", 60, "Image scan results validity in seconds")
	flag.StringVar(&config.TrivyServer, "server", "", "Address of the trivy server")
	flag.StringVar(&config.TrivyBinaryPath, "StringVarrivy", "/usr/local/bin/trivy", "Path to the trivy binary")
	flag.Parse()
	log.Debug().Interface("config", config).Msg("Config parsed")

	log.Info().Msg("Starting metrics server on :9300")
	http.Handle("/metrics", promhttp.Handler())
	go Run(config.ClusterScanInterval, config.ImageScanExpiration, config.TrivyServer, config.TrivyBinaryPath)
	go ImageScanningWorker(config.ClusterScanInterval, config.ImageScanExpiration, config.TrivyServer, config.TrivyBinaryPath)
	http.ListenAndServe(":9300", nil)
}

/*
	x, y := 0, 1
	for {
		select {
		case c <- x:
			x, y = y, x+y
		case <-quit:
			fmt.Println("quit")
			return
		}
	}*/

func ImageScanningWorker(images chan string, quit chan int, config KcissConfig) {
	// Endless loop
	var image string
	for {
		select {
		case images <- image:
			log.Info().Str("image", image).Msg("Processing Image")
			time.Sleep(time.Duration(config.ImageScanExpiration) * time.Second)
			log.Info().Str("image", image).Msg("Processed")

		case <-quit:
			fmt.Println("quit")
			return
		}
	}
}

func Run(interval uint64, expire uint64, trivyserver string, trivypath string) {
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

		log.Info().Msg("Collecting secrets")
		registries := LocalDockerConfigSecrets(clientset)

		// Creates the cluster images & namespaces catalog
		log.Info().Msg("Collecting images")
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
			time.Sleep(time.Duration(expire) * time.Second)
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
