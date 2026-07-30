/*
Copyright The HAMi Authors.
SPDX-License-Identifier: Apache-2.0
*/

// Package main implements the mutating admission webhook for KAI resource isolator.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultListen       = ":8443"
	volumeName          = "kai-resource-isolator-vgpu"
	initContainerName   = "kai-resource-isolator-vgpu-install"
	injectAnnotationKey = "kai-resource-isolator.io/inject"
	gpuFractionKey      = "gpu-fraction"
	gpuMemoryKey        = "gpu-memory"
	artifactPath        = "/artifacts/libvgpu.so"
	installerCPU        = "10m"
	installerMemory     = "32Mi"
)

func main() {
	certFile := flag.String("tls-cert-file", "/etc/tls/tls.crt", "TLS certificate")
	keyFile := flag.String("tls-private-key-file", "/etc/tls/tls.key", "TLS private key")
	listen := flag.String("listen", defaultListen, "Listen address")
	containerMount := flag.String("container-vgpu-mount", getenv("CONTAINER_VGPU_MOUNT", "/usr/local/vgpu"), "Mount path inside the pod where libvgpu.so is staged and which ld.so.preload points at")
	isolatorImage := flag.String("isolator-image", getenv("ISOLATOR_IMAGE", ""), "Image used for the injected vgpu-install initContainer; must contain "+artifactPath)
	flag.Parse()

	if *isolatorImage == "" {
		fmt.Fprintln(os.Stderr, "isolator image is required: set --isolator-image or ISOLATOR_IMAGE")
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/mutate", func(w http.ResponseWriter, r *http.Request) {
		handleMutate(w, r, *containerMount, *isolatorImage)
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("webhook starting listen=%s containerVgpuMount=%s isolatorImage=%s annotationKeys=%s|%s", *listen, *containerMount, *isolatorImage, gpuFractionKey, gpuMemoryKey)

	if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func handleMutate(w http.ResponseWriter, r *http.Request, containerMount, isolatorImage string) {
	if r.Method != http.MethodPost {
		log.Printf("mutate reject: method=%s", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("mutate read body failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		log.Printf("mutate decode admission review failed: %v", err)
		http.Error(w, fmt.Sprintf("decode: %v", err), http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		log.Printf("mutate reject: missing request")
		http.Error(w, "missing request", http.StatusBadRequest)
		return
	}

	resp := admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: true,
	}

	pod := corev1.Pod{}
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		log.Printf("mutate uid=%s unmarshal pod failed: %v", review.Request.UID, err)
		resp.Result = &metav1.Status{
			Message: fmt.Sprintf("unmarshal pod: %v", err),
			Code:    http.StatusBadRequest,
		}
		resp.Allowed = false
		writeAdmission(w, &review, resp)
		return
	}

	if pod.Annotations != nil && strings.EqualFold(pod.Annotations[injectAnnotationKey], "false") {
		log.Printf("mutate uid=%s ns=%s pod=%s skipped: annotation %s=false", review.Request.UID, pod.Namespace, pod.Name, injectAnnotationKey)
		writeAdmission(w, &review, resp)
		return
	}

	patch, err := buildJSONPatch(&pod, containerMount, isolatorImage)
	if err != nil {
		log.Printf("mutate uid=%s ns=%s pod=%s build patch failed: %v", review.Request.UID, pod.Namespace, pod.Name, err)
		resp.Result = &metav1.Status{Message: err.Error(), Code: http.StatusInternalServerError}
		resp.Allowed = false
		writeAdmission(w, &review, resp)
		return
	}
	if len(patch) == 0 {
		log.Printf("mutate uid=%s ns=%s pod=%s skipped: missing annotations %q or %q", review.Request.UID, pod.Namespace, pod.Name, gpuFractionKey, gpuMemoryKey)
		writeAdmission(w, &review, resp)
		return
	}
	log.Printf("mutate uid=%s ns=%s pod=%s injected: patchBytes=%d", review.Request.UID, pod.Namespace, pod.Name, len(patch))
	pt := admissionv1.PatchTypeJSONPatch
	resp.Patch = patch
	resp.PatchType = &pt

	writeAdmission(w, &review, resp)
}

func writeAdmission(w http.ResponseWriter, review *admissionv1.AdmissionReview, resp admissionv1.AdmissionResponse) {
	review.Response = &resp
	if review.APIVersion == "" {
		review.APIVersion = admissionv1.SchemeGroupVersion.String()
	}
	if review.Kind == "" {
		review.Kind = "AdmissionReview"
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if err := enc.Encode(review); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func buildJSONPatch(pod *corev1.Pod, containerMount, isolatorImage string) ([]byte, error) {
	if !podNeedsInjection(pod) {
		return nil, nil
	}

	var ops []map[string]interface{}

	hasVol := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == volumeName {
			hasVol = true
			break
		}
	}
	if !hasVol {
		vol := map[string]interface{}{
			"name":     volumeName,
			"emptyDir": map[string]interface{}{},
		}
		ops = append(ops, appendToList("/spec/volumes", len(pod.Spec.Volumes), vol))
	}

	mountDir := map[string]interface{}{
		"name":      volumeName,
		"mountPath": containerMount,
		"readOnly":  true,
	}
	mountPreload := map[string]interface{}{
		"name":      volumeName,
		"mountPath": "/etc/ld.so.preload",
		"subPath":   "ld.so.preload",
		"readOnly":  true,
	}

	hasInstaller := false
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == initContainerName {
			hasInstaller = true
			break
		}
	}
	initOffset := 0
	if !hasInstaller {
		// Must run before every other initContainer: kubelet materialises a missing subPath
		// as a directory, so ld.so.preload has to exist before anything mounts it.
		//
		// kubelet's QoS calculation includes initContainers, so the installer has to mirror
		// the pod's own class: requests equal to limits to keep a Guaranteed pod Guaranteed,
		// and no resources at all so a BestEffort pod is not promoted to Burstable.
		ops = append(ops, prependToList("/spec/initContainers", len(pod.Spec.InitContainers),
			installerContainer(containerMount, isolatorImage, podDeclaresResources(pod))))
		initOffset = 1
	}

	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		if c.Name == initContainerName {
			continue
		}
		if !hasMount(c, volumeName, containerMount, "") {
			ops = append(ops, map[string]interface{}{
				"op":    "add",
				"path":  fmt.Sprintf("/spec/initContainers/%d/volumeMounts/-", i+initOffset),
				"value": mountDir,
			})
		}
		if !hasMount(c, volumeName, "/etc/ld.so.preload", "ld.so.preload") {
			ops = append(ops, map[string]interface{}{
				"op":    "add",
				"path":  fmt.Sprintf("/spec/initContainers/%d/volumeMounts/-", i+initOffset),
				"value": mountPreload,
			})
		}
	}
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if !hasMount(c, volumeName, containerMount, "") {
			ops = append(ops, map[string]interface{}{
				"op":    "add",
				"path":  fmt.Sprintf("/spec/containers/%d/volumeMounts/-", i),
				"value": mountDir,
			})
		}
		if !hasMount(c, volumeName, "/etc/ld.so.preload", "ld.so.preload") {
			ops = append(ops, map[string]interface{}{
				"op":    "add",
				"path":  fmt.Sprintf("/spec/containers/%d/volumeMounts/-", i),
				"value": mountPreload,
			})
		}
	}

	if len(ops) == 0 {
		return nil, nil
	}
	return json.Marshal(ops)
}

func appendToList(path string, listLen int, value map[string]interface{}) map[string]interface{} {
	if listLen == 0 {
		return createList(path, value)
	}
	return map[string]interface{}{"op": "add", "path": path + "/-", "value": value}
}

func prependToList(path string, listLen int, value map[string]interface{}) map[string]interface{} {
	if listLen == 0 {
		return createList(path, value)
	}
	return map[string]interface{}{"op": "add", "path": path + "/0", "value": value}
}

func createList(path string, value map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"op":    "add",
		"path":  path,
		"value": []interface{}{value},
	}
}

func installerContainer(containerMount, isolatorImage string, setResources bool) map[string]interface{} {
	script := strings.Join([]string{
		"set -e",
		fmt.Sprintf("cp -f %s '%s/libvgpu.so'", artifactPath, containerMount),
		fmt.Sprintf("printf '%%s\\n' '%s/libvgpu.so' > '%s/ld.so.preload'", containerMount, containerMount),
		fmt.Sprintf("chmod 0644 '%s/libvgpu.so' '%s/ld.so.preload'", containerMount, containerMount),
	}, "\n")

	c := map[string]interface{}{
		"name":    initContainerName,
		"image":   isolatorImage,
		"command": []interface{}{"/bin/sh", "-c", script},
		"volumeMounts": []interface{}{
			map[string]interface{}{
				"name":      volumeName,
				"mountPath": containerMount,
			},
		},
	}
	if setResources {
		c["resources"] = map[string]interface{}{
			"requests": map[string]interface{}{"cpu": installerCPU, "memory": installerMemory},
			"limits":   map[string]interface{}{"cpu": installerCPU, "memory": installerMemory},
		}
	}
	return c
}

// podDeclaresResources reports whether any container sets a request or a limit, i.e. whether
// the pod is anything other than BestEffort.
func podDeclaresResources(pod *corev1.Pod) bool {
	for _, list := range [][]corev1.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for i := range list {
			r := list[i].Resources
			if len(r.Requests) > 0 || len(r.Limits) > 0 {
				return true
			}
		}
	}
	return false
}

func podNeedsInjection(pod *corev1.Pod) bool {
	if pod.Annotations == nil {
		return false
	}
	_, hasFraction := pod.Annotations[gpuFractionKey]
	_, hasMemory := pod.Annotations[gpuMemoryKey]
	return hasFraction || hasMemory
}

func hasMount(c *corev1.Container, volName, mountPath, subPath string) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == volName && m.MountPath == mountPath && m.SubPath == subPath {
			return true
		}
	}
	return false
}
