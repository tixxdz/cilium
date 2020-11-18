// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8sTest

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = Describe("K8sConnectionTracking", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
			"bpf.monitorAggregation": "none",
		})
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium bpf ct list global", "cilium endpoint list")
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	Context("CT Timeouts", func() {
		It("Checks timeout of TCP connection attempts in ports that none listens to", func() {

			port := 12346
			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			ExpectWithOffset(2, err).Should(BeNil(), "Cannot get cilium pod on k8s1")
			// ciliumPodK8s2, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
			// ExpectWithOffset(2, err).Should(BeNil(), "Cannot get cilium pod on k8s2")

			yaml := helpers.ManifestGet(kubectl.BasePath(), "testpods.yaml")
			res := kubectl.ApplyDefault(yaml)
			res.ExpectSuccess("unable to apply %s", yaml)

			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=podtest", helpers.HelperTimeout)
			Expect(err).Should(BeNil())
			podIPs, _ := kubectl.GetPodsIPs(helpers.DefaultNamespace, "zgroup=podtest")

			ncCmd := fmt.Sprintf("nc %s %d", podIPs["pod1"], port)
			_ = kubectl.ExecPodCmd(helpers.DefaultNamespace, "pod2", ncCmd)

			bpfCtCmd_ := "cilium bpf ct list global --time-diff | sed -n -e 's/.*-> %s:%d.*remaining: \\([0-9]\\+\\) sec.*/\\1/p'"
			bpfCtCmd := fmt.Sprintf(bpfCtCmd_, podIPs["pod1"], port)
			res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, bpfCtCmd)
			timeout, err := strconv.Atoi(strings.TrimSpace(res.Stdout()))
			Expect(err).To(BeNil())
			Expect(timeout <= 10).To(BeTrue())
		})
	})
})
