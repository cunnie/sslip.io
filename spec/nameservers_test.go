package spec_test

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// RDAPResponse represents the JSON structure returned by RDAP servers
type RDAPResponse struct {
	Nameservers []struct {
		LdhName string `json:"ldhName"`
	} `json:"nameservers"`
}

// getRdapNameservers is called during spec tree construction, so it cannot use
// Ginkgo assertions (Expect). It panics on errors instead.
func getRdapNameservers(domain string) []string {
	url := fmt.Sprintf("https://rdap.namecheap.com/domain/%s", domain)
	resp, err := http.Get(url)
	if err != nil {
		panic(fmt.Sprintf("failed to fetch RDAP for %s: %v", domain, err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("failed to read RDAP response for %s: %v", domain, err))
	}

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("RDAP request for %s returned status %d: %s", domain, resp.StatusCode, string(body)))
	}

	var rdapResponse RDAPResponse
	err = json.Unmarshal(body, &rdapResponse)
	if err != nil {
		panic(fmt.Sprintf("failed to parse RDAP JSON for %s: %v\nResponse body: %s", domain, err, string(body)))
	}

	nameserverMap := make(map[string]bool)
	var nameservers []string
	for _, ns := range rdapResponse.Nameservers {
		nsLower := strings.ToLower(ns.LdhName)
		if !nameserverMap[nsLower] {
			nameserverMap[nsLower] = true
			// rdap records don't have trailing '.'; NS records do; add trailing '.'
			nameservers = append(nameservers, nsLower+".")
		}
	}
	return nameservers
}

func execDig(args ...string) (string, error) {
	cmd := exec.Command("dig", args...)
	output, err := cmd.Output()
	return string(output), err
}

func execDigShort(args ...string) string {
	output, _ := execDig(args...)
	return strings.TrimSpace(output)
}

var _ = Describe("Nameserver Tests", func() {
	domains = getDomains()
	for _, d := range domains {
		domain := d // capture range variable
		rdapNameservers = getRdapNameservers(domain)

		Describe(domain, func() {
			// I don't want a spurious failure, esp. ns-do-sg.sslip.io
			// default is 3 tries, 5 seconds timeout
			var digArgs []string

			BeforeEach(func() {
				digArgs = []string{"+tries=15", "+timeout=10"}
			})

			It("should have at least 2 nameservers", func() {
				Expect(len(rdapNameservers)).To(BeNumerically(">", 1))
			})

			// Exclude the Singapore nameserver "ns-do-sg."
			// because it triggers so many false positives
			nameserversWithoutSingapore := filterNameservers(rdapNameservers)

			for _, rdapNameserver := range nameserversWithoutSingapore {
				rdapNameserver := rdapNameserver // capture range variable

				It(fmt.Sprintf("nameserver %s's NS records include all rdap nameservers %v, `dig ... @%s ns %s +short`",
					rdapNameserver, rdapNameservers, rdapNameserver, domain), func() {
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), "ns", domain, "+short")
					output := execDigShort(args...)
					digNameservers := strings.Split(output, "\n")

					// Check that all rdap nameservers are in dig results
					for _, wns := range rdapNameservers {
						Expect(digNameservers).To(ContainElement(wns))
					}
				})

				It(fmt.Sprintf("nameserver %s's SOA record match", rdapNameserver), func() {
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), "soa", domain, "+short")
					digSOA := execDigShort(args...)
					Expect(digSOA).NotTo(BeEmpty())
					// Note: In the Ruby version, soa is compared across all nameservers
					// This would require a shared variable across tests
				})

				It(fmt.Sprintf("nameserver %s's has an A record", rdapNameserver), func() {
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), "a", domain, "+short")
					output := execDigShort(args...)
					Expect(output).NotTo(Equal(""))
				})

				It(fmt.Sprintf("nameserver %s's has an AAAA record", rdapNameserver), func() {
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), "aaaa", domain, "+short")
					output := execDigShort(args...)
					Expect(output).NotTo(Equal(""))
				})

				It(fmt.Sprintf("resolves random IP with dots for nameserver %s", rdapNameserver), func() {
					a := []int{rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)}
					ipAddr := fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3])
					query := fmt.Sprintf("%s.%s", ipAddr, domain)
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), query, "+short")
					output := execDigShort(args...)
					Expect(output).To(Equal(ipAddr))
				})

				It(fmt.Sprintf("resolves random IP with dashes for nameserver %s", rdapNameserver), func() {
					a := []int{rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)}
					ipAddr := fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3])
					query := fmt.Sprintf("%d-%d-%d-%d.%s", a[0], a[1], a[2], a[3], domain)
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), query, "+short")
					output := execDigShort(args...)
					Expect(output).To(Equal(ipAddr))
				})

				It(fmt.Sprintf("resolves subdomain with dashed IP for nameserver %s", rdapNameserver), func() {
					a := []int{rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)}
					ipAddr := fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3])
					subdomain := randomAlphanumeric(8)
					query := fmt.Sprintf("%s.%d-%d-%d-%d.%s", subdomain, a[0], a[1], a[2], a[3], domain)
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), query, "+short")
					output := execDigShort(args...)
					Expect(output).To(Equal(ipAddr))
				})

				It(fmt.Sprintf("resolves dashed IP with random subdomain for nameserver %s", rdapNameserver), func() {
					a := []int{rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)}
					ipAddr := fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3])
					subdomain := randomAlphanumeric(8)
					query := fmt.Sprintf("%d-%d-%d-%d.%s", a[0], a[1], a[2], a[3], subdomain)
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), query, "+short")
					output := execDigShort(args...)
					Expect(output).To(Equal(ipAddr))
				})

				It(fmt.Sprintf("resolves api.--.%s to :: for nameserver %s", domain, rdapNameserver), func() {
					query := fmt.Sprintf("api.--.%s", domain)
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), "AAAA", query, "+short")
					output := execDigShort(args...)
					Expect(output).To(Equal("::"))
				})

				It(fmt.Sprintf("resolves localhost.--1.%s to ::1 for nameserver %s", domain, rdapNameserver), func() {
					query := fmt.Sprintf("localhost.api.--1.%s", domain)
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), "AAAA", query, "+short")
					output := execDigShort(args...)
					Expect(output).To(Equal("::1"))
				})

				It(fmt.Sprintf("resolves 2001-4860-4860--8888.%s to 2001:4860:4860::8888 for nameserver %s", domain, rdapNameserver), func() {
					query := fmt.Sprintf("2001-4860-4860--8888.%s", domain)
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), "AAAA", query, "+short")
					output := execDigShort(args...)
					Expect(output).To(Equal("2001:4860:4860::8888"))
				})

				It(fmt.Sprintf("resolves 2601-646-100-69f0--24.%s to 2601:646:100:69f0::24 for nameserver %s", domain, rdapNameserver), func() {
					query := fmt.Sprintf("2601-646-100-69f0--24.%s", domain)
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), "AAAA", query, "+short")
					output := execDigShort(args...)
					Expect(output).To(Equal("2601:646:100:69f0::24"))
				})

				It(fmt.Sprintf("gets the expected version number, %s for nameserver %s", sslipVersion, rdapNameserver), func() {
					query := fmt.Sprintf("version.status.%s", domain)
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), "TXT", query, "+short")
					output := execDigShort(args...)
					Expect(output).To(ContainSubstring(sslipVersion))
				})

				It(fmt.Sprintf("gets the source (querier's) IP address for nameserver %s", rdapNameserver), func() {
					query := fmt.Sprintf("ip.%s", domain)
					args := append(digArgs, fmt.Sprintf("@%s", rdapNameserver), "TXT", query, "+short")
					output := execDigShort(args...)
					// Look on my Regular Expressions, ye mighty, and despair!
					ipv4Pattern := `^"(\d+\.\d+\.\d+\.\d+)"$`
					ipv6Pattern := `^"(([[:xdigit:]]*:){2,7}[[:xdigit:]]*)"$`
					matched, _ := regexp.MatchString(ipv4Pattern, output)
					if !matched {
						matched, _ = regexp.MatchString(ipv6Pattern, output)
					}
					Expect(matched).To(BeTrue())
				})

				It(fmt.Sprintf("is able to reach https://%s and get a valid response (2xx) for nameserver %s", domain, rdapNameserver), func() {
					cmd := exec.Command("curl", "-If", fmt.Sprintf("https://%s", domain))
					cmd.Stderr = nil
					err := cmd.Run()
					Expect(err).ToNot(HaveOccurred())
				})
			}
		})
	}
})

func getDomains() []string {
	domainsEnv := os.Getenv("DOMAINS")
	if domainsEnv == "" {
		domainsEnv = "nip.io,sslip.io"
	}
	domainSlice := strings.Split(domainsEnv, ",")
	domains = make([]string, len(domainSlice))
	for i, d := range domainSlice {
		domains[i] = strings.TrimSpace(d)
	}
	fmt.Fprintf(GinkgoWriter, "---> domains: %v!\n", domains)
	return domains
}

func filterNameservers(nameservers []string) []string {
	var filtered []string
	for _, ns := range nameservers {
		if !strings.HasPrefix(ns, "ns-do-sg.") {
			filtered = append(filtered, ns)
		}
	}
	return filtered
}

func randomAlphanumeric(length int) string {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}
