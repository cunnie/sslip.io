package main_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSslipIoDnsServer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SslipIoDnsServer Suite")
}
