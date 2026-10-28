package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	eventsv1 "k8s.io/api/events/v1"
)

// waitEvent waits for an Event about the named object with this reason and type
// (Normal or Warning), so a spec can tell a refusal from a routine note.
func waitEvent(regarding, reason, typ string) {
	GinkgoHelper()
	Eventually(func() (bool, error) {
		l := &eventsv1.EventList{}
		if err := k8sClient.List(ctx, l); err != nil {
			return false, err
		}
		for _, e := range l.Items {
			if e.Regarding.Name == regarding && e.Reason == reason && e.Type == typ {
				return true, nil
			}
		}
		return false, nil
	}).Should(BeTrue(), "%s event %s about %s", typ, reason, regarding)
}
