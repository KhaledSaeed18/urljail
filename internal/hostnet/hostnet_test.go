package hostnet

import "testing"

func TestTapFor(t *testing.T) {
	tap := TapFor(0)
	if tap.Name != "uj0" || tap.HostIP != "172.16.0.1" || tap.GuestIP != "172.16.0.2" || tap.GuestMAC != "06:00:AC:10:00:02" {
		t.Fatalf("TapFor(0) = %+v", tap)
	}
	// The CI rootfs derives the guest IP from MAC bytes 3–6: AC:10:0B:02 = 172.16.11.2.
	if tap := TapFor(11); tap.GuestMAC != "06:00:AC:10:0B:02" || tap.GuestIP != "172.16.11.2" {
		t.Fatalf("TapFor(11) = %+v", tap)
	}
	if got, want := TapFor(1).BootArgs(), "ip=172.16.1.2::172.16.1.1:255.255.255.252::eth0:off"; got != want {
		t.Fatalf("BootArgs = %q, want %q", got, want)
	}
}
