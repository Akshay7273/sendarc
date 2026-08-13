package main

import "testing"

func TestFindInviteCode(t *testing.T) {
	stderrInvite := "\u250c\u2500 SendBeam invite \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500...\n" +
		"\u2502 4-brave-otter\n" +
		"\u2502 link: http://10.0.0.1:8443/#4-brave-otter\n" +
		"\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"

	tests := []struct {
		name   string
		stdout string
		stderr string
		want   string
	}{
		{
			name:   "invite only on stderr",
			stdout: "Connecting to ws://10.0.0.1:8443/ws ...\n",
			stderr: stderrInvite,
			want:   "4-brave-otter",
		},
		{
			name:   "invite only on stdout",
			stdout: stderrInvite,
			stderr: "Connecting to ws://10.0.0.1:8443/ws ...\n",
			want:   "4-brave-otter",
		},
		{
			name:   "no invite yet",
			stdout: "Connecting to ws://10.0.0.1:8443/ws ...\n",
			stderr: "Waiting for the receiver to join ...\n",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findInviteCode(tt.stdout, tt.stderr); got != tt.want {
				t.Fatalf("findInviteCode = %q, want %q", got, tt.want)
			}
		})
	}
}
