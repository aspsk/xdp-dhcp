#! /bin/bash

failed=0

negative()
{
	"$@" 2>/dev/null || return
	echo "FAIL: unexpected ok from '$@'"
	failed=$((failed+1))
}

negative ./xdp-dhcp -n --mac ''
negative ./xdp-dhcp -n --mac '11:22:33:44:55'
negative ./xdp-dhcp -n --mac '11:22:33:44:55:66:77'

negative ./xdp-dhcp -n --lease '1'
negative ./xdp-dhcp -n --lease '12'
negative ./xdp-dhcp -n --lease '0s'
negative ./xdp-dhcp -n --lease '1z'

negative ./xdp-dhcp -n --addr '10.1.0.1/33'
negative ./xdp-dhcp -n --addr '10.1.01/33'
negative ./xdp-dhcp -n --addr '10.1.0.1234/33'

negative ./xdp-dhcp -n --dev 'wokka_pokka'
negative ./xdp-dhcp -n --dev 'loppapoppa'
negative ./xdp-dhcp -n --dev '123a'
negative ./xdp-dhcp -n --dev '-45'

exit $failed
