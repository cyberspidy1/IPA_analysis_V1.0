// jailbreak_check.js
rpc.exports = {
    checkjailbreak: function () {
        var fs = require('fs');
        var indicators = [
            "/Applications/Cydia.app",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/bin/ssh",
            "/private/var/lib/apt",
            "/private/var/stash"
        ];

        var found = [];
        indicators.forEach(function(indicator) {
            if (fs.existsSync(indicator)) {
                found.push(indicator);
            }
        });

        return found;
    }
};

