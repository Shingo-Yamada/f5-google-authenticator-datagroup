# F5 BIG-IP APM Google Authenticator

![Branching](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/F5_Google_Auth_DataGroup2.gif)

## Configuration
* * *
## Virtual Server
##### (tmos)# list ltm virtual vs_codygreenF5-MFA
```
ltm virtual vs_codygreenF5-MFA {
    creation-time 2020-05-27:01:14:42
    destination 10.1.1.9:sun-sr-https
    ip-protocol tcp
    last-modified-time 2020-05-27:01:14:42
    mask 255.255.255.255
    profiles {
        Google_authenticator_DGstorage { }
        clientssl_default {
            context clientside
        }
        http { }
        rba { }
        serverssl {
            context serverside
        }
        tcp { }
        websso { }
    }
    rules {
        F5_Google_Auth
    }
    source 0.0.0.0/0
    source-address-translation {
        type automap
    }
    translate-address enabled
    translate-port enabled
    vs-index 3
}
```


##### (tmos)# list ltm virtual VS_F5-MGMT-ETH
```
ltm virtual VS_F5-MGMT-ETH {
    creation-time 2020-07-01:14:06:54
    destination 192.0.0.2:10443
    ip-protocol tcp
    last-modified-time 2020-07-01:21:48:43
    mask 255.255.255.255
    profiles {
        http { }
        serverssl {
            context serverside
        }
        tcp { }
    }
    rules {
        rule_mgmt_access
    }
    source 0.0.0.0/0
    source-address-translation {
        type automap
    }
    translate-address enabled
    translate-port enabled
    vs-index 2
}
```
* * *
## iRule
##### (tmos)# list ltm rule F5_Google_Auth
```
ltm rule F5_Google_Auth {
##############################################################################################
proc add_totp_key { virtual basic_creds username key datagroup } {
    set tcp_conn [connect -timeout 2000 -idle 2000 -status tcp_conn_status $virtual]
    if { $tcp_conn_status equals "connected" } then {
        set http_request_body "\{\"command\":\"run\",\"utilCmdArgs\":\"add_totp_key $username $key $datagroup\"\}"
        set http_request "POST /mgmt/tm/cli/script/ HTTP/1.0\r\nHost: azure.f5users.tokyo\r\nAuthorization: Basic $basic_creds\r\nContent-Length: [string length $http_request_body]\r\n\r\n$http_request_body"
        send -timeout 2000 -status tcp_sent_status $tcp_conn $http_request
        if { $tcp_sent_status equals "sent" } then {
            set http_response [recv -timeout 2000 $tcp_conn]
            if { $http_response starts_with "HTTP/1.1 200" } then {
                return "Success"
            } elseif { $http_response equals "" } then {
                return "Error: Receive Timeout"
            } else {
                return "Error: API Response = $http_response"
            }
        } else {
            return "Error: Send Status = $tcp_sent_status"
        }
    } else {
        return "Error: Connection Status = $tcp_conn_status"
    }
}
proc delete_totp_key { virtual basic_creds username key datagroup } {
    set tcp_conn [connect -timeout 2000 -idle 2000 -status tcp_conn_status $virtual]
    if { $tcp_conn_status equals "connected" } then {
        set http_request_body "\{\"command\":\"run\",\"utilCmdArgs\":\"delete_totp_key $username $datagroup\"\}"
        set http_request "POST /mgmt/tm/cli/script/ HTTP/1.0\r\nHost: azure.f5users.tokyo\r\nAuthorization: Basic $basic_creds\r\nContent-Length: [string length $http_request_body]\r\n\r\n$http_request_body"
        send -timeout 2000 -status tcp_sent_status $tcp_conn $http_request
        if { $tcp_sent_status equals "sent" } then {
            set http_response [recv -timeout 2000 $tcp_conn]
            if { $http_response starts_with "HTTP/1.1 200" } then {
                return "Success"
            } elseif { $http_response equals "" } then {
                return "Error: Receive Timeout"
            } else {
                return "Error: API Response = $http_response"
            }
        } else {
            return "Error: Send Status = $tcp_sent_status"
        }
    } else {
        return "Error: Connection Status = $tcp_conn_status"
    }
}
##############################################################################################
when RULE_INIT {
        ##############################################################################################
        # Configure the Google Authenticator key sizes and HMAC operation modes.
        #
        # Note: Google Authenticator uses a hardcoded 80 bit key length with HMAC-SHA1 verification.
        #       The underlying HOTP algorithm (see RFC 4226) and TOTP algorithm (RFC 6238) standards
        #       require at least 128 bit and even recommend a 160 bit key length. In addition, both
        #       RFC standards include HMAC-SHA256 and HMAC-SHA512 operation modes.
        #       So if the Google Authenticator code is changed in the future to match the official
        #       requirements or even recommendations, then you have to change the variables below.
        #

        set static::ga_key_size 80              ;# Shared key size in bits
        set static::ga_hmac_mode "hmac-sha1"    ;# Options "hmac-sha1", "hmac-sha256" or "hmac-sha512"

        ##############################################################################################
        # Configure Google Authenticator verification settings
        #

        # allowed clock skew units (1 unit = +/-30 seconds in both directions)
        set static::ga_allowed_clock_skew_units 2
        # lock the user out after x attempts for a period of x seconds
        set static::lockout_attempts 3
        set static::lockout_period 60
        # logon page session variable name for code attempt form field
        set static::ga_code_form_field "ga_code_attempt"
        # key (shared secret) storage method: ldap, ad, or datagroup
        set static::ga_key_storage "datagroup"
        # LDAP attribute for key if storing in LDAP (optional)
        set static::ga_key_ldap_attr "google_auth_key"
        # Active Directory attribute for key if storing in AD (optional)
        set static::ga_key_ad_attr "gaSecret"
        # datagroup name if storing key in a datagroup (optional)
        set static::ga_key_dg "token_keys"

        ##############################################################################################
        # Initialize the Base32 alphabet to binary conversation (see RFC 4648)
        #

        set static::b32_to_binary [list \
        A 00000 B 00001 C 00010 D 00011 \
        E 00100 F 00101 G 00110 H 00111 \
        I 01000 J 01001 K 01010 L 01011 \
        M 01100 N 01101 O 01110 P 01111 \
        Q 10000 R 10001 S 10010 T 10011 \
        U 10100 V 10101 W 10110 X 10111 \
        Y 11000 Z 11001 2 11010 3 11011 \
        4 11100 5 11101 6 11110 7 11111 \
        0 "" 1 "" = "" " " "" \
        ]
}

when ACCESS_POLICY_AGENT_EVENT {
    switch [ACCESS::policy agent_id] {
        "is_enrolled" {
            set user [ACCESS::session data get session.logon.last.username]
            set secret [class match -value $user equals token_keys]
            if {$secret != ""} {
                ACCESS::session data set session.custom.is_enrolled 1
                ACCESS::session data set session.custom.secret $secret
            } else {
                ACCESS::session data set session.custom.is_enrolled 0
                log local0.info "INFO: f5_mfa.tcl - Cannot found secret key for $user"
            }
        }
        "generateQRCode" {
            set account [ACCESS::session data get session.logon.last.username]
            set domain [ACCESS::session data get session.logon.last.domain]
            set secret [b64encode [md5 [expr rand()]]]
            set secret [string range $secret 0 9]

            array set b32_alphabet_inv {
               0 A  1 B  2 C  3 D
               4 E  5 F  6 G  7 H
               8 I  9 J 10 K 11 L
              12 M 13 N 14 O 15 P
              16 Q 17 R 18 S 19 T
              20 U 21 V 22 W 23 X
              24 Y 25 Z 26 2 27 3
              28 4 29 5 30 6 31 7
            }
            set secret_b32 ""
            set l [string length $secret]
            set n 0
            set j 0

            # encode loop is outlined in RFC 4648
            for { set i 0 } { $i < $l } { incr i } {
              set n [expr {$n << 8}]
              set n [expr {$n + [scan [string index $secret $i] %c]}]
              set j [incr j 8]

              while { $j >= 5 } {
                set j [incr j -5]
                append secret_b32 $b32_alphabet_inv([expr {($n & (0x1F << $j)) >> $j}])
              }
            }

            # pad final input group with zeros to form an integral number of 5-bit groups, then encode
            if { $j > 0 } { append secret_b32 $b32_alphabet_inv([expr {$n << (5 - $j) & 0x1F}]) }

            # if the final quantum is not an integral multiple of 40, append "=" padding
            set pad [expr 8 - {[string length $secret_b32]} % 8]
            if { ($pad > 0) && ($pad < 8) } { append secret_b32 [string repeat = $pad] }

            set ga_qr_code_link ""
            append ga_qr_code_link "$account@$domain"
            append ga_qr_code_link "?secret="
            append ga_qr_code_link $secret_b32
            ACCESS::session data set session.custom.otp.qr_uri $ga_qr_code_link
            ACCESS::session data set session.custom.otp.secret $secret_b32
            log "<generateQRCode>: URI=$ga_qr_code_link SECRET:$secret_b32"
        }
        "ga_code_verify" {
                ##############################################################################################
                # Defining the user provided token code and provisioned user key
                #

                # set variables from APM logon page
                set username [ACCESS::session data get session.logon.last.username]
                set ga(token) [ACCESS::session data get session.logon.last.$static::ga_code_form_field]
                log local0.notice "ga(token):$ga(token)"
                # retrieve key from specified storage
                set ga(key) ""
                switch $static::ga_key_storage {
                        ldap {
                                set ga(key) [ACCESS::session data get session.ldap.last.attr.$static::ga_key_ldap_attr]
                        }
                        ad {
                                set ga(key) [ACCESS::session data get session.ad.last.attr.$static::ga_key_ad_attr]
                        }
                        datagroup {
                                set ga(key) [class lookup $username $static::ga_key_dg]
                                log local0.notice "ga(key):$ga(key)"
                        }
                }
                # Map the Base32 encoded ga(key) to binary string representation to get key-size
                set ga(key-size) [string length [set ga(key) [string map -nocase $static::b32_to_binary $ga(key)]]]
                # set lockout table
                set static::lockout_state_table "[virtual name]_lockout_status"
                # increment the number of login attempts for the user
                set prev_attempts [table incr -notouch -subtable $static::lockout_state_table $username]
                table timeout -subtable $static::lockout_state_table $username $static::lockout_period

                ##############################################################################################
                # Calculating GA code with the following ga_result value:
                #       0 = successful
                #       1 = failed
                #       2 = no key found
                #       3 = invalid key length
                #       4 = user locked out

                # make sure that the user isn't locked out
                if { $prev_attempts <= $static::lockout_attempts } {
                        # check key-size >= $static::ga_key_size
                        if { $ga(key-size) >= $static::ga_key_size } then {
                                # Convert the translated ga(key) binary string representation to binary
                                set ga(key) [binary format B$static::ga_key_size $ga(key)]
                                # Initialize ga(clock) timeframe based on Unix epoch time in seconds / 30
                                set ga(clock) [expr { [clock seconds] / 30 } ]

                                ##############################################################################################
                                # Perform verification of the provided ga(token) for current time frame ga(clock)
                                #

                                # Calculate hex encoded HMAC checksum value for wide-int value of time frame ga(clock) using ga(key) as secret
                                binary scan [CRYPTO::sign -alg $static::ga_hmac_mode -key $ga(key) [binary format W* $ga(clock)]] H* ga(verify)
                                # Parse ga(offset) based on the last nibble (= 4 bits / 1 hex) of the ga(verify) HMAC checksum and multiply with 2 for byte to hex conversation
                                set ga(offset) [expr { "0x[string index $ga(verify) end]" * 2 } ]
                                # Parse (= 4 bytes / 8 hex) from ga(verify) starting at the ga(offset) value, then remove the most significant bit, perform the modulo 1000000 and format the result to a 6 digit number
                                set ga(verify) [format %06d [expr { ( "0x[string range $ga(verify) $ga(offset) [expr { $ga(offset) + 7 } ]]" & 0x7FFFFFFF ) % 1000000 } ]]
                                log local0.notice "ga(verify):$ga(verify)"
                                # Compare ga(verify) with user provided ga(token) value
                                if { $ga(verify) equals $ga(token) } then {
                                        # The provided ga(token) is valid"
                                        set ga_result 0
                                } elseif { $static::ga_allowed_clock_skew_units > 0 } then {
                                        ##############################################################################################
                                        # Perform verification of the provided ga(token) for additional clock skew units
                                        #
                                        # Note: The order is increasing/decreasing according to ga(clock) (aka. Unix epoch time +30sec, -30sec, +60sec, -60sec, etc.)
                                        #

                                        set ga_result 1
                                        for { set x 1 } { $x <= $static::ga_allowed_clock_skew_units } { incr x } {
                                                ##############################################################################################
                                                # Perform verification of the provided ga(token) for time frame ga(clock) + $x
                                                #

                                                # Calculate hex encoded HMAC checksum value for wide-int value of time frame ga(clock) + x using ga(key) as secret
                                                binary scan [CRYPTO::sign -alg $static::ga_hmac_mode -key $ga(key) [binary format W* [expr { $ga(clock) + $x }]]] H* ga(verify)
                                                # Parse ga(offset) based on the last nibble (= 4 bits / 1 hex) of the ga(verify) HMAC checksum and multiply with 2 for byte to hex conversation
                                                set ga(offset) [expr { "0x[string index $ga(verify) end]" * 2 } ]
                                                # Parse (= 4 bytes / 8 hex) from ga(verify) starting at the ga(offset) value, then remove the most significant bit, perform the modulo 1000000 and format the result to a 6 digit number
                                                set ga(verify) [format %06d [expr { ( "0x[string range $ga(verify) $ga(offset) [expr { $ga(offset) + 7 } ]]" & 0x7FFFFFFF ) % 1000000 } ]]
                                                # Compare ga(verify) with user provided ga(token) value
                                                if { $ga(verify) equals $ga(token) } then {
                                                        # The provided ga(token) is valid"
                                                        set ga_result 0
                                                        break
                                                }
                                                ##############################################################################################
                                                # Perform verification of the provided ga(token) for time frame ga(clock) - $x
                                                #

                                                # Calculate hex encoded HMAC checksum value for wide-int value of time frame ga(clock) - $x using ga(key) as secret
                                                binary scan [CRYPTO::sign -alg $static::ga_hmac_mode -key $ga(key) [binary format W* [expr { $ga(clock) - $x }]]] H* ga(verify)
                                                # Parse ga(offset) based on the last nibble (= 4 bits / 1 hex) of the ga(verify) HMAC checksum and multiply with 2 for byte to hex conversation
                                                set ga(offset) [expr { "0x[string index $ga(verify) end]" * 2 } ]
                                                # Parse (= 4 bytes / 8 hex) from ga(verify) starting at the ga(offset) value, then remove the most significant bit, perform the modulo 1000000 and format the result to a 6 digit number
                                                set ga(verify) [format %06d [expr { ( "0x[string range $ga(verify) $ga(offset) [expr { $ga(offset) + 7 } ]]" & 0x7FFFFFFF ) % 1000000 } ]]
                                                # Compare ga(verify) with user provided ga(token) value
                                                if { $ga(verify) equals $ga(token) } then {
                                                        # The provided ga(token) is valid"
                                                        set ga_result 0
                                                        break
                                                }
                                        }
                                } else {
                                        # The provided ga(token) is invalid"
                                        set ga_result 1
                                }
                        } elseif { $ga(key-size) > 0 } {
                                # The provided ga(key) is malformated
                                set ga_result 3
                        } else {
                            # could not retrieve user's key
                                set ga_result 2
                        }
                } else {
                        # user locked out due to too many failed attempts
                        set ga_result 4
                }
                unset -nocomplain ga
                # set code verification result in session variable
                ACCESS::session data set session.custom.ga_result $ga_result
        }
        "add_user" {
            #set ilx_handle [ILX::init "f5_mfa_plugin" "f5_mfa_extension"]
            #set user [ACCESS::session data get session.logon.last.username]
            #set sec [ACCESS::session data get session.custom.otp.secret]
            #log local0.info "INFO: f5_mfa.tcl - user:$user secret:$sec"
            #if {[catch {set result [ILX::call $ilx_handle -timeout 10000 addUser $user $sec]} result]} {
            #    log local0.error "ERROR: f5_mfa.tcl - Client - [IP::client_addr], ILX failure: $result"
            #    return
            #}
            #log local0.info "user:$result"
            set result [call add_totp_key "VS_F5-MGMT-ETH" "[b64encode "admin:Netw0rld"]" "[ACCESS::session data get session.logon.last.username]" "[ACCESS::session data get session.custom.otp.secret]" "$static::ga_key_dg"]
            log local0.info "Result: $result"
            if { $result equals "Success" } {
                ACCESS::session data set session.custom.add_user.result $result
            }
        }
        "delete_user" {
            set result [call delete_totp_key "VS_F5-MGMT-ETH" "[b64encode "admin:Netw0rld"]" "[ACCESS::session data get session.logon.last.username]" "[ACCESS::session data get session.custom.otp.secret]" "$static::ga_key_dg"]
            log local0.info "Result: $result"
            if { $result equals "Success" } {
                ACCESS::session data set session.custom.delete_user.result $result
            }
        }
    }
}
}
```
* * *
##### (tmos)# list ltm rule rule_mgmt_access
```
ltm rule rule_mgmt_access {
when CLIENT_ACCEPTED {
    node 127.0.0.1 8443
    log "vs_api_access"
}
}
```
* * *
## Script
##### (tmos)# list cli script
```
cli script add_totp_key {
proc script::run {} {
        set cmd "tmsh::modify /ltm data-group internal [lindex $tmsh::argv 3] \{ records add \{ [lindex $tmsh::argv 1] \{ data [lindex $tmsh::argv 2] \} \} \}"
        tmsh::log "Executing the command: $cmd"
        eval $cmd
    }
    total-signing-status not-all-signed
}
```
* * *
##### 
```
cli script delete_totp_key {
proc script::run {} {
        set cmd "tmsh::modify /ltm data-group internal [lindex $tmsh::argv 2] \{ records delete \{ [lindex $tmsh::argv 1] \} \}"
        tmsh::log "Executing the command: $cmd"
        eval $cmd
    }
    total-signing-status not-all-signed
}
```
* * *
## Data-Group
##### (tmos)# list ltm data-group internal token_keys
```
ltm data-group internal token_keys {
    records {
        user01 {
            data G5QTQZLYF54TMRRP
        }
    }
    type string
}
```

***
## VPE
#### Google_authenticator_DGstorage

![Branching](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe.jpg)


### Logon Page
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe1.png)
### Local DB Auth
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe2.png)
### is_enrolled
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe3.png)

![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe4.png)

### is_enrolled(del)
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe5.png)

![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe6.png)

### Delete Confirm
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe7.png)

### delete_user
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe8.png)

![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe9.png)

### OK Delete
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe10.png)

### OTP Page
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe11.png)

### ga_code_verify
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe12.png)

![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe13.png)

### generateQRCode
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe14.png)

### Message Box
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe17.png)

### add_user
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe18.png)

![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe19.png)

### OK
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe20.png)


### Variable Assign
![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe15.png)

![Octocat](https://github.com/Shingo-Yamada/f5-google-authenticator-datagroup/blob/master/vpe/vpe16.png)
```
set qr_img {<div id="qrcode"></div><script type="text/javascript">var QRCode;!function(){function a(a){var b,d,e,f;for(this.mode=c.MODE_8BIT_BYTE,this.data=a,this.parsedData=[],b=0,d=this.data.length;d>b;b++)e=[],f=this.data.charCodeAt(b),f>65536?(e[0]=240|(1835008&f)>>>18,e[1]=128|(258048&f)>>>12,e[2]=128|(4032&f)>>>6,e[3]=128|63&f):f>2048?(e[0]=224|(61440&f)>>>12,e[1]=128|(4032&f)>>>6,e[2]=128|63&f):f>128?(e[0]=192|(1984&f)>>>6,e[1]=128|63&f):e[0]=f,this.parsedData.push(e);this.parsedData=Array.prototype.concat.apply([],this.parsedData),this.parsedData.length!=this.data.length&&(this.parsedData.unshift(191),this.parsedData.unshift(187),this.parsedData.unshift(239))}function b(a,b){this.typeNumber=a,this.errorCorrectLevel=b,this.modules=null,this.moduleCount=0,this.dataCache=null,this.dataList=[]}function i(a,b){var c,d;if(void 0==a.length)throw new Error(a.length+"/"+b);for(c=0;c<a.length&&0==a[c];)c++;for(this.num=new Array(a.length-c+b),d=0;d<a.length-c;d++)this.num[d]=a[d+c]}function j(a,b){this.totalCount=a,this.dataCount=b}function k(){this.buffer=[],this.length=0}function m(){return"undefined"!=typeof CanvasRenderingContext2D}function n(){var c,a=!1,b=navigator.userAgent;return/android/i.test(b)&&(a=!0,c=b.toString().match(/android ([0-9]\.[0-9])/i),c&&c[1]&&(a=parseFloat(c[1]))),a}function r(a,b){var f,g,h,c=1,e=s(a);for(f=0,g=l.length;g>=f;f++){switch(h=0,b){case d.L:h=l[f][0];break;case d.M:h=l[f][1];break;case d.Q:h=l[f][2];break;case d.H:h=l[f][3]}if(h>=e)break;c++}if(c>l.length)throw new Error("Too long data");return c}function s(a){var b=encodeURI(a).toString().replace(/\%[0-9a-fA-F]{2}/g,"a");return b.length+(b.length!=a?3:0)}var c,d,e,f,g,h,l,o,p,q;for(a.prototype={getLength:function(){return this.parsedData.length},write:function(a){for(var b=0,c=this.parsedData.length;c>b;b++)a.put(this.parsedData[b],8)}},b.prototype={addData:function(b){var c=new a(b);this.dataList.push(c),this.dataCache=null},isDark:function(a,b){if(0>a||this.moduleCount<=a||0>b||this.moduleCount<=b)throw new Error(a+","+b);return this.modules[a][b]},getModuleCount:function(){return this.moduleCount},make:function(){this.makeImpl(!1,this.getBestMaskPattern())},makeImpl:function(a,c){var d,e;for(this.moduleCount=4*this.typeNumber+17,this.modules=new Array(this.moduleCount),d=0;d<this.moduleCount;d++)for(this.modules[d]=new Array(this.moduleCount),e=0;e<this.moduleCount;e++)this.modules[d][e]=null;this.setupPositionProbePattern(0,0),this.setupPositionProbePattern(this.moduleCount-7,0),this.setupPositionProbePattern(0,this.moduleCount-7),this.setupPositionAdjustPattern(),this.setupTimingPattern(),this.setupTypeInfo(a,c),this.typeNumber>=7&&this.setupTypeNumber(a),null==this.dataCache&&(this.dataCache=b.createData(this.typeNumber,this.errorCorrectLevel,this.dataList)),this.mapData(this.dataCache,c)},setupPositionProbePattern:function(a,b){var c,d;for(c=-1;7>=c;c++)if(!(-1>=a+c||this.moduleCount<=a+c))for(d=-1;7>=d;d++)-1>=b+d||this.moduleCount<=b+d||(this.modules[a+c][b+d]=c>=0&&6>=c&&(0==d||6==d)||d>=0&&6>=d&&(0==c||6==c)||c>=2&&4>=c&&d>=2&&4>=d?!0:!1)},getBestMaskPattern:function(){var c,d,a=0,b=0;for(c=0;8>c;c++)this.makeImpl(!0,c),d=f.getLostPoint(this),(0==c||a>d)&&(a=d,b=c);return b},createMovieClip:function(a,b,c){var f,g,h,i,j,d=a.createEmptyMovieClip(b,c),e=1;for(this.make(),f=0;f<this.modules.length;f++)for(g=f*e,h=0;h<this.modules[f].length;h++)i=h*e,j=this.modules[f][h],j&&(d.beginFill(0,100),d.moveTo(i,g),d.lineTo(i+e,g),d.lineTo(i+e,g+e),d.lineTo(i,g+e),d.endFill());return d},setupTimingPattern:function(){var a,b;for(a=8;a<this.moduleCount-8;a++)null==this.modules[a][6]&&(this.modules[a][6]=0==a%2);for(b=8;b<this.moduleCount-8;b++)null==this.modules[6][b]&&(this.modules[6][b]=0==b%2)},setupPositionAdjustPattern:function(){var b,c,d,e,g,h,a=f.getPatternPosition(this.typeNumber);for(b=0;b<a.length;b++)for(c=0;c<a.length;c++)if(d=a[b],e=a[c],null==this.modules[d][e])for(g=-2;2>=g;g++)for(h=-2;2>=h;h++)this.modules[d+g][e+h]=-2==g||2==g||-2==h||2==h||0==g&&0==h?!0:!1},setupTypeNumber:function(a){var c,d,b=f.getBCHTypeNumber(this.typeNumber);for(c=0;18>c;c++)d=!a&&1==(1&b>>c),this.modules[Math.floor(c/3)][c%3+this.moduleCount-8-3]=d;for(c=0;18>c;c++)d=!a&&1==(1&b>>c),this.modules[c%3+this.moduleCount-8-3][Math.floor(c/3)]=d},setupTypeInfo:function(a,b){var e,g,c=this.errorCorrectLevel<<3|b,d=f.getBCHTypeInfo(c);for(e=0;15>e;e++)g=!a&&1==(1&d>>e),6>e?this.modules[e][8]=g:8>e?this.modules[e+1][8]=g:this.modules[this.moduleCount-15+e][8]=g;for(e=0;15>e;e++)g=!a&&1==(1&d>>e),8>e?this.modules[8][this.moduleCount-e-1]=g:9>e?this.modules[8][15-e-1+1]=g:this.modules[8][15-e-1]=g;this.modules[this.moduleCount-8][8]=!a},mapData:function(a,b){var h,i,j,k,c=-1,d=this.moduleCount-1,e=7,g=0;for(h=this.moduleCount-1;h>0;h-=2)for(6==h&&h--;;){for(i=0;2>i;i++)null==this.modules[d][h-i]&&(j=!1,g<a.length&&(j=1==(1&a[g]>>>e)),k=f.getMask(b,d,h-i),k&&(j=!j),this.modules[d][h-i]=j,e--,-1==e&&(g++,e=7));if(d+=c,0>d||this.moduleCount<=d){d-=c,c=-c;break}}}},b.PAD0=236,b.PAD1=17,b.createData=function(a,c,d){var h,i,l,e=j.getRSBlocks(a,c),g=new k;for(h=0;h<d.length;h++)i=d[h],g.put(i.mode,4),g.put(i.getLength(),f.getLengthInBits(i.mode,a)),i.write(g);for(l=0,h=0;h<e.length;h++)l+=e[h].dataCount;if(g.getLengthInBits()>8*l)throw new Error("code length overflow. ("+g.getLengthInBits()+">"+8*l+")");for(g.getLengthInBits()+4<=8*l&&g.put(0,4);0!=g.getLengthInBits()%8;)g.putBit(!1);for(;;){if(g.getLengthInBits()>=8*l)break;if(g.put(b.PAD0,8),g.getLengthInBits()>=8*l)break;g.put(b.PAD1,8)}return b.createBytes(g,e)},b.createBytes=function(a,b){var j,k,l,m,n,o,p,q,r,s,t,c=0,d=0,e=0,g=new Array(b.length),h=new Array(b.length);for(j=0;j<b.length;j++){for(k=b[j].dataCount,l=b[j].totalCount-k,d=Math.max(d,k),e=Math.max(e,l),g[j]=new Array(k),m=0;m<g[j].length;m++)g[j][m]=255&a.buffer[m+c];for(c+=k,n=f.getErrorCorrectPolynomial(l),o=new i(g[j],n.getLength()-1),p=o.mod(n),h[j]=new Array(n.getLength()-1),m=0;m<h[j].length;m++)q=m+p.getLength()-h[j].length,h[j][m]=q>=0?p.get(q):0}for(r=0,m=0;m<b.length;m++)r+=b[m].totalCount;for(s=new Array(r),t=0,m=0;d>m;m++)for(j=0;j<b.length;j++)m<g[j].length&&(s[t++]=g[j][m]);for(m=0;e>m;m++)for(j=0;j<b.length;j++)m<h[j].length&&(s[t++]=h[j][m]);return s},c={MODE_NUMBER:1,MODE_ALPHA_NUM:2,MODE_8BIT_BYTE:4,MODE_KANJI:8},d={L:1,M:0,Q:3,H:2},e={PATTERN000:0,PATTERN001:1,PATTERN010:2,PATTERN011:3,PATTERN100:4,PATTERN101:5,PATTERN110:6,PATTERN111:7},f={PATTERN_POSITION_TABLE:[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],G15:1335,G18:7973,G15_MASK:21522,getBCHTypeInfo:function(a){for(var b=a<<10;f.getBCHDigit(b)-f.getBCHDigit(f.G15)>=0;)b^=f.G15<<f.getBCHDigit(b)-f.getBCHDigit(f.G15);return(a<<10|b)^f.G15_MASK},getBCHTypeNumber:function(a){for(var b=a<<12;f.getBCHDigit(b)-f.getBCHDigit(f.G18)>=0;)b^=f.G18<<f.getBCHDigit(b)-f.getBCHDigit(f.G18);return a<<12|b},getBCHDigit:function(a){for(var b=0;0!=a;)b++,a>>>=1;return b},getPatternPosition:function(a){return f.PATTERN_POSITION_TABLE[a-1]},getMask:function(a,b,c){switch(a){case e.PATTERN000:return 0==(b+c)%2;case e.PATTERN001:return 0==b%2;case e.PATTERN010:return 0==c%3;case e.PATTERN011:return 0==(b+c)%3;case e.PATTERN100:return 0==(Math.floor(b/2)+Math.floor(c/3))%2;case e.PATTERN101:return 0==b*c%2+b*c%3;case e.PATTERN110:return 0==(b*c%2+b*c%3)%2;case e.PATTERN111:return 0==(b*c%3+(b+c)%2)%2;default:throw new Error("bad maskPattern:"+a)}},getErrorCorrectPolynomial:function(a){var c,b=new i([1],0);for(c=0;a>c;c++)b=b.multiply(new i([1,g.gexp(c)],0));return b},getLengthInBits:function(a,b){if(b>=1&&10>b)switch(a){case c.MODE_NUMBER:return 10;case c.MODE_ALPHA_NUM:return 9;case c.MODE_8BIT_BYTE:return 8;case c.MODE_KANJI:return 8;default:throw new Error("mode:"+a)}else if(27>b)switch(a){case c.MODE_NUMBER:return 12;case c.MODE_ALPHA_NUM:return 11;case c.MODE_8BIT_BYTE:return 16;case c.MODE_KANJI:return 10;default:throw new Error("mode:"+a)}else{if(!(41>b))throw new Error("type:"+b);switch(a){case c.MODE_NUMBER:return 14;case c.MODE_ALPHA_NUM:return 13;case c.MODE_8BIT_BYTE:return 16;case c.MODE_KANJI:return 12;default:throw new Error("mode:"+a)}}},getLostPoint:function(a){var d,e,f,g,h,i,j,k,l,b=a.getModuleCount(),c=0;for(d=0;b>d;d++)for(e=0;b>e;e++){for(f=0,g=a.isDark(d,e),h=-1;1>=h;h++)if(!(0>d+h||d+h>=b))for(i=-1;1>=i;i++)0>e+i||e+i>=b||(0!=h||0!=i)&&g==a.isDark(d+h,e+i)&&f++;f>5&&(c+=3+f-5)}for(d=0;b-1>d;d++)for(e=0;b-1>e;e++)j=0,a.isDark(d,e)&&j++,a.isDark(d+1,e)&&j++,a.isDark(d,e+1)&&j++,a.isDark(d+1,e+1)&&j++,(0==j||4==j)&&(c+=3);for(d=0;b>d;d++)for(e=0;b-6>e;e++)a.isDark(d,e)&&!a.isDark(d,e+1)&&a.isDark(d,e+2)&&a.isDark(d,e+3)&&a.isDark(d,e+4)&&!a.isDark(d,e+5)&&a.isDark(d,e+6)&&(c+=40);for(e=0;b>e;e++)for(d=0;b-6>d;d++)a.isDark(d,e)&&!a.isDark(d+1,e)&&a.isDark(d+2,e)&&a.isDark(d+3,e)&&a.isDark(d+4,e)&&!a.isDark(d+5,e)&&a.isDark(d+6,e)&&(c+=40);for(k=0,e=0;b>e;e++)for(d=0;b>d;d++)a.isDark(d,e)&&k++;return l=Math.abs(100*k/b/b-50)/5,c+=10*l}},g={glog:function(a){if(1>a)throw new Error("glog("+a+")");return g.LOG_TABLE[a]},gexp:function(a){for(;0>a;)a+=255;for(;a>=256;)a-=255;return g.EXP_TABLE[a]},EXP_TABLE:new Array(256),LOG_TABLE:new Array(256)},h=0;8>h;h++)g.EXP_TABLE[h]=1<<h;for(h=8;256>h;h++)g.EXP_TABLE[h]=g.EXP_TABLE[h-4]^g.EXP_TABLE[h-5]^g.EXP_TABLE[h-6]^g.EXP_TABLE[h-8];for(h=0;255>h;h++)g.LOG_TABLE[g.EXP_TABLE[h]]=h;i.prototype={get:function(a){return this.num[a]},getLength:function(){return this.num.length},multiply:function(a){var c,d,b=new Array(this.getLength()+a.getLength()-1);for(c=0;c<this.getLength();c++)for(d=0;d<a.getLength();d++)b[c+d]^=g.gexp(g.glog(this.get(c))+g.glog(a.get(d)));return new i(b,0)},mod:function(a){var b,c,d;if(this.getLength()-a.getLength()<0)return this;for(b=g.glog(this.get(0))-g.glog(a.get(0)),c=new Array(this.getLength()),d=0;d<this.getLength();d++)c[d]=this.get(d);for(d=0;d<a.getLength();d++)c[d]^=g.gexp(g.glog(a.get(d))+b);return new i(c,0).mod(a)}},j.RS_BLOCK_TABLE=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],j.getRSBlocks=function(a,b){var d,e,f,g,h,i,k,c=j.getRsBlockTable(a,b);if(void 0==c)throw new Error("bad rs block @ typeNumber:"+a+"/errorCorrectLevel:"+b);for(d=c.length/3,e=[],f=0;d>f;f++)for(g=c[3*f+0],h=c[3*f+1],i=c[3*f+2],k=0;g>k;k++)e.push(new j(h,i));return e},j.getRsBlockTable=function(a,b){switch(b){case d.L:return j.RS_BLOCK_TABLE[4*(a-1)+0];case d.M:return j.RS_BLOCK_TABLE[4*(a-1)+1];case d.Q:return j.RS_BLOCK_TABLE[4*(a-1)+2];case d.H:return j.RS_BLOCK_TABLE[4*(a-1)+3];default:return void 0}},k.prototype={get:function(a){var b=Math.floor(a/8);return 1==(1&this.buffer[b]>>>7-a%8)},put:function(a,b){for(var c=0;b>c;c++)this.putBit(1==(1&a>>>b-c-1))},getLengthInBits:function(){return this.length},putBit:function(a){var b=Math.floor(this.length/8);this.buffer.length<=b&&this.buffer.push(0),a&&(this.buffer[b]|=128>>>this.length%8),this.length++}},l=[[17,14,11,7],[32,26,20,14],[53,42,32,24],[78,62,46,34],[106,84,60,44],[134,106,74,58],[154,122,86,64],[192,152,108,84],[230,180,130,98],[271,213,151,119],[321,251,177,137],[367,287,203,155],[425,331,241,177],[458,362,258,194],[520,412,292,220],[586,450,322,250],[644,504,364,280],[718,560,394,310],[792,624,442,338],[858,666,482,382],[929,711,509,403],[1003,779,565,439],[1091,857,611,461],[1171,911,661,511],[1273,997,715,535],[1367,1059,751,593],[1465,1125,805,625],[1528,1190,868,658],[1628,1264,908,698],[1732,1370,982,742],[1840,1452,1030,790],[1952,1538,1112,842],[2068,1628,1168,898],[2188,1722,1228,958],[2303,1809,1283,983],[2431,1911,1351,1051],[2563,1989,1423,1093],[2699,2099,1499,1139],[2809,2213,1579,1219],[2953,2331,1663,1273]],o=function(){var a=function(a,b){this._el=a,this._htOption=b};return a.prototype.draw=function(a){function g(a,b){var d,c=document.createElementNS("http://www.w3.org/2000/svg",a);for(d in b)b.hasOwnProperty(d)&&c.setAttribute(d,b[d]);return c}var h,i,j,k,b=this._htOption,c=this._el,d=a.getModuleCount();for(Math.floor(b.width/d),Math.floor(b.height/d),this.clear(),h=g("svg",{viewBox:"0 0 "+String(d)+" "+String(d),width:"100%",height:"100%",fill:b.colorLight}),h.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:xlink","http://www.w3.org/1999/xlink"),c.appendChild(h),h.appendChild(g("rect",{fill:b.colorLight,width:"100%",height:"100%"})),h.appendChild(g("rect",{fill:b.colorDark,width:"1",height:"1",id:"template"})),i=0;d>i;i++)for(j=0;d>j;j++)a.isDark(i,j)&&(k=g("use",{x:String(j),y:String(i)}),k.setAttributeNS("http://www.w3.org/1999/xlink","href","#template"),h.appendChild(k))},a.prototype.clear=function(){for(;this._el.hasChildNodes();)this._el.removeChild(this._el.lastChild)},a}(),p="svg"===document.documentElement.tagName.toLowerCase(),q=p?o:m()?function(){function a(){this._elImage.src=this._elCanvas.toDataURL("image/png"),this._elImage.style.display="block",this._elCanvas.style.display="none"}function d(a,b){var d,e,f,c=this;return c._fFail=b,c._fSuccess=a,null===c._bSupportDataURI?(d=document.createElement("img"),e=function(){c._bSupportDataURI=!1,c._fFail&&c._fFail.call(c)},f=function(){c._bSupportDataURI=!0,c._fSuccess&&c._fSuccess.call(c)},d.onabort=e,d.onerror=e,d.onload=f,d.src="data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==",void 0):(c._bSupportDataURI===!0&&c._fSuccess?c._fSuccess.call(c):c._bSupportDataURI===!1&&c._fFail&&c._fFail.call(c),void 0)}var b,c,e;return this._android&&this._android<=2.1&&(b=1/window.devicePixelRatio,c=CanvasRenderingContext2D.prototype.drawImage,CanvasRenderingContext2D.prototype.drawImage=function(a,d,e,f,g,h,i,j){if("nodeName"in a&&/img/i.test(a.nodeName))for(var l=arguments.length-1;l>=1;l--)arguments[l]=arguments[l]*b;else"undefined"==typeof j&&(arguments[1]*=b,arguments[2]*=b,arguments[3]*=b,arguments[4]*=b);c.apply(this,arguments)}),e=function(a,b){this._bIsPainted=!1,this._android=n(),this._htOption=b,this._elCanvas=document.createElement("canvas"),this._elCanvas.width=b.width,this._elCanvas.height=b.height,a.appendChild(this._elCanvas),this._el=a,this._oContext=this._elCanvas.getContext("2d"),this._bIsPainted=!1,this._elImage=document.createElement("img"),this._elImage.alt="Scan me!",this._elImage.style.display="none",this._el.appendChild(this._elImage),this._bSupportDataURI=null},e.prototype.draw=function(a){var j,k,l,m,n,b=this._elImage,c=this._oContext,d=this._htOption,e=a.getModuleCount(),f=d.width/e,g=d.height/e,h=Math.round(f),i=Math.round(g);for(b.style.display="none",this.clear(),j=0;e>j;j++)for(k=0;e>k;k++)l=a.isDark(j,k),m=k*f,n=j*g,c.strokeStyle=l?d.colorDark:d.colorLight,c.lineWidth=1,c.fillStyle=l?d.colorDark:d.colorLight,c.fillRect(m,n,f,g),c.strokeRect(Math.floor(m)+.5,Math.floor(n)+.5,h,i),c.strokeRect(Math.ceil(m)-.5,Math.ceil(n)-.5,h,i);this._bIsPainted=!0},e.prototype.makeImage=function(){this._bIsPainted&&d.call(this,a)},e.prototype.isPainted=function(){return this._bIsPainted},e.prototype.clear=function(){this._oContext.clearRect(0,0,this._elCanvas.width,this._elCanvas.height),this._bIsPainted=!1},e.prototype.round=function(a){return a?Math.floor(1e3*a)/1e3:a},e}():function(){var a=function(a,b){this._el=a,this._htOption=b};return a.prototype.draw=function(a){var h,i,j,k,l,b=this._htOption,c=this._el,d=a.getModuleCount(),e=Math.floor(b.width/d),f=Math.floor(b.height/d),g=['<table style="border:0;border-collapse:collapse;">'];for(h=0;d>h;h++){for(g.push("<tr>"),i=0;d>i;i++)g.push('<td style="border:0;border-collapse:collapse;padding:0;margin:0;width:'+e+"px;height:"+f+"px;background-color:"+(a.isDark(h,i)?b.colorDark:b.colorLight)+';"></td>');g.push("</tr>")}g.push("</table>"),c.innerHTML=g.join(""),j=c.childNodes[0],k=(b.width-j.offsetWidth)/2,l=(b.height-j.offsetHeight)/2,k>0&&l>0&&(j.style.margin=l+"px "+k+"px")},a.prototype.clear=function(){this._el.innerHTML=""},a}(),QRCode=function(a,b){if(this._htOption={width:256,height:256,typeNumber:4,colorDark:"#000000",colorLight:"#ffffff",correctLevel:d.H},"string"==typeof b&&(b={text:b}),b)for(var c in b)this._htOption[c]=b[c];"string"==typeof a&&(a=document.getElementById(a)),this._htOption.useSVG&&(q=o),this._android=n(),this._el=a,this._oQRCode=null,this._oDrawing=new q(this._el,this._htOption),this._htOption.text&&this.makeCode(this._htOption.text)},QRCode.prototype.makeCode=function(a){this._oQRCode=new b(r(a,this._htOption.correctLevel),this._htOption.correctLevel),this._oQRCode.addData(a),this._oQRCode.make(),this._el.title=a,this._oDrawing.draw(this._oQRCode),this.makeImage()},QRCode.prototype.makeImage=function(){"function"==typeof this._oDrawing.makeImage&&(!this._android||this._android>=3)&&this._oDrawing.makeImage()},QRCode.prototype.clear=function(){this._oDrawing.clear()},QRCode.CorrectLevel=d}();}; append qr_img "new QRCode(document.getElementById('qrcode'), \"otpauth:\/\/totp\/"; append qr_img "[mcget -nocache {session.custom.otp.qr_uri}]"; append qr_img "\");<\/script>";
```
