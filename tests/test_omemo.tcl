package require tcltest
namespace import ::tcltest::*

lappend auto_path [file normalize [file dirname [info script]]/..]
package require omemo

source [file join [file dirname [info script]] test_helpers.tcl]

test version-1.0 {omemo::version returns 0.3} -body {
    omemo::version
} -result 0.3

test fingerprint-1.0 {fingerprint is 64 hex in 8 groups of 8} -body {
    set ik [binary decode hex 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20]
    omemo::fingerprint $ik
} -result {01020304 05060708 090a0b0c 0d0e0f10 11121314 15161718 191a1b1c 1d1e1f20}

test fingerprint-1.1 {fingerprint rejects wrong-size input} -body {
    omemo::fingerprint [binary decode hex 0102]
} -returnCodes error -match glob -result {*32 bytes*}

test store-roundtrip-1.0 {store serialize/deserialize preserves identity} -body {
    omemo::store create st -device 1001
    st setup
    set blob [st serialize]
    omemo::store create st2 -device 1001
    st2 deserialize $blob
    set ok [expr {[st identity_pub] eq [st2 identity_pub]}]
    st destroy
    st2 destroy
    set ok
} -result 1

test bundle-1.0 {bundle dict has expected shape} -body {
    omemo::store create st -device 1001
    st setup
    set b [st bundle]
    set keys [lsort [dict keys $b]]
    set npks [llength [dict get $b prekeys]]
    set ik_len   [string length [dict get $b ik]]
    set spks_len [string length [dict get $b spks]]
    st destroy
    list keys $keys n $npks ik $ik_len spks $spks_len
} -result {keys {ik prekeys spk spk_id spks} n 100 ik 32 spks 64}

test message-aes-1.0 {encrypt_message/decrypt_message round-trip} -body {
    set plain "hello world this is a test message"
    set enc [omemo::encrypt_message $plain]
    set ct  [dict get $enc ct]
    set key [dict get $enc key]
    set iv  [dict get $enc iv]
    set out [omemo::decrypt_message $key $iv $ct]
    expr {$out eq $plain}
} -result 1

test media-aes-1.0 {media_encrypt/media_decrypt round-trip (XEP-0454)} -body {
    set plain "the quick brown fox jumps over the lazy dog"
    set enc [omemo::media_encrypt $plain]
    set ct  [dict get $enc ct]
    set key [dict get $enc key]
    set iv  [dict get $enc iv]
    set out [omemo::media_decrypt $key $iv $ct]
    list key_len [string length $key] iv_len [string length $iv] \
         ct_grew [expr {[string length $ct] == [string length $plain] + 16}] \
         match [expr {$out eq $plain}]
} -result {key_len 32 iv_len 12 ct_grew 1 match 1}

test media-aes-1.1 {media_decrypt rejects a tampered ciphertext} -body {
    set enc [omemo::media_encrypt "secret payload"]
    set ct  [dict get $enc ct]
    # Flip one bit in the first ciphertext byte.
    binary scan $ct cu* bytes
    lset bytes 0 [expr {[lindex $bytes 0] ^ 0x01}]
    set bad [binary format cu* $bytes]
    omemo::media_decrypt [dict get $enc key] [dict get $enc iv] $bad
} -returnCodes error -match glob -result {*ECRYPTO*}

test media-aes-1.2 {media_decrypt rejects a wrong key} -body {
    set enc [omemo::media_encrypt "another secret"]
    set wrong [string repeat \x00 32]
    omemo::media_decrypt $wrong [dict get $enc iv] [dict get $enc ct]
} -returnCodes error -match glob -result {*ECRYPTO*}

test media-aes-1.3 {media_decrypt rejects a short key} -body {
    set enc [omemo::media_encrypt "x"]
    omemo::media_decrypt [string repeat \x00 16] [dict get $enc iv] [dict get $enc ct]
} -returnCodes error -match glob -result {*EPARAM*}

test session-initiate-1.0 {Alice initiates against Bob's bundle and round-trips a key} -setup {
    ::th::open_skipped_db [file join [file dirname [info script]] skipped.db]
    ::th::wire_storage
} -body {
    set h [::th::make_pair alice@example.com 11 bob@example.com 22]
    set payload [binary decode hex [string repeat ab 32]]
    set wrap [alice_session encrypt_key $payload]
    set isp  [dict get $wrap isprekey]
    set p    [dict get $wrap p]
    set out  [bob_session decrypt_key bob_store $p -prekey $isp]
    set used [bob_session used_prekey_id]
    ::th::cleanup_pair
    list isprekey $isp match [expr {$out eq $payload}] used_nonempty [expr {$used ne {}}]
} -cleanup {
    ::th::close_skipped_db
} -result {isprekey 1 match 1 used_nonempty 1}

test session-second-msg-not-prekey-1.0 {after first decrypt, next msg is not a prekey} -setup {
    ::th::open_skipped_db [file join [file dirname [info script]] skipped.db]
    ::th::wire_storage
} -body {
    ::th::make_pair alice@example.com 11 bob@example.com 22
    set p1 [binary decode hex [string repeat 11 32]]
    set m1 [alice_session encrypt_key $p1]
    bob_session decrypt_key bob_store [dict get $m1 p] -prekey [dict get $m1 isprekey]

    # Bob responds so the ratchet advances on both sides.
    set p2 [binary decode hex [string repeat 22 32]]
    set m2 [bob_session encrypt_key $p2]
    alice_session decrypt_key alice_store [dict get $m2 p] -prekey [dict get $m2 isprekey]

    # Alice sends again.
    set p3 [binary decode hex [string repeat 33 32]]
    set m3 [alice_session encrypt_key $p3]
    set isp3 [dict get $m3 isprekey]
    set out3 [bob_session decrypt_key bob_store [dict get $m3 p] -prekey $isp3]
    ::th::cleanup_pair
    list isprekey $isp3 match [expr {$out3 eq $p3}]
} -cleanup {
    ::th::close_skipped_db
} -result {isprekey 0 match 1}

test skipped-keys-ooo-1.0 {out-of-order decrypt exercises store_mk and load_mk} -setup {
    ::th::open_skipped_db [file join [file dirname [info script]] skipped.db]
    ::th::wire_storage
} -body {
    ::th::make_pair alice@example.com 11 bob@example.com 22

    # Handshake first message (prekey) so subsequent flow is plain ratchet.
    set hp [binary decode hex [string repeat 99 32]]
    set h0 [alice_session encrypt_key $hp]
    bob_session decrypt_key bob_store [dict get $h0 p] -prekey [dict get $h0 isprekey]

    # Alice sends 5 more messages, all in the same sending chain.
    set payloads {}
    set wraps {}
    for {set i 0} {$i < 5} {incr i} {
        set pl [binary decode hex [string repeat [format %02x [expr {$i + 1}]] 32]]
        lappend payloads $pl
        lappend wraps [alice_session encrypt_key $pl]
    }

    # Bob decrypts in order 3, 2, 1, 5, 4 (indices 2, 1, 0, 4, 3).
    set order {2 1 0 4 3}
    set results {}
    set max_skip 0
    foreach idx $order {
        set w [lindex $wraps $idx]
        set out [bob_session decrypt_key bob_store [dict get $w p] -prekey [dict get $w isprekey]]
        lappend results [expr {$out eq [lindex $payloads $idx]}]
        set sc [::th::skipped_count]
        if {$sc > $max_skip} { set max_skip $sc }
    }
    set final_count [::th::skipped_count]
    ::th::cleanup_pair
    list all_match [expr {[lsearch -exact $results 0] < 0}] \
         max_skipped_in_db $max_skip final_count $final_count
} -cleanup {
    ::th::close_skipped_db
} -result {all_match 1 max_skipped_in_db 2 final_count 0}

test skipped-keys-cmdprefix-1.0 {set_storage accepts multi-word command prefixes} -setup {
    ::th::open_skipped_db [file join [file dirname [info script]] skipped.db]
    # Wire storage using a 2-word command prefix (apply + lambda). Before the
    # callback-prefix fix this failed with 'invalid command name "apply ..."'
    # because the whole prefix was passed as argv[0] of Tcl_EvalObjv.
    omemo::set_storage \
        -load  [list apply {{jid device dh nr}        { load_mk  $jid $device $dh $nr       }}] \
        -store [list apply {{jid device dh nr mk n}   { store_mk $jid $device $dh $nr $mk $n }}]
} -body {
    ::th::make_pair alice@example.com 11 bob@example.com 22

    set hp [binary decode hex [string repeat 99 32]]
    set h0 [alice_session encrypt_key $hp]
    bob_session decrypt_key bob_store [dict get $h0 p] -prekey [dict get $h0 isprekey]

    set p1 [binary decode hex [string repeat 11 32]]
    set p2 [binary decode hex [string repeat 22 32]]
    set m1 [alice_session encrypt_key $p1]
    set m2 [alice_session encrypt_key $p2]

    # Decrypt m2 first -> exercises store_mk via multi-word prefix.
    set out2 [bob_session decrypt_key bob_store [dict get $m2 p] -prekey [dict get $m2 isprekey]]
    set sc_after_store [::th::skipped_count]

    # Decrypt m1 -> exercises load_mk via multi-word prefix.
    set out1 [bob_session decrypt_key bob_store [dict get $m1 p] -prekey [dict get $m1 isprekey]]
    set sc_after_load [::th::skipped_count]

    ::th::cleanup_pair
    list match2 [expr {$out2 eq $p2}] stored $sc_after_store \
         match1 [expr {$out1 eq $p1}] drained $sc_after_load
} -cleanup {
    ::th::close_skipped_db
} -result {match2 1 stored 1 match1 1 drained 0}

test session-serialize-1.0 {session serialize/deserialize survives a message exchange} -setup {
    ::th::open_skipped_db [file join [file dirname [info script]] skipped.db]
    ::th::wire_storage
} -body {
    ::th::make_pair alice@example.com 11 bob@example.com 22
    set p1 [binary decode hex [string repeat 11 32]]
    set m1 [alice_session encrypt_key $p1]
    bob_session decrypt_key bob_store [dict get $m1 p] -prekey [dict get $m1 isprekey]

    set blob [bob_session serialize]
    omemo::session create bob2 -jid alice@example.com -device 11
    bob2 deserialize $blob

    set p2 [binary decode hex [string repeat 22 32]]
    set m2 [alice_session encrypt_key $p2]
    set out [bob2 decrypt_key bob_store [dict get $m2 p] -prekey [dict get $m2 isprekey]]

    bob2 destroy
    ::th::cleanup_pair
    list blob_len [string length $blob] match [expr {$out eq $p2}]
} -cleanup {
    ::th::close_skipped_db
} -match glob -result {blob_len * match 1}

test session-remote-identity-1.0 {after first prekey decrypt remote_identity equals sender ik} -setup {
    ::th::open_skipped_db [file join [file dirname [info script]] skipped.db]
    ::th::wire_storage
} -body {
    ::th::make_pair alice@example.com 11 bob@example.com 22
    set p1 [binary decode hex [string repeat 11 32]]
    set m1 [alice_session encrypt_key $p1]
    bob_session decrypt_key bob_store [dict get $m1 p] -prekey [dict get $m1 isprekey]
    set ok [expr {[bob_session remote_identity] eq [alice_store identity_pub]}]
    ::th::cleanup_pair
    set ok
} -cleanup {
    ::th::close_skipped_db
} -result 1

test heartbeat-1.0 {heartbeat returns empty in steady state} -setup {
    ::th::open_skipped_db [file join [file dirname [info script]] skipped.db]
    ::th::wire_storage
} -body {
    ::th::make_pair alice@example.com 11 bob@example.com 22
    set p1 [binary decode hex [string repeat 11 32]]
    set m1 [alice_session encrypt_key $p1]
    bob_session decrypt_key bob_store [dict get $m1 p] -prekey [dict get $m1 isprekey]
    set hb [bob_session heartbeat bob_store]
    ::th::cleanup_pair
    set hb
} -cleanup {
    ::th::close_skipped_db
} -result {}

test store-rotate-signed-prekey-1.0 {rotate_signed_prekey changes spk_id and spk bytes} -body {
    omemo::store create st -device 9
    st setup
    set b1 [st bundle]
    st rotate_signed_prekey
    set b2 [st bundle]
    set id_changed  [expr {[dict get $b1 spk_id] != [dict get $b2 spk_id]}]
    set spk_changed [expr {[dict get $b1 spk]    ne [dict get $b2 spk]}]
    st destroy
    list id_changed $id_changed spk_changed $spk_changed
} -result {id_changed 1 spk_changed 1}

test store-mark-prekey-used-1.0 {mark_prekey_used removes the entry from bundle} -body {
    omemo::store create st -device 9
    st setup
    set b1 [st bundle]
    set first_id [dict get [lindex [dict get $b1 prekeys] 0] id]
    st mark_prekey_used $first_id
    set b2 [st bundle]
    set still_present 0
    foreach entry [dict get $b2 prekeys] {
        if {[dict get $entry id] == $first_id} { set still_present 1; break }
    }
    set count_b1 [llength [dict get $b1 prekeys]]
    set count_b2 [llength [dict get $b2 prekeys]]
    st destroy
    list still_present $still_present b1 $count_b1 b2 $count_b2
} -result {still_present 0 b1 100 b2 99}

test store-refill-prekeys-1.0 {refill_prekeys restores the prekey count to 100} -body {
    omemo::store create st -device 9
    st setup
    set first_id [dict get [lindex [dict get [st bundle] prekeys] 0] id]
    st mark_prekey_used $first_id
    set before [llength [dict get [st bundle] prekeys]]
    st refill_prekeys
    set after [llength [dict get [st bundle] prekeys]]
    st destroy
    list before $before after $after
} -result {before 99 after 100}

test callback-error-1.0 {store_mk error surfaces as {OMEMO ESTORAGE}} -setup {
    ::th::open_skipped_db [file join [file dirname [info script]] skipped.db]
    proc bad_store {jid device dh nr mk n} { error "disk full" }
    omemo::set_storage -load load_mk -store bad_store
} -body {
    ::th::make_pair alice@example.com 11 bob@example.com 22
    set hp [binary decode hex [string repeat 99 32]]
    set h0 [alice_session encrypt_key $hp]
    bob_session decrypt_key bob_store [dict get $h0 p] -prekey [dict get $h0 isprekey]

    # Force a skip on Bob's side: Alice sends 2 messages; Bob receives the 2nd
    # first, which makes picomemo call store_mk for the skipped nr=0 key.
    set p1 [binary decode hex [string repeat 11 32]]
    set p2 [binary decode hex [string repeat 22 32]]
    set m1 [alice_session encrypt_key $p1]
    set m2 [alice_session encrypt_key $p2]

    set caught ""
    set ecode  ""
    try {
        bob_session decrypt_key bob_store [dict get $m2 p] -prekey [dict get $m2 isprekey]
    } trap {OMEMO ESTORAGE} {msg opts} {
        set caught $msg
        set ecode  [dict get $opts -errorcode]
    } on error {msg opts} {
        set caught "WRONG: $msg"
        set ecode  [dict get $opts -errorcode]
    }
    ::th::cleanup_pair
    list caught $caught ecode $ecode
} -cleanup {
    omemo::set_storage -load load_mk -store store_mk
    ::th::close_skipped_db
} -match glob -result {caught {disk full} ecode {OMEMO ESTORAGE}}

catch {file delete -- [file join [file dirname [info script]] skipped.db]}

cleanupTests
