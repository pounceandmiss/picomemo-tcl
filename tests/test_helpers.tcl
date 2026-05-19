package require sqlite3

namespace eval ::th {
    variable db_path
}

proc ::th::open_skipped_db {{path skipped.db}} {
    variable db_path
    set db_path $path
    catch {file delete -- $path}
    sqlite3 db $path
    db eval {
        CREATE TABLE IF NOT EXISTS mkskipped(
            jid    TEXT    NOT NULL,
            device INTEGER NOT NULL,
            dh     BLOB    NOT NULL,
            nr     INTEGER NOT NULL,
            mk     BLOB    NOT NULL,
            PRIMARY KEY (jid, device, dh, nr)
        )
    }
}

proc ::th::close_skipped_db {} {
    catch {db close}
}

proc load_mk {jid device dh nr} {
    set rows [db eval {
        SELECT mk FROM mkskipped
         WHERE jid=:jid AND device=:device AND dh=:dh AND nr=:nr
    }]
    if {[llength $rows] == 0} { return {} }
    db eval {
        DELETE FROM mkskipped
         WHERE jid=:jid AND device=:device AND dh=:dh AND nr=:nr
    }
    return [lindex $rows 0]
}

proc store_mk {jid device dh nr mk n} {
    db eval {
        INSERT OR REPLACE INTO mkskipped(jid, device, dh, nr, mk)
        VALUES (:jid, :device, :dh, :nr, :mk)
    }
}

proc ::th::skipped_count {} {
    return [db eval {SELECT COUNT(*) FROM mkskipped}]
}

proc ::th::wire_storage {} {
    omemo::set_storage -load load_mk -store store_mk
}

# Create two stores and an Alice-side session initiated against Bob's bundle.
# Returns dict {alice_store bob_store alice_session bob_session}.
proc ::th::make_pair {alice_jid alice_dev bob_jid bob_dev} {
    omemo::store create alice_store -device $alice_dev
    alice_store setup
    omemo::store create bob_store   -device $bob_dev
    bob_store setup

    set bundle [bob_store bundle]
    set pre0   [lindex [dict get $bundle prekeys] 0]
    set pk     [dict get $pre0 pk]
    set pk_id  [dict get $pre0 id]

    omemo::session create alice_session -jid $bob_jid -device $bob_dev
    alice_session initiate alice_store \
        -ik     [dict get $bundle ik] \
        -spk    [dict get $bundle spk] \
        -spks   [dict get $bundle spks] \
        -pk     $pk \
        -spk-id [dict get $bundle spk_id] \
        -pk-id  $pk_id

    omemo::session create bob_session -jid $alice_jid -device $alice_dev

    return [dict create \
        alice_store   alice_store \
        bob_store     bob_store \
        alice_session alice_session \
        bob_session   bob_session]
}

proc ::th::cleanup_pair {} {
    foreach name {alice_session bob_session alice_store bob_store} {
        catch {$name destroy}
    }
}
