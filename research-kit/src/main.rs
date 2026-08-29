#[cfg(not(windows))]
fn main() {
    eprintln!("win32-min-research-kit runs on Windows; the ACL parser itself is portable.");
}

#[cfg(windows)]
fn main() {
    println!("win32-min ecosystem research inventory");
    println!("======================================");

    current_identity();
    service_inventory();
    kerberos_inventory();
    eventlog_inventory();
    descriptor_inventory();
}

#[cfg(windows)]
fn current_identity() {
    use windows_token::Token;

    println!("\n[identity]");
    match Token::open_current_process() {
        Ok(token) => match (token.user_sid(), token.integrity_level()) {
            (Ok(sid), Ok(level)) => println!("user_sid={sid} integrity={level:?}"),
            (sid, level) => println!("partial sid={sid:?} integrity={level:?}"),
        },
        Err(error) => println!("unavailable: {error}"),
    }
}

#[cfg(windows)]
fn service_inventory() {
    use windows_scm::{ScmAccess, ScmHandle, ServiceFilter, ServiceState};

    println!("\n[services]");
    let result = ScmHandle::open(None, ScmAccess::CONNECT | ScmAccess::ENUMERATE_SERVICE)
        .and_then(|scm| scm.enumerate(ServiceFilter::AllWin32));
    match result {
        Ok(services) => {
            let running = services
                .iter()
                .filter(|service| service.current_state == ServiceState::Running)
                .count();
            println!(
                "total={} running={} stopped_or_pending={}",
                services.len(),
                running,
                services.len().saturating_sub(running)
            );
            for service in services
                .iter()
                .filter(|service| service.process_id != 0)
                .take(5)
            {
                println!("pid={:<6} name={}", service.process_id, service.name);
            }
        }
        Err(error) => println!("unavailable: {error}"),
    }
}

#[cfg(windows)]
fn kerberos_inventory() {
    println!("\n[kerberos]");
    match windows_lsa::query_ticket_cache(None) {
        Ok(tickets) => {
            println!("cached_tickets={}", tickets.len());
            for ticket in tickets.iter().take(5) {
                println!(
                    "server={} realm={} encryption_type={} flags=0x{:08x}",
                    ticket.server_name,
                    ticket.realm_name,
                    ticket.encryption_type,
                    ticket.ticket_flags
                );
            }
        }
        Err(error) => println!("unavailable: {error}"),
    }
}

#[cfg(windows)]
fn eventlog_inventory() {
    use windows_eventlog_native::{EventLog, QueryDirection};

    println!("\n[eventlog]");
    let xpath = "*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]";
    match EventLog::query("Application", xpath, QueryDirection::Reverse) {
        Ok(events) => {
            let mut shown = 0usize;
            for event in events.take(5) {
                match event {
                    Ok(event) => {
                        println!(
                            "time={} event_id={} provider={}",
                            event.time_created, event.event_id, event.provider
                        );
                        shown += 1;
                    }
                    Err(error) => {
                        println!("iteration stopped: {error}");
                        break;
                    }
                }
            }
            println!("events_shown={shown}");
        }
        Err(error) => println!("unavailable: {error}"),
    }
}

#[cfg(windows)]
fn descriptor_inventory() {
    use windows_sddl::{build_rbcd_sd, parse, AccessMask, Sid};

    println!("\n[security-descriptor]");
    let Some(trustee) = Sid::parse("S-1-5-21-1-2-3-1104") else {
        println!("internal demo SID was rejected");
        return;
    };
    let bytes = build_rbcd_sd(&trustee);
    match parse(&bytes) {
        Ok(descriptor) => {
            let dangerous = descriptor
                .dacl
                .iter()
                .flat_map(|acl| &acl.aces)
                .filter(|ace| {
                    ace.is_allow()
                        && ace.mask.intersects(
                            AccessMask::GENERIC_ALL
                                | AccessMask::WRITE_DAC
                                | AccessMask::WRITE_OWNER,
                        )
                })
                .count();
            println!("bytes={} dangerous_allow_aces={dangerous}", bytes.len());
        }
        Err(error) => println!("unavailable: {error}"),
    }
}
